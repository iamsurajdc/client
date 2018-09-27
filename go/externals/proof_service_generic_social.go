package externals

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	libkb "github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	jsonw "github.com/keybase/go-jsonw"
)

const kbUsernameKey = "%{kb_username}"
const remoteUsernameKey = "%{username}"
const sigHashKey = "%{sig_hash}"

//=============================================================================

// Validated configuration from the server
type GenericSocialProofConfig struct {
	keybase1.ParamProofServiceConfig
	usernameRe *regexp.Regexp
}

func NewGenericSocialProofConfig(config keybase1.ParamProofServiceConfig) (*GenericSocialProofConfig, error) {
	gsConfig := &GenericSocialProofConfig{
		ParamProofServiceConfig: config,
	}
	if err := gsConfig.parseAndValidate(); err != nil {
		return nil, err
	}
	return gsConfig, nil
}

func (c *GenericSocialProofConfig) parseAndValidate() (err error) {
	c.usernameRe, err = regexp.Compile(c.Username.Re)
	if err != nil {
		return err
	}

	if err = c.validatePrefillURL(); err != nil {
		return err
	}

	if err = c.validateCheckURL(); err != nil {
		return err
	}
	if err = c.validateProfileURL(); err != nil {
		return err
	}

	return nil
}

func (c *GenericSocialProofConfig) validateProfileURL() error {
	if !strings.Contains(c.ProfileUrl, remoteUsernameKey) {
		return fmt.Errorf("invalid ProfileUrl %s, missing %s", c.ProfileUrl, remoteUsernameKey)
	}
	return nil
}

func (c *GenericSocialProofConfig) validatePrefillURL() error {
	if !strings.Contains(c.PrefillUrl, kbUsernameKey) {
		return fmt.Errorf("invalid PrefillUrl %s, missing %s", c.PrefillUrl, kbUsernameKey)
	}
	if !strings.Contains(c.PrefillUrl, sigHashKey) {
		return fmt.Errorf("invalid PrefillUrl %s, missing %s", c.PrefillUrl, sigHashKey)
	}
	return nil
}

func (c *GenericSocialProofConfig) validateCheckURL() error {
	if !strings.Contains(c.CheckUrl, remoteUsernameKey) {
		return fmt.Errorf("invalid CheckUrl %s, missing %s", c.CheckUrl, remoteUsernameKey)
	}
	return nil
}

func (c *GenericSocialProofConfig) profileURLWithValues(remoteUsername string) (string, error) {
	url := strings.Replace(c.ProfileUrl, remoteUsernameKey, remoteUsername, 1)
	if !strings.Contains(url, remoteUsername) {
		return "", fmt.Errorf("Invalid ProfileUrl %s, missing username", url)
	}
	return url, nil
}

func (c *GenericSocialProofConfig) prefillURLWithValues(kbUsername string, sigID keybase1.SigID) (string, error) {
	url := strings.Replace(c.PrefillUrl, kbUsernameKey, kbUsername, 1)
	if !strings.Contains(url, kbUsername) {
		return "", fmt.Errorf("Invalid PrefillUrl %s, missing kbUsername", url)
	}
	url = strings.Replace(url, sigHashKey, sigID.String(), 1)
	if !strings.Contains(url, sigID.String()) {
		return "", fmt.Errorf("Invalid PrefillUrl %s, missing sigHash", url)
	}
	return url, nil
}

func (c *GenericSocialProofConfig) checkURLWithValues(remoteUsername string) (string, error) {
	url := strings.Replace(c.CheckUrl, remoteUsernameKey, remoteUsername, 1)
	if !strings.Contains(url, remoteUsername) {
		return "", fmt.Errorf("Invalid CheckUrl %s, missing username", url)
	}
	return url, nil
}

//=============================================================================
// GenericSocialProof
//

type GenericSocialProofChecker struct {
	proof  libkb.RemoteProofChainLink
	config *GenericSocialProofConfig
}

var _ libkb.ProofChecker = (*GenericSocialProofChecker)(nil)

func NewGenericSocialProofChecker(proof libkb.RemoteProofChainLink, config *GenericSocialProofConfig) (*GenericSocialProofChecker, libkb.ProofError) {
	return &GenericSocialProofChecker{
		proof:  proof,
		config: config,
	}, nil
}

func (rc *GenericSocialProofChecker) GetTorError() libkb.ProofError { return nil }

func (rc *GenericSocialProofChecker) CheckStatus(mctx libkb.MetaContext, _ libkb.SigHint, _ libkb.ProofCheckerMode,
	pvlU keybase1.MerkleStoreEntry) (*libkb.SigHint, libkb.ProofError) {

	_, sigID, err := libkb.OpenSig(rc.proof.GetArmoredSig())
	if err != nil {
		return nil, libkb.NewProofError(keybase1.ProofStatus_BAD_SIGNATURE,
			"Bad signature: %v", err)
	}

	remoteUsername := rc.proof.GetRemoteUsername()
	apiURL, err := rc.config.checkURLWithValues(remoteUsername)
	if err != nil {
		return nil, libkb.NewProofError(keybase1.ProofStatus_BAD_API_URL,
			"Bad api url: %v", err)
	}

	if _, err = url.Parse(apiURL); err != nil {
		return nil, libkb.NewProofError(keybase1.ProofStatus_FAILED_PARSE,
			"Could not parse url: '%v'", apiURL)
	}

	res, err := mctx.G().GetExternalAPI().Get(libkb.APIArg{
		Endpoint:    apiURL,
		MetaContext: mctx,
	})
	if err != nil {
		return nil, libkb.XapiError(err, apiURL)
	}

	// We expect a single result to match which contains an array of proofs.
	results, perr := libkb.AtSelectorPath(res.Body, rc.config.CheckPath, mctx.CDebugf)
	if perr != nil {
		return nil, perr
	}
	if len(results) != 1 {
		return nil, libkb.NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
			"Json selector did not match any values")
	}
	var proofs []keybase1.ParamProofJSON
	if err = results[0].UnmarshalAgain(&proofs); err != nil {
		return nil, libkb.NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
			"Json could not be deserialized")
	}

	found := false
	for _, proof := range proofs {
		if proof.KbUsername == rc.proof.GetUsername() && sigID.Equal(proof.SigHash) {
			found = true
			break
		}
	}
	if !found {
		return nil, libkb.NewProofError(keybase1.ProofStatus_NOT_FOUND,
			"Unable to find the proof")
	}

	humanURL, err := rc.config.profileURLWithValues(remoteUsername)
	if err != nil {
		humanURL = ""
	}
	verifiedSigHint := libkb.NewVerifiedSigHint(sigID, "" /* remoteID */, apiURL, humanURL, "" /* checkText */)
	return verifiedSigHint, nil
}

//=============================================================================

type GenericSocialProofServiceType struct {
	libkb.BaseServiceType
	config *GenericSocialProofConfig
}

func NewGenericSocialProofServiceType(config *GenericSocialProofConfig) GenericSocialProofServiceType {
	return GenericSocialProofServiceType{
		config: config,
	}
}

func (t GenericSocialProofServiceType) AllStringKeys() []string { return t.BaseAllStringKeys(t) }

func (t GenericSocialProofServiceType) NormalizeUsername(s string) (string, error) {
	if !t.config.usernameRe.MatchString(s) {
		return "", libkb.NewBadUsernameError(s)
	}
	return strings.ToLower(s), nil
}

func (t GenericSocialProofServiceType) NormalizeRemoteName(mctx libkb.MetaContext, s string) (ret string, err error) {
	return t.NormalizeUsername(s)
}

func (t GenericSocialProofServiceType) GetPrompt() string {
	return fmt.Sprintf("Your username on %s", t.config.DisplayName)
}

func (t GenericSocialProofServiceType) ToServiceJSON(username string) *jsonw.Wrapper {
	return t.BaseToServiceJSON(t, username)
}

func (t GenericSocialProofServiceType) PostInstructions(username string) *libkb.Markup {
	return libkb.FmtMarkup(`Please click on the following link to post to %v:`, t.config.DisplayName)
}

func (t GenericSocialProofServiceType) DisplayName(username string) string {
	return t.config.DisplayName
}
func (t GenericSocialProofServiceType) GetTypeName() string { return t.config.Domain }

func (t GenericSocialProofServiceType) RecheckProofPosting(tryNumber int, status keybase1.ProofStatus, _ string) (warning *libkb.Markup, err error) {
	return t.BaseRecheckProofPosting(tryNumber, status)
}

func (t GenericSocialProofServiceType) GetProofType() string {
	return libkb.GenericSocialWebServiceBinding
}

func (t GenericSocialProofServiceType) CheckProofText(text string, id keybase1.SigID, sig string) (err error) {
	// We don't rely only any server trust in FormatProofText so there is nothing to verify here.
	return nil
}

func (t GenericSocialProofServiceType) FormatProofText(m libkb.MetaContext, ppr *libkb.PostProofRes,
	kbUsername string, sigID keybase1.SigID) (string, error) {
	return t.config.prefillURLWithValues(kbUsername, sigID)
}

func (t GenericSocialProofServiceType) MakeProofChecker(l libkb.RemoteProofChainLink) libkb.ProofChecker {
	return &GenericSocialProofChecker{
		proof:  l,
		config: t.config,
	}
}

func (t GenericSocialProofServiceType) IsDevelOnly() bool { return false }
