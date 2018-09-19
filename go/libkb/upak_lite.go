package libkb

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/buger/jsonparser"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
)

func LoadUPAKLite(arg LoadUserArg) (ret *keybase1.UpkLitev1AllIncarnations, err error) {
	uid := arg.uid
	m := arg.m

	// get sig hints in order to populate during merkle leaf lookup
	sigHints, err := LoadSigHints(m, arg.uid)
	if err != nil {
		return nil, err
	}
	leaf, err := lookupMerkleLeaf(m, uid, false, sigHints)
	if err != nil {
		return nil, err
	}
	// TODO: this is heavy-handed, especially for big users.
	// i'm pretty sure we can get what we need by requesting much
	// less data from the server than going through user/lookup.
	user, err := LoadUserFromServer(m, uid, nil)
	if err != nil {
		return nil, err
	}
	loader := NewHighSigChainLoader(m, user, leaf)
	highChain, err := loader.Load()
	if err != nil {
		return nil, err
	}
	return highChain.ToUPAKLite()
}

type HighSigChainLoader struct {
	BaseSigChainLoader
	MetaContextified
	user      *User
	leaf      *MerkleUserLeaf
	chain     *HighSigChain
	chainType *ChainType
	links     ChainLinks
	ckf       ComputedKeyFamily
	dirtyTail *MerkleTriple
}

type HighSigChain struct {
	BaseSigChain
	Contextified
	uid                  keybase1.UID
	username             NormalizedUsername
	chainLinks           ChainLinks
	localCki             *ComputedKeyInfos
	localChainTail       *MerkleTriple
	localChainUpdateTime time.Time
}

func NewHighSigChainLoader(m MetaContext, user *User, leaf *MerkleUserLeaf) *HighSigChainLoader {
	hsc := HighSigChain{
		uid:      user.GetUID(),
		username: user.GetNormalizedName(),
	}
	loader := HighSigChainLoader{
		user:             user,
		leaf:             leaf,
		chain:            &hsc,
		chainType:        PublicChain,
		MetaContextified: NewMetaContextified(m),
	}
	loader.ckf.kf = user.GetKeyFamily()
	return &loader
}

func (l *HighSigChainLoader) Load() (ret *HighSigChain, err error) {
	// request new links (and the unverified tail) from the server
	// and put them into the highSigChain
	err = l.LoadFromServer()
	if err != nil {
		return nil, err
	}
	// verify the chain
	err = l.chain.VerifyChain(l.M())
	if err != nil {
		return nil, err
	}
	// compute keys
	err = l.VerifySigsAndComputeKeys()

	return l.chain, nil
}

func (l *HighSigChainLoader) selfUID() (uid keybase1.UID) {
	//for now let's always assume this isn't applicable, but we can add it later
	return
}

func (l *HighSigChainLoader) LoadFromServer() (err error) {
	srv := l.GetMerkleTriple()
	l.dirtyTail, err = l.chain.LoadFromServer(l.M(), srv, l.selfUID())
	return
}

func (hsc *HighSigChain) LoadFromServer(m MetaContext, t *MerkleTriple, selfUID keybase1.UID) (dirtyTail *MerkleTriple, err error) {
	// hit the api and get the sigs
	// parse and Unpack() them into chainlinks and put them on the chain
	// and verify some basic stuff like the uid, seqno
	// with a little work over in sig_chain.go, there's some reusable code here

	// get the high sigs from the server
	m, tbs := m.WithTimeBuckets()

	apiArg := APIArg{
		Endpoint:    "sig/get_high",
		SessionType: APISessionTypeREQUIRED,
		Args:        HTTPArgs{"uid": S{Val: hsc.uid.String()}},
		MetaContext: m,
	}
	resp, finisher, err := m.G().API.GetResp(apiArg)
	if err != nil {
		return nil, err
	}
	if finisher != nil {
		defer finisher()
	}
	recordFin := tbs.Record("HighSigChain.LoadFromServer.ReadAll")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		recordFin()
		return nil, err
	}
	recordFin()

	// parse the response
	// ------------------
	if val, err := jsonparser.GetInt(body, "status", "code"); err == nil {
		if keybase1.StatusCode(val) == keybase1.StatusCode_SCDeleted {
			return nil, UserDeletedError{}
		}
	}
	var links ChainLinks
	var lastLink *ChainLink

	jsonparser.ArrayEach(body, func(value []byte, dataType jsonparser.ValueType, offset int, inErr error) {
		var link *ChainLink

		parentSigChain := &SigChain{} // because we don't want the cache to use these
		link, err = ImportLinkFromServer(m.G(), parentSigChain, value, selfUID)
		links = append(links, link)
		lastLink = link
	}, "sigs")
	foundTail, err := lastLink.checkAgainstMerkleTree(t)
	if err != nil {
		return nil, err
	}
	if !foundTail {
		// the server needs to send the last link as well as all the high links :(
		err = fmt.Errorf("Last link is not the tail")
		return nil, err
	}
	dirtyTail = lastLink.ToMerkleTriple()

	hsc.chainLinks = links
	return dirtyTail, err
}

func (hsc *HighSigChain) VerifyChain(m MetaContext) (err error) {
	// for each link, call VerifyLink on it
	// also check the hprevs and seqnos and link.CheckNameAndID
	// set that it's highChainVerified
	for i := len(hsc.chainLinks) - 1; i >= 0; i-- {
		curr := hsc.chainLinks[i]
		if err = curr.VerifyLink(); err != nil {
			return err
		}
		if i > 0 {
			prev := hsc.chainLinks[i-1]
			if curr.GetHighSkip() == nil {
				// TODO: fallback to normal prevs if the link doesn't have a high_skip
				return fmt.Errorf("link at seqno %d doesn't have a high skip", curr.GetSeqno())
			}
			if !prev.id.Eq(curr.GetHighSkip().Hash) {
				return ChainLinkPrevHashMismatchError{fmt.Sprintf("Chain mismatch at seqno=%d", curr.GetSeqno())}
			}
			if prev.GetSeqno() != curr.GetHighSkip().Seqno {
				return ChainLinkWrongSeqnoError{fmt.Sprintf("Chain seqno mismatch at seqno=%d (previous=%d)", curr.GetSeqno(), prev.GetSeqno())}
			}
		}
		if err = curr.CheckNameAndID(hsc.username, hsc.uid); err != nil {
			return err
		}
		curr.highChainVerified = true
	}
	return
}

func (l *HighSigChainLoader) VerifySigsAndComputeKeys() (err error) {
	_, err = l.chain.VerifySigsAndComputeKeys(l.M(), l.leaf.eldest, &l.ckf)
	return err
}

func (hsc *HighSigChain) VerifySigsAndComputeKeys(m MetaContext, eldest keybase1.KID, ckf *ComputedKeyFamily) (bool, error) {
	// call verifySubchain, which is hopefully close to completely reusable

	// if cached, ckf.cki, err = sc.verifySubchain(m, *ckf.kf, links); err != nil {
	// 	return cached, len(links), err
	// }

	return false, nil
}

func (l *HighSigChainLoader) GetMerkleTriple() (ret *MerkleTriple) {
	// leaf is what the server said was the leaf for the user
	if l.leaf != nil {
		ret = l.chainType.GetMerkleTriple(l.leaf)
	}
	return
}

func (hsc HighSigChain) ToUPAKLite() (ret *keybase1.UpkLitev1AllIncarnations, err error) {
	// this method probably shouldn't be on the Highsigchain, but should instead be
	// a top level thing that takes one. this is easier for now.
	final := keybase1.UpkLitev1AllIncarnations{
		Current: keybase1.UpkLitev1{
			Username: hsc.username.String(),
			Uid:      hsc.uid,
		},
	}
	ret = &final
	return ret, err
}
