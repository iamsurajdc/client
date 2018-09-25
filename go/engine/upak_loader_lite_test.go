package engine

import (
	"reflect"
	"testing"

	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

type _deviceKeys map[keybase1.KID]keybase1.PublicKeyV2NaCl

func highKeysMatch(dk1, dk2 _deviceKeys) bool {
	highKeys1 := make(_deviceKeys)
	highKeys2 := make(_deviceKeys)
	for kid, key := range dk1 {
		if key.Base.IsSibkey || key.Base.IsEldest {
			highKeys1[kid] = key
		}
	}
	for kid, key := range dk2 {
		if key.Base.IsSibkey || key.Base.IsEldest {
			highKeys2[kid] = key
		}
	}
	return reflect.DeepEqual(highKeys1, highKeys2)
}

func assertUPAKLiteMatchesUPAK(t *testing.T, tc libkb.TestContext, uid keybase1.UID) {
	ctx := context.TODO()
	loadArg := libkb.NewLoadUserByUIDArg(ctx, tc.G, uid)
	upak, _, err := tc.G.GetUPAKLoader().LoadV2(loadArg)
	require.NoError(t, err)
	loadArg.ForUPAKLite()
	upakLite, err := tc.G.GetUPAKLoader().LoadLite(loadArg)
	require.NoError(t, err)
	// uid and name
	require.Equal(t, upakLite.Current.Uid, upak.Current.Uid)
	require.Equal(t, upakLite.Current.Username, upak.Current.Username)
	// device keys (not subkeys, just sibkeys and eldest)
	require.True(t, highKeysMatch(upakLite.Current.DeviceKeys, upak.Current.DeviceKeys))
}

func TestLoadLiteBasicUser(t *testing.T) {
	tc := SetupEngineTest(t, "loadlite")
	defer tc.Cleanup()

	t.Logf("create new user")
	fu := CreateAndSignupFakeUser(tc, "jim")
	uid := fu.UID()
	// basic new user
	assertUPAKLiteMatchesUPAK(t, tc, uid)

	// add a new high link (a new PGP key) and test
	uis := libkb.UIs{LogUI: tc.G.UI.GetLogUI(), SecretUI: fu.NewSecretUI()}
	_, _, key := armorKey(t, tc, fu.Email)
	eng, err := NewPGPKeyImportEngineFromBytes(tc.G, []byte(key), true)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMetaContextForTest(tc).WithUIs(uis)
	if err := RunEngine2(m, eng); err != nil {
		t.Fatal(err)
	}
	assertUPAKLiteMatchesUPAK(t, tc, uid)
}
