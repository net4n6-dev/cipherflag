// Ported from cipherflag-EE's Venafi push-scheduler hot-reload work
// (EE CHANGELOG v2.6.0 / ki:0006).
//
// BuildClient centralises client construction so that both the push scheduler
// (Pusher) and the TestConnection handler share identical URL-derivation and
// credential-validation logic. CE-delta: uses NormalizeTPPBaseURLs (CE
// already defined it in tpp_adapter.go) rather than reimplementing the suffix
// logic inline.
package venafi

import (
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// BuildClient constructs a VenafiClient from config.
// Returns (nil, error) if required credentials are missing.
//
// URL convention (matches TestConnection behaviour in the handler):
//   - TPP: NormalizeTPPBaseURLs derives /vedsdk and /vedauth from BaseURL.
func BuildClient(v config.VenafiExportConfig) (VenafiClient, error) {
	switch v.Platform {
	case "cloud":
		if v.APIKey == "" {
			return nil, fmt.Errorf("venafi cloud: APIKey is required")
		}
		return NewCloudClient(v.Region, v.APIKey), nil

	default: // "tpp" or anything unset defaults to TPP path
		if v.BaseURL == "" || v.ClientID == "" || v.RefreshToken == "" {
			return nil, fmt.Errorf("venafi tpp: BaseURL, ClientID, and RefreshToken are all required")
		}
		sdkBase, authBase := NormalizeTPPBaseURLs(v.BaseURL)
		tppClient := NewClient(sdkBase, authBase, v.ClientID, v.RefreshToken)
		return NewTPPAdapter(tppClient, v.Folder), nil
	}
}
