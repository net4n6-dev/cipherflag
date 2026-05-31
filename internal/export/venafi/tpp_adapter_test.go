// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package venafi

import "testing"

func TestNormalizeTPPBaseURLs(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		wantSDKBase  string
		wantAuthBase string
	}{
		{
			name:         "bare URL without trailing suffix",
			base:         "https://tpp.example.com",
			wantSDKBase:  "https://tpp.example.com/vedsdk",
			wantAuthBase: "https://tpp.example.com/vedauth",
		},
		{
			name:         "URL already ending in vedsdk",
			base:         "https://tpp.example.com/vedsdk",
			wantSDKBase:  "https://tpp.example.com/vedsdk",
			wantAuthBase: "https://tpp.example.com/vedauth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSDK, gotAuth := NormalizeTPPBaseURLs(tt.base)
			if gotSDK != tt.wantSDKBase {
				t.Errorf("sdkBase = %q, want %q", gotSDK, tt.wantSDKBase)
			}
			if gotAuth != tt.wantAuthBase {
				t.Errorf("authBase = %q, want %q", gotAuth, tt.wantAuthBase)
			}
		})
	}
}
