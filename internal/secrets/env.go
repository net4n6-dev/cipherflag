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

package secrets

import (
	"fmt"
	"os"
)

func resolveEnv(varName string) (string, error) {
	v, ok := os.LookupEnv(varName)
	if !ok {
		return "", fmt.Errorf("secrets: env var %s not set", varName)
	}
	if v == "" {
		return "", fmt.Errorf("secrets: env var %s is empty", varName)
	}
	return v, nil
}
