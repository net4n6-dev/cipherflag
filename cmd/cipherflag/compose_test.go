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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

type composeFile struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		Profiles    []string `yaml:"profiles"`
		Volumes     []string `yaml:"volumes"`
		NetworkMode string   `yaml:"network_mode"`
		CapAdd      []string `yaml:"cap_add"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

// CE 2.0.0 removed the Zeek sensor from docker-compose.yml, although the
// docs and the published cipherflag-ce-zeek image expected it. It is back
// as an opt-in profile, writing to a volume mounted where the config
// compose runs with (config/cipherflag.toml, via ./config) reads Zeek logs.
func TestCompose_ZeekSensorProfile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	require.NoError(t, err)
	var c composeFile
	require.NoError(t, yaml.Unmarshal(raw, &c))

	zeek, ok := c.Services["zeek"]
	require.True(t, ok, "docker-compose.yml has a zeek service")
	require.Equal(t, []string{"zeek"}, zeek.Profiles,
		"opt-in: a plain `docker compose up` must not start a packet-capturing container")
	require.Equal(t, "ghcr.io/net4n6-dev/cipherflag-ce-zeek:"+Version, zeek.Image,
		"the sensor runs the release it ships with")
	require.Equal(t, "host", zeek.NetworkMode, "live capture needs the host's interfaces")
	require.ElementsMatch(t, []string{"NET_RAW", "NET_ADMIN"}, zeek.CapAdd)
	require.Contains(t, zeek.Volumes, "zeek-logs:/zeek-logs")

	require.Contains(t, c.Volumes, "zeek-logs")

	cfg, err := config.Load(filepath.Join("..", "..", "config", "cipherflag.toml"))
	require.NoError(t, err)
	require.True(t, cfg.Sources.ZeekFile.Enabled, "the compose config reads Zeek logs")
	require.Contains(t, c.Services["cipherflag"].Volumes, "zeek-logs:"+cfg.Sources.ZeekFile.LogDir+":ro",
		"cipherflag reads the sensor's logs, read-only, at the log_dir its config names")
}
