#!/bin/sh
# Copyright 2026 net4n6-dev
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# check-release-tag.sh <tag>
#
# Fails unless a release tag (for example v2.3.0 or v2.3.0-rc1) names the
# version the binary reports: `const Version` in cmd/cipherflag/main.go must
# equal the tag without its leading "v". The release workflow runs this
# before it publishes images, so an image tagged 2.3.1 can never contain a
# binary that prints 2.3.0. Run from the repository root.
#
# TestVersionHasChangelogSection (cmd/cipherflag/version_test.go) checks on
# every CI run that Version has a CHANGELOG.md section.

set -eu

tag="${1:?usage: scripts/check-release-tag.sh <tag, e.g. v2.3.0>}"
case "$tag" in
  v*) ;;
  *) echo "release tag $tag must start with v" >&2; exit 1 ;;
esac
want="${tag#v}"

have=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' cmd/cipherflag/main.go)
if [ -z "$have" ]; then
  echo "cannot find const Version in cmd/cipherflag/main.go" >&2
  exit 1
fi
if [ "$have" != "$want" ]; then
  echo "release tag $tag does not match const Version = \"$have\" in cmd/cipherflag/main.go" >&2
  exit 1
fi
echo "release tag $tag matches const Version in cmd/cipherflag/main.go"
