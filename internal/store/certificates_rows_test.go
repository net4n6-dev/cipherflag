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

package store

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// failingRows ends immediately and reports an error, as a statement timeout or
// a dropped connection part way through a result set does.
type failingRows struct {
	pgx.Rows
	err error
}

func (failingRows) Next() bool   { return false }
func (f failingRows) Err() error { return f.err }
func (failingRows) Close()       {}

// A query that dies mid-result must surface as an error, not as a short page
// that looks like the end of the data.
func TestCertificatesFromRows_ReturnsTheRowsError(t *testing.T) {
	want := errors.New("connection reset")
	certs, err := certificatesFromRows(failingRows{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v (certs = %v)", err, want, certs)
	}
}

func TestCertificatesFromRows_NoRowsIsAnEmptySlice(t *testing.T) {
	certs, err := certificatesFromRows(failingRows{})
	if err != nil || certs == nil || len(certs) != 0 {
		t.Fatalf("certs = %#v, err = %v", certs, err)
	}
}
