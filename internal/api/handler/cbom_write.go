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

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/bomjson"
	"github.com/rs/zerolog/log"
)

// extendWriteDeadline clears the response write deadline for the current
// request. The server applies a 30s WriteTimeout to every route, but a CBOM
// export builds its whole document before writing, so a large estate can
// outlive it. Call it first in every export handler, before generation starts.
// Response writers without deadline support (httptest recorders) are ignored.
func extendWriteDeadline(w http.ResponseWriter) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Time{})
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Warn().Err(err).Msg("cbom: could not extend write deadline")
	}
}

// writeBOM serialises bom with bomjson (which keeps a JSF signature) and
// writes it as a CycloneDX response. The body is built before any header is
// sent, so a serialisation failure becomes a 500 instead of a truncated 200.
// filename, when non-empty, adds a Content-Disposition attachment header;
// pretty indents the JSON.
func writeBOM(w http.ResponseWriter, bom *cdx.BOM, filename string, pretty bool) {
	body, err := bomjson.Encode(bom)
	if err == nil && pretty {
		var buf bytes.Buffer
		if err = json.Indent(&buf, body, "", "  "); err == nil {
			body = buf.Bytes()
			// The old repo handler used json.Encoder, so its output always
			// ended with a newline. Signed output (MarshalSigned) has none.
			if !bytes.HasSuffix(body, []byte("\n")) {
				body = append(body, '\n')
			}
		}
	}
	if err != nil {
		log.Error().Err(err).Msg("cbom: serialise BOM failed")
		writeError(w, http.StatusInternalServerError, "CBOM serialisation failed")
		return
	}
	w.Header().Set("Content-Type", cbomContentType)
	if filename != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
