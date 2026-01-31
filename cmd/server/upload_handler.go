// ---------------------------------------------------------------------------
// Copyright (c) 2026 Everlast Networks Pty. Ltd..
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" basis,
// without warranties or conditions of any kind, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------------------------------------

package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/envelope"
	"github.com/example/qtls/internal/payload"
	"github.com/example/qtls/internal/qtls"
)

func handleInternalUpload(
	ctx context.Context,
	uploads *uploadStore,
	prov crypto.Provider,
	keys qtls.Keys,
	mode crypto.Mode,
	upstream *url.URL,
	pl payload.RequestPayload,
	msg envelope.Message,
) (envelope.Message, error) {
	switch msg.Header.Path {
	case internalUploadInit:
		if err := uploads.init(pl.Headers); err != nil {
			return envelope.Message{}, err
		}
		return qtls.SealResponse(ctx, qtls.Options{Provider: prov}, keys, mode, http.StatusOK, map[string]string{"Content-Type": "application/json"}, jsonOK(), msg.Header.ReplayID)
	case internalUploadChunk:
		if err := uploads.appendChunk(pl.Headers, pl.Body); err != nil {
			return envelope.Message{}, err
		}
		return qtls.SealResponse(ctx, qtls.Options{Provider: prov}, keys, mode, http.StatusOK, map[string]string{"Content-Type": "application/json"}, jsonOK(), msg.Header.ReplayID)
	case internalUploadAbort:
		uploads.abort(pl.Headers)
		return qtls.SealResponse(ctx, qtls.Options{Provider: prov}, keys, mode, http.StatusOK, map[string]string{"Content-Type": "application/json"}, jsonOK(), msg.Header.ReplayID)
	case internalUploadFinal:
		fu, err := uploads.finalise(pl.Headers)
		if err != nil {
			return envelope.Message{}, err
		}
		defer fu.cleanup()

		upURL := *upstream
		upURL.Path = fu.path
		upURL.RawQuery = fu.query

		upReq, err := http.NewRequestWithContext(ctx, fu.method, upURL.String(), fu.file)
		if err != nil {
			return envelope.Message{}, err
		}
		for k, v := range fu.headers {
			if isHopByHopHeader(k) {
				continue
			}
			upReq.Header.Set(k, v)
		}
		// Ensure upstream sees the right host for virtual hosting.
		if h := upReq.Header.Get("Host"); h == "" {
			upReq.Host = upstream.Host
		}

		upClient := &http.Client{Timeout: 0}
		upResp, err := upClient.Do(upReq)
		if err != nil {
			return envelope.Message{}, err
		}
		defer upResp.Body.Close()

		upBody, err := readAllLimited(upResp.Body, 32<<20)
		if err != nil {
			return envelope.Message{}, err
		}

		respHdrs := make(map[string]string, len(upResp.Header))
		for k, vv := range upResp.Header {
			if len(vv) == 0 {
				continue
			}
			respHdrs[k] = vv[0]
		}

		return qtls.SealResponse(ctx, qtls.Options{Provider: prov}, keys, mode, upResp.StatusCode, respHdrs, upBody, msg.Header.ReplayID)
	default:
		return envelope.Message{}, errors.New("unsupported internal path")
	}
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
