package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/envelope"
	"github.com/example/qtls/internal/qtls"
)

type qtlsHTTPResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

func sendOneShot(
	ctx context.Context,
	log *slog.Logger,
	prov crypto.Provider,
	keys qtls.Keys,
	mode crypto.Mode,
	hc *http.Client,
	serverURL string,
	rawQuery string,
	method string,
	path string,
	hdrs map[string]string,
	body []byte,
) (qtlsHTTPResponse, error) {
	msg, err := qtls.SealRequest(ctx, qtls.Options{Provider: prov}, keys, mode, method, path, hdrs, body)
	if err != nil {
		return qtlsHTTPResponse{}, err
	}
	mb, err := msg.MarshalBinary()
	if err != nil {
		return qtlsHTTPResponse{}, err
	}

	transportURL, err := appendRawQuery(serverURL, rawQuery)
	if err != nil {
		return qtlsHTTPResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, transportURL, bytes.NewReader(mb))
	if err != nil {
		return qtlsHTTPResponse{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := hc.Do(req)
	if err != nil {
		return qtlsHTTPResponse{}, err
	}
	defer resp.Body.Close()

	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return qtlsHTTPResponse{}, err
	}
	if resp.StatusCode != 200 {
		log.Error("server_error", slog.Int("status", resp.StatusCode), slog.String("body", string(rb)))
		return qtlsHTTPResponse{}, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var rmsg envelope.Message
	if err := rmsg.UnmarshalBinary(rb); err != nil {
		return qtlsHTTPResponse{}, err
	}

	pl, err := qtls.OpenResponse(ctx, qtls.Options{Provider: prov}, keys, rmsg)
	if err != nil {
		return qtlsHTTPResponse{}, err
	}

	status := int(rmsg.Header.StatusCode)
	// Defensive copy.
	outHdrs := make(map[string]string, len(pl.Headers))
	for k, v := range pl.Headers {
		outHdrs[k] = v
	}

	return qtlsHTTPResponse{Status: status, Headers: outHdrs, Body: pl.Body}, nil
}
