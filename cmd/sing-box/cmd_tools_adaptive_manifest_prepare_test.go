package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/group/adaptive"
)

type adaptiveManifestRoundTripper func(*http.Request) (*http.Response, error)

func (f adaptiveManifestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPrepareAdaptiveYouTubeRangeSpecValidatesAndDigestsPrivateURL(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 16)
	client := &http.Client{Transport: adaptiveManifestRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Range") != "bytes=0-15" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("unexpected range request headers: %+v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     http.Header{"Content-Range": []string{"bytes 0-15/1000"}},
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    request,
		}, nil
	})}
	now := time.Date(2026, time.July, 28, 1, 2, 3, 0, time.UTC)
	privateURL := "https://r1---sn-a5mekn.googlevideo.com/videoplayback?expire=secret-token"
	spec, err := prepareAdaptiveYouTubeRangeSpec(now, client, []byte(privateURL+"\n"), 77, 30*time.Minute, 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Generation != 77 || len(spec.Targets) != 1 || spec.Targets[0].Capability != adaptive.ProbeCapabilityRange || spec.Targets[0].ExpectedDigest == "" || spec.Targets[0].URL != privateURL {
		t.Fatalf("unexpected private manifest specification: %+v", spec)
	}
}

func TestPrepareAdaptiveYouTubeRangeSpecNeverIncludesURLInErrors(t *testing.T) {
	privateURL := "https://r1---sn-a5mekn.googlevideo.com/videoplayback?token=must-not-leak"
	client := &http.Client{Transport: adaptiveManifestRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("upstream failed with private request")
	})}
	_, err := prepareAdaptiveYouTubeRangeSpec(time.Now(), client, []byte(privateURL), 1, time.Minute, 0, 15)
	if err == nil || strings.Contains(err.Error(), "must-not-leak") || strings.Contains(err.Error(), "googlevideo.com/videoplayback") {
		t.Fatalf("private URL leaked through preparation error: %v", err)
	}
}
