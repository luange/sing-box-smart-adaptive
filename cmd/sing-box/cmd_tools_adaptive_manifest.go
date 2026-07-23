package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group/adaptive"

	"github.com/spf13/cobra"
)

var (
	adaptiveManifestListen   string
	adaptiveManifestPath     string
	adaptiveManifestSpecPath string
	adaptiveManifestKeyPath  string
	adaptiveManifestTLSCert  string
	adaptiveManifestTLSKey   string
)

var commandToolsAdaptiveManifest = &cobra.Command{Use: "adaptive-manifest", Short: "AdaptivePool signed probe manifest control plane"}

var commandToolsAdaptiveManifestServe = &cobra.Command{
	Use:   "serve",
	Short: "Serve a reloadable signed probe manifest over TLS",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := serveAdaptiveManifest(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestListen, "listen", "127.0.0.1:9443", "TLS listen address")
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestPath, "path", "/adaptive-probe-manifest", "HTTP path")
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestSpecPath, "manifest", "", "Manifest payload specification file")
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestKeyPath, "key", "", "Mode-0600 Ed25519 private key file")
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestTLSCert, "tls-cert", "", "TLS certificate file")
	commandToolsAdaptiveManifestServe.Flags().StringVar(&adaptiveManifestTLSKey, "tls-key", "", "TLS private key file")
	for _, name := range []string{"manifest", "key", "tls-cert", "tls-key"} {
		_ = commandToolsAdaptiveManifestServe.MarkFlagRequired(name)
	}
	commandToolsAdaptiveManifest.AddCommand(commandToolsAdaptiveManifestServe)
	commandTools.AddCommand(commandToolsAdaptiveManifest)
}

func serveAdaptiveManifest() error {
	if !strings.HasPrefix(adaptiveManifestPath, "/") || strings.ContainsAny(adaptiveManifestPath, "?#") {
		return errors.New("adaptive manifest path must be an absolute URL path")
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != adaptiveManifestPath {
			http.NotFound(writer, request)
			return
		}
		manifest, err := loadPublishedAdaptiveManifest(adaptiveManifestSpecPath, adaptiveManifestKeyPath, time.Now())
		if err != nil {
			writer.Header().Set("Cache-Control", "no-store")
			http.Error(writer, "manifest unavailable", http.StatusServiceUnavailable)
			return
		}
		if err = manifest.WriteHTTP(writer.Header(), writer); err != nil {
			return
		}
	})
	server := &http.Server{Addr: adaptiveManifestListen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	return server.ListenAndServeTLS(adaptiveManifestTLSCert, adaptiveManifestTLSKey)
}

func loadPublishedAdaptiveManifest(specPath, keyPath string, now time.Time) (*adaptive.PublishedProbeManifest, error) {
	keyContent, err := readLimitedRegularFile(keyPath, 16*1024, true)
	if err != nil {
		return nil, err
	}
	var keyFile adaptiveManifestPrivateKeyFile
	if err = decodeStrictJSON(keyContent, &keyFile); err != nil {
		return nil, errors.New("invalid adaptive manifest key file")
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(keyFile.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid adaptive manifest private key")
	}
	specContent, err := readLimitedRegularFile(specPath, 256*1024, false)
	if err != nil {
		return nil, err
	}
	var spec adaptive.ProbeManifestPayload
	if err = decodeStrictJSON(specContent, &spec); err != nil {
		return nil, errors.New("invalid adaptive manifest specification")
	}
	if now.Before(spec.IssuedAt) || !now.Before(spec.ExpiresAt) || spec.ExpiresAt.Sub(now) < 30*time.Second {
		return nil, errors.New("adaptive manifest specification is outside its validity window")
	}
	return adaptive.PublishProbeManifest(keyFile.KeyID, ed25519.PrivateKey(privateKey), spec)
}

func readLimitedRegularFile(path string, limit int64, requirePrivate bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("adaptive manifest input must be a bounded regular file")
	}
	if requirePrivate && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("adaptive manifest private key file permissions must be 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("adaptive manifest input exceeds limit")
	}
	return content, nil
}

func decodeStrictJSON(content []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
