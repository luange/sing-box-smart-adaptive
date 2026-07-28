package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group/adaptive"

	"github.com/spf13/cobra"
)

var (
	adaptiveManifestListen     string
	adaptiveManifestPath       string
	adaptiveManifestSpecPath   string
	adaptiveManifestKeyPath    string
	adaptiveManifestTLSCert    string
	adaptiveManifestTLSKey     string
	adaptiveManifestURLFile    string
	adaptiveManifestOutput     string
	adaptiveManifestGeneration uint64
	adaptiveManifestValidFor   time.Duration
	adaptiveManifestRangeStart int64
	adaptiveManifestRangeEnd   int64
	adaptiveManifestForce      bool
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

var commandToolsAdaptiveManifestPrepareYouTube = &cobra.Command{
	Use:   "prepare-youtube-range",
	Short: "Prepare a private signed-URL Range manifest specification",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := prepareAdaptiveYouTubeRangeManifest(); err != nil {
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
	commandToolsAdaptiveManifestPrepareYouTube.Flags().StringVar(&adaptiveManifestURLFile, "url-file", "", "Mode-0600 file containing one fresh googlevideo HTTPS URL")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().StringVar(&adaptiveManifestOutput, "output", "", "Private manifest specification output (mode 0600)")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().Uint64Var(&adaptiveManifestGeneration, "generation", 0, "Monotonic manifest generation (defaults to current Unix nanoseconds)")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().DurationVar(&adaptiveManifestValidFor, "valid-for", 30*time.Minute, "Manifest validity window")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().Int64Var(&adaptiveManifestRangeStart, "range-start", 0, "First payload byte")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().Int64Var(&adaptiveManifestRangeEnd, "range-end", 65535, "Last payload byte")
	commandToolsAdaptiveManifestPrepareYouTube.Flags().BoolVar(&adaptiveManifestForce, "force", false, "Replace an existing output file")
	_ = commandToolsAdaptiveManifestPrepareYouTube.MarkFlagRequired("url-file")
	_ = commandToolsAdaptiveManifestPrepareYouTube.MarkFlagRequired("output")
	commandToolsAdaptiveManifest.AddCommand(commandToolsAdaptiveManifestPrepareYouTube)
	commandTools.AddCommand(commandToolsAdaptiveManifest)
}

func prepareAdaptiveYouTubeRangeManifest() error {
	urlContent, err := readLimitedRegularFile(adaptiveManifestURLFile, 16*1024, true)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if !isGoogleVideoURL(request.URL) {
				return errors.New("adaptive media redirect rejected")
			}
			return nil
		},
	}
	spec, err := prepareAdaptiveYouTubeRangeSpec(time.Now().UTC(), client, urlContent, adaptiveManifestGeneration, adaptiveManifestValidFor, adaptiveManifestRangeStart, adaptiveManifestRangeEnd)
	if err != nil {
		return err
	}
	document, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return errors.New("adaptive manifest specification encoding failed")
	}
	return writeExclusiveSecretFile(adaptiveManifestOutput, append(document, '\n'), adaptiveManifestForce)
}

func prepareAdaptiveYouTubeRangeSpec(now time.Time, client *http.Client, urlContent []byte, generation uint64, validFor time.Duration, rangeStart, rangeEnd int64) (adaptive.ProbeManifestPayload, error) {
	if client == nil || validFor < time.Minute || validFor > 6*time.Hour || rangeStart < 0 || rangeEnd < rangeStart || rangeEnd-rangeStart+1 > 1024*1024 {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube Range policy is invalid")
	}
	rawURL := strings.TrimSpace(string(urlContent))
	parsed, err := url.Parse(rawURL)
	if err != nil || !isGoogleVideoURL(parsed) || parsed.RawQuery == "" || parsed.Fragment != "" || parsed.User != nil {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube signed URL is invalid")
	}
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube Range request is invalid")
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Range", "bytes="+strconv.FormatInt(rangeStart, 10)+"-"+strconv.FormatInt(rangeEnd, 10))
	request.Header.Set("User-Agent", "sing-box-adaptive-manifest/1")
	response, err := client.Do(request)
	if err != nil {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube Range fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusPartialContent || !strings.HasPrefix(strings.TrimSpace(response.Header.Get("Content-Range")), "bytes "+strconv.FormatInt(rangeStart, 10)+"-"+strconv.FormatInt(rangeEnd, 10)+"/") {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube endpoint did not honor the requested Range")
	}
	wanted := rangeEnd - rangeStart + 1
	payload, err := io.ReadAll(io.LimitReader(response.Body, wanted+1))
	if err != nil || int64(len(payload)) != wanted {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube Range payload length is invalid")
	}
	if bytes.Contains(bytes.ToLower(payload[:min(len(payload), 64)]), []byte("<html")) {
		return adaptive.ProbeManifestPayload{}, errors.New("adaptive YouTube Range returned an HTML payload")
	}
	digest := sha256.Sum256(payload)
	if generation == 0 {
		generation = uint64(now.UnixNano())
	}
	issuedAt := now.Add(-5 * time.Second)
	redirectHosts := []string{strings.ToLower(parsed.Hostname())}
	if response.Request != nil && response.Request.URL != nil {
		finalHost := strings.ToLower(response.Request.URL.Hostname())
		if finalHost != "" && finalHost != redirectHosts[0] {
			redirectHosts = append(redirectHosts, finalHost)
		}
	}
	return adaptive.ProbeManifestPayload{
		SourceID: adaptive.YouTubeTargetSourceID, ServiceID: adaptive.YouTubeProbeServiceID,
		Generation: generation, IssuedAt: issuedAt, ExpiresAt: now.Add(validFor),
		Targets: []adaptive.ProbeManifestTarget{{
			URL: rawURL, Capability: adaptive.ProbeCapabilityRange, RangeStart: &rangeStart, RangeEnd: &rangeEnd,
			ExpectedDigest: hex.EncodeToString(digest[:]), RedirectHosts: redirectHosts,
		}},
	}, nil
}

func isGoogleVideoURL(parsed *url.URL) bool {
	if parsed == nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Port() != "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	return host == "googlevideo.com" || strings.HasSuffix(host, ".googlevideo.com")
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
