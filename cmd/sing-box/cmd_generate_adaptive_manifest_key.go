package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

type adaptiveManifestPrivateKeyFile struct {
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
}

type adaptiveManifestPublicKeyFile struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

var (
	adaptiveManifestKeyOutput       string
	adaptiveManifestPublicKeyOutput string
	adaptiveManifestKeyID           string
	adaptiveManifestKeyForce        bool
)

var commandGenerateAdaptiveManifestKey = &cobra.Command{
	Use:   "adaptive-manifest-key",
	Short: "Generate an Ed25519 key for AdaptivePool probe manifests",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateAdaptiveManifestKey(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerateAdaptiveManifestKey.Flags().StringVarP(&adaptiveManifestKeyOutput, "output", "o", "", "Private key output file (required, mode 0600)")
	commandGenerateAdaptiveManifestKey.Flags().StringVar(&adaptiveManifestPublicKeyOutput, "public-output", "", "Optional public key output file")
	commandGenerateAdaptiveManifestKey.Flags().StringVar(&adaptiveManifestKeyID, "key-id", "", "Key identifier (defaults to a UTC rotation timestamp)")
	commandGenerateAdaptiveManifestKey.Flags().BoolVar(&adaptiveManifestKeyForce, "force", false, "Replace existing output files")
	_ = commandGenerateAdaptiveManifestKey.MarkFlagRequired("output")
	commandGenerate.AddCommand(commandGenerateAdaptiveManifestKey)
}

func generateAdaptiveManifestKey() error {
	keyID := strings.TrimSpace(adaptiveManifestKeyID)
	if keyID == "" {
		keyID = "adaptive-" + time.Now().UTC().Format("20060102T150405Z")
	}
	if len(keyID) > 128 || strings.ContainsAny(keyID, "\r\n\t") {
		return errors.New("invalid adaptive manifest key id")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDocument, err := json.MarshalIndent(adaptiveManifestPrivateKeyFile{KeyID: keyID, PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey)}, "", "  ")
	if err != nil {
		return err
	}
	if err = writeExclusiveSecretFile(adaptiveManifestKeyOutput, append(privateDocument, '\n'), adaptiveManifestKeyForce); err != nil {
		return err
	}
	publicDocument, err := json.MarshalIndent(adaptiveManifestPublicKeyFile{KeyID: keyID, PublicKey: base64.RawStdEncoding.EncodeToString(publicKey)}, "", "  ")
	if err != nil {
		return err
	}
	publicDocument = append(publicDocument, '\n')
	if adaptiveManifestPublicKeyOutput != "" {
		return writeExclusiveFile(adaptiveManifestPublicKeyOutput, publicDocument, 0o644, adaptiveManifestKeyForce)
	}
	_, err = os.Stdout.Write(publicDocument)
	return err
}

func writeExclusiveSecretFile(path string, content []byte, force bool) error {
	return writeExclusiveFile(path, content, 0o600, force)
}

func writeExclusiveFile(path string, content []byte, mode os.FileMode, force bool) error {
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return errors.New("invalid output path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("output file already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".adaptive-key-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(content)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
