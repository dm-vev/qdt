package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func ensureServerAssets(configPath string, cfg *Config) (bool, error) {
	updated := false
	if cfg.Token == "" {
		token, err := randomToken()
		if err != nil {
			return updated, err
		}
		cfg.Token = token
		updated = true
	}
	if cfg.TLSCert == "" {
		cfg.TLSCert = defaultCertPath(configPath)
		updated = true
	}
	if cfg.TLSKey == "" {
		cfg.TLSKey = defaultKeyPath(configPath)
		updated = true
	}
	certExists, err := fileExists(cfg.TLSCert)
	if err != nil {
		return updated, err
	}
	keyExists, err := fileExists(cfg.TLSKey)
	if err != nil {
		return updated, err
	}
	if !certExists || !keyExists {
		if err := generateSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			return updated, err
		}
		updated = true
	}
	return updated, nil
}

func randomToken() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("token random: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(secret), nil
}

func defaultCertPath(configPath string) string {
	dir := filepath.Dir(configPath)
	return filepath.Join(dir, "cert.pem")
}

func defaultKeyPath(configPath string) string {
	dir := filepath.Dir(configPath)
	return filepath.Join(dir, "key.pem")
}

func writeConfig(path string, cfg Config) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

func generateSelfSigned(certPath, keyPath string) error {
	if err := ensureDir(certPath); err != nil {
		return err
	}
	if err := ensureDir(keyPath); err != nil {
		return err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "QDT",
			Organization: []string{"QDT"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
