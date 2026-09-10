// Copyright 2026 Google LLC
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

package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/agent-substrate/substrate/internal/ateapiauth"
)

func generateTestCertificate(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
}

func TestMutateAuthenticationConfig_Bootstrap(t *testing.T) {
	cfg, outYAML, err := mutateAuthenticationConfig(
		"",
		"keycloak",
		"https://keycloak.example.com/realms/test",
		[]string{"substrate"},
		true,
		false,
		"https://kubernetes.default.svc",
	)
	if err != nil {
		t.Fatalf("mutateAuthenticationConfig() unexpected error: %v", err)
	}

	if cfg.ActorIdentityJWTProvider != "kubernetes" {
		t.Errorf("got actorIdentityJWTProvider = %q, want %q", cfg.ActorIdentityJWTProvider, "kubernetes")
	}

	if len(cfg.JWTProviders) != 2 {
		t.Fatalf("got %d providers, want 2", len(cfg.JWTProviders))
	}

	keycloakProvider := cfg.JWTProviders[1]
	if keycloakProvider.Name != "keycloak" {
		t.Errorf("got name = %q, want keycloak", keycloakProvider.Name)
	}
	if keycloakProvider.CertificateAuthorityFile != "/etc/ateapi/authentication/keycloak-ca.crt" {
		t.Errorf("got CA file = %q, want /etc/ateapi/authentication/keycloak-ca.crt", keycloakProvider.CertificateAuthorityFile)
	}

	var parsed ateapiauth.AuthenticationConfig
	if err := yaml.UnmarshalStrict([]byte(outYAML), &parsed); err != nil {
		t.Fatalf("failed to parse generated YAML: %v", err)
	}
	if diff := cmp.Diff(cfg, &parsed); diff != "" {
		t.Errorf("mismatch between struct and marshaled YAML (-want +got):\n%s", diff)
	}
}

func TestMutateAuthenticationConfig_AppendAndInPlaceUpdate(t *testing.T) {
	initialYAML := `
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc
  audiences:
  - api.ate-system.svc
`

	// 1. Append new provider without CA
	cfg1, yaml1, err := mutateAuthenticationConfig(
		initialYAML,
		"okta",
		"https://okta.example.com",
		[]string{"substrate-api"},
		false,
		false,
		"",
	)
	if err != nil {
		t.Fatalf("append unexpected error: %v", err)
	}
	if len(cfg1.JWTProviders) != 2 {
		t.Fatalf("got %d providers, want 2", len(cfg1.JWTProviders))
	}
	if cfg1.JWTProviders[1].CertificateAuthorityFile != "" {
		t.Errorf("expected empty CA file, got %q", cfg1.JWTProviders[1].CertificateAuthorityFile)
	}

	// 2. In-place update of the okta provider (adding CA and updating audiences)
	cfg2, _, err := mutateAuthenticationConfig(
		yaml1,
		"okta",
		"https://okta.example.com",
		[]string{"substrate-api", "admin-api"},
		true,
		true,
		"",
	)
	if err != nil {
		t.Fatalf("update unexpected error: %v", err)
	}
	if len(cfg2.JWTProviders) != 2 {
		t.Fatalf("got %d providers, want 2 (no duplicates)", len(cfg2.JWTProviders))
	}
	if cfg2.ActorIdentityJWTProvider != "okta" {
		t.Errorf("got ActorIdentityJWTProvider = %q, want okta", cfg2.ActorIdentityJWTProvider)
	}
	if cfg2.JWTProviders[1].CertificateAuthorityFile != "/etc/ateapi/authentication/okta-ca.crt" {
		t.Errorf("got CA file = %q, want okta-ca.crt", cfg2.JWTProviders[1].CertificateAuthorityFile)
	}
	if diff := cmp.Diff([]string{"substrate-api", "admin-api"}, cfg2.JWTProviders[1].Audiences); diff != "" {
		t.Errorf("audiences mismatch (-want +got):\n%s", diff)
	}
}

func TestMutateAuthenticationConfig_ValidationRejections(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		audiences []string
		wantErr   string
	}{
		{
			name:      "insecure http issuer",
			issuer:    "http://insecure.example.com",
			audiences: []string{"substrate"},
			wantErr:   "must be an HTTPS URL",
		},
		{
			name:      "issuer with query",
			issuer:    "https://auth.example.com?query=1",
			audiences: []string{"substrate"},
			wantErr:   "without query or fragment",
		},
		{
			name:      "empty audiences",
			issuer:    "https://auth.example.com",
			audiences: []string{},
			wantErr:   "must contain at least one audience",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := mutateAuthenticationConfig(
				"",
				"test-idp",
				tc.issuer,
				tc.audiences,
				false,
				false,
				"",
			)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain expected substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidatePEMCert(t *testing.T) {
	validCert := generateTestCertificate(t)

	// Valid certificate
	got, err := validatePEMCert(validCert)
	if err != nil {
		t.Fatalf("validatePEMCert() unexpected error: %v", err)
	}
	if string(got) != string(validCert) {
		t.Errorf("validatePEMCert() returned modified bytes")
	}

	// Invalid non-PEM data
	if _, err := validatePEMCert([]byte("not a pem cert")); err == nil {
		t.Errorf("validatePEMCert() expected error for non-PEM data, got nil")
	}

	// Non-certificate PEM block (e.g. RSA PRIVATE KEY)
	fakeKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte{1, 2, 3},
	})
	if _, err := validatePEMCert(fakeKeyPEM); err == nil {
		t.Errorf("validatePEMCert() expected error for non-CERTIFICATE block, got nil")
	}
}

func TestResolveCACertificate(t *testing.T) {
	ctx := context.Background()
	certPEM := generateTestCertificate(t)

	kc := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "keycloak",
			Name:      "keycloak-tls",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
		},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "custom",
			Name:      "tls-only",
		},
		Data: map[string][]byte{
			"tls.crt": certPEM,
		},
	})

	// 1. From Secret with ca.crt
	got, err := resolveCACertificate(ctx, kc, caCertificateOptions{
		caSecretName:      "keycloak-tls",
		caSecretNamespace: "keycloak",
		caSecretKey:       "ca.crt",
	})
	if err != nil {
		t.Fatalf("resolveCACertificate() error = %v", err)
	}
	if string(got) != string(certPEM) {
		t.Errorf("mismatch in extracted CA bytes")
	}

	// 2. Fallback to tls.crt when ca.crt requested but not present
	got, err = resolveCACertificate(ctx, kc, caCertificateOptions{
		caSecretName:      "tls-only",
		caSecretNamespace: "custom",
		caSecretKey:       "ca.crt",
	})
	if err != nil {
		t.Fatalf("resolveCACertificate() fallback error = %v", err)
	}
	if string(got) != string(certPEM) {
		t.Errorf("mismatch in fallback CA bytes")
	}

	// 3. From local file
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test-ca.crt")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write temp cert file: %v", err)
	}
	got, err = resolveCACertificate(ctx, nil, caCertificateOptions{
		caFile: certFile,
	})
	if err != nil {
		t.Fatalf("resolveCACertificate() from file error = %v", err)
	}
	if string(got) != string(certPEM) {
		t.Errorf("mismatch in file CA bytes")
	}

	// 4. Neither secret nor file specified
	got, err = resolveCACertificate(ctx, nil, caCertificateOptions{})
	if err != nil {
		t.Fatalf("resolveCACertificate() empty options error = %v", err)
	}
	if got != nil {
		t.Errorf("expected nil CA bytes when none specified, got %v", got)
	}

	// 5. Secret not found
	_, err = resolveCACertificate(ctx, kc, caCertificateOptions{
		caSecretName:      "missing-secret",
		caSecretNamespace: "keycloak",
		caSecretKey:       "ca.crt",
	})
	if err == nil {
		t.Errorf("expected error for missing secret, got nil")
	}
}

func TestExecuteAddJwtProvider(t *testing.T) {
	ctx := context.Background()
	certPEM := generateTestCertificate(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "keycloak",
			Name:      "keycloak-tls",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
		},
	}

	// Case 1: Initial creation (ConfigMap does not exist)
	kc := fake.NewSimpleClientset(secret)
	opts := addJwtProviderOptions{
		issuer:            "https://keycloak.keycloak.svc.cluster.local:8443/realms/substrate",
		audiences:         []string{"substrate"},
		caSecretName:      "keycloak-tls",
		caSecretNamespace: "keycloak",
		caSecretKey:       "ca.crt",
		systemNamespace:   "ate-system",
		configMapName:     "ate-api-authentication",
		restart:           false,
	}

	cfg, err := executeAddJwtProvider(ctx, kc, "keycloak", opts)
	if err != nil {
		t.Fatalf("executeAddJwtProvider() error = %v", err)
	}
	if len(cfg.JWTProviders) != 2 {
		t.Fatalf("got %d providers, want 2", len(cfg.JWTProviders))
	}

	cm, err := kc.CoreV1().ConfigMaps("ate-system").Get(ctx, "ate-api-authentication", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to retrieve created ConfigMap: %v", err)
	}
	if cm.Data["keycloak-ca.crt"] != string(certPEM) {
		t.Errorf("expected keycloak-ca.crt in ConfigMap Data")
	}
	if cm.Data["authentication.yaml"] == "" {
		t.Errorf("expected non-empty authentication.yaml in ConfigMap Data")
	}

	// Case 2: Update existing ConfigMap with another provider
	opts2 := addJwtProviderOptions{
		issuer:          "https://okta.example.com",
		audiences:       []string{"substrate-api"},
		systemNamespace: "ate-system",
		configMapName:   "ate-api-authentication",
		restart:         false,
	}
	cfg2, err := executeAddJwtProvider(ctx, kc, "okta", opts2)
	if err != nil {
		t.Fatalf("executeAddJwtProvider() update error = %v", err)
	}
	if len(cfg2.JWTProviders) != 3 {
		t.Fatalf("got %d providers, want 3", len(cfg2.JWTProviders))
	}

	cmUpdated, err := kc.CoreV1().ConfigMaps("ate-system").Get(ctx, "ate-api-authentication", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to retrieve updated ConfigMap: %v", err)
	}
	// Verify previous ca cert is preserved
	if cmUpdated.Data["keycloak-ca.crt"] != string(certPEM) {
		t.Errorf("previous keycloak-ca.crt was not preserved")
	}

	// Case 3: Dry-run does not write to cluster
	optsDryRun := addJwtProviderOptions{
		issuer:          "https://auth0.example.com",
		audiences:       []string{"substrate-api"},
		systemNamespace: "ate-system",
		configMapName:   "ate-api-authentication",
		dryRun:          true,
	}
	cfgDry, err := executeAddJwtProvider(ctx, kc, "auth0", optsDryRun)
	if err != nil {
		t.Fatalf("executeAddJwtProvider() dry-run error = %v", err)
	}
	if len(cfgDry.JWTProviders) != 4 {
		t.Errorf("dry-run config expected 4 providers, got %d", len(cfgDry.JWTProviders))
	}
	// Verify cm was NOT modified by dry-run (still 3 providers)
	cmAfterDry, _ := kc.CoreV1().ConfigMaps("ate-system").Get(ctx, "ate-api-authentication", metav1.GetOptions{})
	var parsedConfig ateapiauth.AuthenticationConfig
	if err := yaml.UnmarshalStrict([]byte(cmAfterDry.Data["authentication.yaml"]), &parsedConfig); err != nil {
		t.Fatalf("failed to parse yaml: %v", err)
	}
	if len(parsedConfig.JWTProviders) != 3 {
		t.Errorf("dry-run modified cluster configmap: got %d providers, want 3", len(parsedConfig.JWTProviders))
	}
}
