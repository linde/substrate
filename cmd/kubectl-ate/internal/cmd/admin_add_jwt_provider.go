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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/agent-substrate/substrate/internal/ateapiauth"
	"github.com/agent-substrate/substrate/internal/ateclient"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

var (
	jwtProviderIssuer            string
	jwtProviderAudiences         []string
	jwtProviderCASecret          string
	jwtProviderCASecretNamespace string
	jwtProviderCASecretKey       string
	jwtProviderCAFile            string
	jwtProviderSystemNamespace   string
	jwtProviderConfigMap         string
	jwtProviderSetActorIdentity  bool
	jwtProviderRestart           bool
	jwtProviderWait              bool
	jwtProviderTimeout           time.Duration
	jwtProviderDryRun            bool
)

const (
	defaultSystemNamespace     = "ate-system"
	defaultConfigMapName       = "ate-api-authentication"
	defaultAPIServerDeployment = "ate-api-server"
	defaultInClusterIssuer     = "https://kubernetes.default.svc"
)

var addJwtProviderCmd = &cobra.Command{
	Use:     "add-jwt-provider <name>",
	Aliases: []string{"configure-jwt-provider"},
	Short:   "Add or update a trusted OIDC JWT provider in the Substrate authentication config",
	Long: `Add or update a trusted OpenID Connect (OIDC) JWT provider in Substrate's
control plane authentication ConfigMap (ate-system/ate-api-authentication).

If a CA certificate secret or file is specified, the certificate is validated
and embedded into the ConfigMap, and the provider is configured to use it.
By default, this command also performs a rolling restart of the ate-api-server
deployment and waits for the rollout to complete.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		providerName := args[0]

		if jwtProviderIssuer == "" {
			return fmt.Errorf("--issuer is required")
		}
		if len(jwtProviderAudiences) == 0 {
			return fmt.Errorf("--audience is required")
		}

		var kc kubernetes.Interface
		if !jwtProviderDryRun || jwtProviderCASecret != "" {
			kconfig, err := ateclient.LoadKubeConfig(kubeconfig, k8sContext)
			if err != nil {
				return fmt.Errorf("while reading kubeconfig: %w", err)
			}
			kc, err = kubernetes.NewForConfig(kconfig)
			if err != nil {
				return fmt.Errorf("while creating Kubernetes client: %w", err)
			}
		}

		opts := addJwtProviderOptions{
			issuer:            jwtProviderIssuer,
			audiences:         jwtProviderAudiences,
			caSecretName:      jwtProviderCASecret,
			caSecretNamespace: jwtProviderCASecretNamespace,
			caSecretKey:       jwtProviderCASecretKey,
			caFile:            jwtProviderCAFile,
			systemNamespace:   jwtProviderSystemNamespace,
			configMapName:     jwtProviderConfigMap,
			setActorIdentity:  jwtProviderSetActorIdentity,
			restart:           jwtProviderRestart,
			wait:              jwtProviderWait,
			timeout:           jwtProviderTimeout,
			dryRun:            jwtProviderDryRun,
		}

		_, err := executeAddJwtProvider(ctx, kc, providerName, opts)
		return err
	},
}

type addJwtProviderOptions struct {
	issuer            string
	audiences         []string
	caSecretName      string
	caSecretNamespace string
	caSecretKey       string
	caFile            string
	systemNamespace   string
	configMapName     string
	setActorIdentity  bool
	restart           bool
	wait              bool
	timeout           time.Duration
	dryRun            bool
}

func executeAddJwtProvider(
	ctx context.Context,
	kc kubernetes.Interface,
	providerName string,
	opts addJwtProviderOptions,
) (*ateapiauth.AuthenticationConfig, error) {
	if opts.systemNamespace == "" {
		opts.systemNamespace = defaultSystemNamespace
	}
	if opts.configMapName == "" {
		opts.configMapName = defaultConfigMapName
	}

	caOpts := caCertificateOptions{
		caSecretName:      opts.caSecretName,
		caSecretNamespace: opts.caSecretNamespace,
		caSecretKey:       opts.caSecretKey,
		caFile:            opts.caFile,
	}
	caCertBytes, err := resolveCACertificate(ctx, kc, caOpts)
	if err != nil {
		return nil, err
	}

	var existingYAML string
	var existingConfigMap *corev1.ConfigMap
	var clusterIssuer string

	if kc != nil {
		cm, err := kc.CoreV1().ConfigMaps(opts.systemNamespace).Get(ctx, opts.configMapName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("while reading ConfigMap %s/%s: %w", opts.systemNamespace, opts.configMapName, err)
			}
			clusterIssuer = detectClusterOIDCIssuer(ctx, kc)
		} else {
			existingConfigMap = cm
			if cm.Data != nil {
				existingYAML = cm.Data["authentication.yaml"]
			}
		}
	}

	newConfig, newYAML, err := mutateAuthenticationConfig(
		existingYAML,
		providerName,
		opts.issuer,
		opts.audiences,
		len(caCertBytes) > 0,
		opts.setActorIdentity,
		clusterIssuer,
	)
	if err != nil {
		return nil, err
	}

	if opts.dryRun {
		fmt.Println("# Dry run: Resulting authentication.yaml:")
		fmt.Println(newYAML)
		if len(caCertBytes) > 0 {
			fmt.Printf("# Embedded CA certificate (%s-ca.crt): %d bytes\n", providerName, len(caCertBytes))
		}
		return newConfig, nil
	}

	if kc == nil {
		return nil, fmt.Errorf("kubernetes client is required to apply changes to cluster")
	}

	caKeyName := fmt.Sprintf("%s-ca.crt", providerName)
	if existingConfigMap == nil {
		newCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: opts.systemNamespace,
				Name:      opts.configMapName,
			},
			Data: map[string]string{
				"authentication.yaml": newYAML,
			},
		}
		if len(caCertBytes) > 0 {
			newCM.Data[caKeyName] = string(caCertBytes)
		}
		_, err = kc.CoreV1().ConfigMaps(opts.systemNamespace).Create(ctx, newCM, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("while creating ConfigMap %s/%s: %w", opts.systemNamespace, opts.configMapName, err)
		}
		fmt.Printf("Created ConfigMap %s/%s with JWT provider %q\n", opts.systemNamespace, opts.configMapName, providerName)
	} else {
		cmToUpdate := existingConfigMap.DeepCopy()
		if cmToUpdate.Data == nil {
			cmToUpdate.Data = make(map[string]string)
		}
		cmToUpdate.Data["authentication.yaml"] = newYAML
		if len(caCertBytes) > 0 {
			cmToUpdate.Data[caKeyName] = string(caCertBytes)
		}
		_, err = kc.CoreV1().ConfigMaps(opts.systemNamespace).Update(ctx, cmToUpdate, metav1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("while updating ConfigMap %s/%s: %w", opts.systemNamespace, opts.configMapName, err)
		}
		fmt.Printf("Updated ConfigMap %s/%s with JWT provider %q\n", opts.systemNamespace, opts.configMapName, providerName)
	}

	if opts.restart {
		if err := restartDeployment(ctx, kc, opts.systemNamespace, defaultAPIServerDeployment); err != nil {
			return nil, err
		}
		fmt.Printf("Triggered rollout restart of deployment/%s in namespace %s\n", defaultAPIServerDeployment, opts.systemNamespace)

		if opts.wait {
			fmt.Printf("Waiting up to %s for deployment/%s rollout to finish...\n", opts.timeout, defaultAPIServerDeployment)
			if err := waitForDeploymentRollout(ctx, kc, opts.systemNamespace, defaultAPIServerDeployment, opts.timeout); err != nil {
				return nil, err
			}
			fmt.Printf("Deployment/%s successfully rolled out\n", defaultAPIServerDeployment)
		}
	}

	return newConfig, nil
}

type caCertificateOptions struct {
	caSecretName      string
	caSecretNamespace string
	caSecretKey       string
	caFile            string
}

func resolveCACertificate(ctx context.Context, kc kubernetes.Interface, opts caCertificateOptions) ([]byte, error) {
	if opts.caFile != "" {
		b, err := os.ReadFile(opts.caFile)
		if err != nil {
			return nil, fmt.Errorf("while reading CA file %q: %w", opts.caFile, err)
		}
		return validatePEMCert(b)
	}

	if opts.caSecretName != "" {
		if kc == nil {
			return nil, fmt.Errorf("cannot read Secret %q without a Kubernetes client", opts.caSecretName)
		}
		ns := opts.caSecretNamespace
		if ns == "" {
			ns = "default"
		}
		secret, err := kc.CoreV1().Secrets(ns).Get(ctx, opts.caSecretName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("while fetching secret %s/%s: %w", ns, opts.caSecretName, err)
		}

		key := opts.caSecretKey
		val, ok := secret.Data[key]
		if !ok {
			if key == "ca.crt" {
				if altVal, altOk := secret.Data["tls.crt"]; altOk {
					val = altVal
					ok = true
				}
			}
			if !ok {
				return nil, fmt.Errorf("key %q not found in secret %s/%s", key, ns, opts.caSecretName)
			}
		}

		return validatePEMCert(val)
	}

	return nil, nil
}

func validatePEMCert(data []byte) ([]byte, error) {
	rest := data
	certCount := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected PEM block of type CERTIFICATE, got %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid x509 certificate in PEM data: %w", err)
		}
		certCount++
	}
	if certCount == 0 {
		return nil, fmt.Errorf("provided data contains no valid PEM CERTIFICATE blocks")
	}
	return data, nil
}

func detectClusterOIDCIssuer(ctx context.Context, kc kubernetes.Interface) string {
	if kc == nil || kc.Discovery() == nil || kc.Discovery().RESTClient() == nil {
		return defaultInClusterIssuer
	}
	res, err := kc.Discovery().RESTClient().Get().AbsPath("/.well-known/openid-configuration").DoRaw(ctx)
	if err == nil {
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.Unmarshal(res, &doc); err == nil && doc.Issuer != "" {
			return doc.Issuer
		}
	}
	return defaultInClusterIssuer
}

func bootstrapAuthenticationConfig(clusterIssuer string) ateapiauth.AuthenticationConfig {
	if clusterIssuer == "" {
		clusterIssuer = defaultInClusterIssuer
	}
	return ateapiauth.AuthenticationConfig{
		ActorIdentityJWTProvider: "kubernetes",
		JWTProviders: []ateapiauth.JWTProviderConfig{
			{
				Name:                     "kubernetes",
				Issuer:                   clusterIssuer,
				Audiences:                []string{"api.ate-system.svc"},
				CertificateAuthorityFile: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
				DiscoveryTokenFile:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
		},
	}
}

func mutateAuthenticationConfig(
	existingYAML string,
	providerName string,
	issuer string,
	audiences []string,
	hasCA bool,
	setActorIdentity bool,
	clusterIssuer string,
) (*ateapiauth.AuthenticationConfig, string, error) {
	var cfg ateapiauth.AuthenticationConfig
	if existingYAML != "" {
		if err := yaml.UnmarshalStrict([]byte(existingYAML), &cfg); err != nil {
			return nil, "", fmt.Errorf("while parsing existing authentication.yaml: %w", err)
		}
	} else {
		cfg = bootstrapAuthenticationConfig(clusterIssuer)
	}

	var caFilePath string
	if hasCA {
		caFilePath = fmt.Sprintf("/etc/ateapi/authentication/%s-ca.crt", providerName)
	}

	newProvider := ateapiauth.JWTProviderConfig{
		Name:                     providerName,
		Issuer:                   issuer,
		Audiences:                audiences,
		CertificateAuthorityFile: caFilePath,
	}

	found := false
	for i, p := range cfg.JWTProviders {
		if p.Name == providerName {
			cfg.JWTProviders[i] = newProvider
			found = true
			break
		}
	}
	if !found {
		cfg.JWTProviders = append(cfg.JWTProviders, newProvider)
	}

	if setActorIdentity {
		cfg.ActorIdentityJWTProvider = providerName
	} else if cfg.ActorIdentityJWTProvider == "" && len(cfg.JWTProviders) > 0 {
		cfg.ActorIdentityJWTProvider = cfg.JWTProviders[0].Name
	}

	if err := ateapiauth.ValidateAuthenticationConfig(&cfg); err != nil {
		return nil, "", fmt.Errorf("invalid authentication config: %w", err)
	}

	outBytes, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, "", fmt.Errorf("while marshaling authentication config: %w", err)
	}

	return &cfg, string(outBytes), nil
}

func restartDeployment(ctx context.Context, kc kubernetes.Interface, namespace, name string) error {
	restartedAt := time.Now().UTC().Format(time.RFC3339)
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		restartedAt,
	)
	_, err := kc.AppsV1().Deployments(namespace).Patch(
		ctx,
		name,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("deployment %s/%s not found to restart", namespace, name)
		}
		return fmt.Errorf("while patching deployment %s/%s: %w", namespace, name, err)
	}
	return nil
}

func waitForDeploymentRollout(ctx context.Context, kc kubernetes.Interface, namespace, name string, timeout time.Duration) error {
	var lastMsg string
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(pollCtx context.Context) (bool, error) {
		d, err := kc.AppsV1().Deployments(namespace).Get(pollCtx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, fmt.Errorf("deployment %s/%s not found", namespace, name)
			}
			return false, err
		}
		if d.Generation > d.Status.ObservedGeneration {
			lastMsg = "waiting for controller to observe update"
			return false, nil
		}
		for _, cond := range d.Status.Conditions {
			if cond.Type == appsv1.DeploymentProgressing && cond.Reason == "ProgressDeadlineExceeded" {
				return false, fmt.Errorf("deployment %s/%s exceeded progress deadline", namespace, name)
			}
		}
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if d.Status.UpdatedReplicas < desired {
			lastMsg = fmt.Sprintf("%d/%d replicas updated", d.Status.UpdatedReplicas, desired)
			return false, nil
		}
		if d.Status.Replicas > d.Status.UpdatedReplicas {
			lastMsg = fmt.Sprintf("%d old replicas pending termination", d.Status.Replicas-d.Status.UpdatedReplicas)
			return false, nil
		}
		if d.Status.AvailableReplicas < d.Status.UpdatedReplicas {
			lastMsg = fmt.Sprintf("%d/%d replicas available", d.Status.AvailableReplicas, d.Status.UpdatedReplicas)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("while waiting for deployment %s/%s rollout: %w (last status: %s)", namespace, name, err, lastMsg)
	}
	return nil
}

func init() {
	adminCmd.AddCommand(addJwtProviderCmd)

	addJwtProviderCmd.Flags().StringVar(&jwtProviderIssuer, "issuer", "", "Trusted OIDC issuer HTTPS URL (required)")
	addJwtProviderCmd.Flags().StringSliceVarP(&jwtProviderAudiences, "audience", "a", nil, "Expected audience(s) in JWT tokens (required, repeatable or comma-separated)")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderCASecret, "ca-secret", "", "Name of a Kubernetes Secret containing the CA certificate")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderCASecretNamespace, "ca-secret-namespace", "", "Namespace of --ca-secret (defaults to 'default')")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderCASecretKey, "ca-secret-key", "ca.crt", "Key in --ca-secret containing the PEM CA certificate (falls back to tls.crt)")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderCAFile, "ca-file", "", "Local file path to a PEM CA certificate (alternative to --ca-secret)")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderSystemNamespace, "system-namespace", defaultSystemNamespace, "Substrate system namespace")
	addJwtProviderCmd.Flags().StringVar(&jwtProviderConfigMap, "configmap", defaultConfigMapName, "Substrate authentication ConfigMap name")
	addJwtProviderCmd.Flags().BoolVar(&jwtProviderSetActorIdentity, "set-actor-identity", false, "Set this provider as the actor identity JWT provider")
	addJwtProviderCmd.Flags().BoolVar(&jwtProviderRestart, "restart", true, "Trigger a rollout restart of ate-api-server after updating config")
	addJwtProviderCmd.Flags().BoolVar(&jwtProviderWait, "wait", true, "Wait for ate-api-server rollout to finish")
	addJwtProviderCmd.Flags().DurationVar(&jwtProviderTimeout, "timeout", 120*time.Second, "Maximum duration to wait for rollout")
	addJwtProviderCmd.Flags().BoolVar(&jwtProviderDryRun, "dry-run", false, "Print resulting authentication.yaml without applying to cluster")

	addJwtProviderCmd.MarkFlagRequired("issuer")
	addJwtProviderCmd.MarkFlagRequired("audience")
}
