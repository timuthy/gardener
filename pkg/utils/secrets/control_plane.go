// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import (
	"fmt"

	"github.com/gardener/gardener/pkg/secretsmanager/apis/v1alpha1"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/infodata"
)

const (
	// DataKeyKubeconfig is the key in a secret data holding the kubeconfig.
	DataKeyKubeconfig = "kubeconfig"
)

// ControlPlaneSecretDataKeyCertificatePEM returns the data key inside a Secret of type ControlPlane whose value
// contains the certificate PEM.
func ControlPlaneSecretDataKeyCertificatePEM(name string) string { return fmt.Sprintf("%s.crt", name) }

// ControlPlaneSecretDataKeyPrivateKey returns the data key inside a Secret of type ControlPlane whose value
// contains the private key PEM.
func ControlPlaneSecretDataKeyPrivateKey(name string) string { return fmt.Sprintf("%s.key", name) }

// ControlPlane contains the certificate, and optionally the basic auth. information as well as a Kubeconfig.
type ControlPlane struct {
	Name string

	Certificate *Certificate
	BasicAuth   *BasicAuth
	Token       *Token
	Kubeconfig  []byte
}

type controlPlaneSecretConfigManager struct {
	*certificateSecretConfigManager
	kubeConfigRequest *v1alpha1.KubeConfigRequest

	basicAuth *BasicAuth
	token     *Token
}

// NewControlPlaneSecretConfigManager creates a new control plane secret manager with the given config.
func NewControlPlaneSecretConfigManager(config v1alpha1.ControlPlaneSecretConfig, signingCA *Certificate, auth *BasicAuth, token *Token) ConfigInterface {
	return &controlPlaneSecretConfigManager{
		certificateSecretConfigManager: &certificateSecretConfigManager{CertificateSecretConfig: config.CertificateSecretConfig, signingCA: signingCA},
		kubeConfigRequest:              config.KubeConfigRequest,
		basicAuth:                      auth,
		token:                          token,
	}
}

// GetName returns the name of the secret.
func (s *controlPlaneSecretConfigManager) GetName() string {
	return s.certificateSecretConfigManager.Name
}

// Generate implements ConfigInterface.
func (s *controlPlaneSecretConfigManager) Generate() (DataInterface, error) {
	return s.GenerateControlPlane()
}

// GenerateInfoData implements ConfigInterface
func (s *controlPlaneSecretConfigManager) GenerateInfoData() (infodata.InfoData, error) {
	cert, err := s.certificateSecretConfigManager.GenerateCertificate()
	if err != nil {
		return nil, err
	}

	if len(cert.PrivateKeyPEM) == 0 && len(cert.CertificatePEM) == 0 {
		return infodata.EmptyInfoData, nil
	}

	return NewCertificateInfoData(cert.PrivateKeyPEM, cert.CertificatePEM), nil
}

// GenerateFromInfoData implements ConfigInterface
func (s *controlPlaneSecretConfigManager) GenerateFromInfoData(infoData infodata.InfoData) (DataInterface, error) {
	data, ok := infoData.(*CertificateInfoData)
	if !ok {
		return nil, fmt.Errorf("could not convert InfoData entry %s to CertificateInfoData", s.Name)
	}

	certificate := &Certificate{
		Name: s.Name,
		CA:   s.signingCA,

		PrivateKeyPEM:  data.PrivateKey,
		CertificatePEM: data.Certificate,
	}

	controlPlane := &ControlPlane{
		Name: s.Name,

		Certificate: certificate,
		BasicAuth:   s.basicAuth,
		Token:       s.token,
	}

	if s.kubeConfigRequest != nil {
		kubeconfig, err := generateKubeconfig(s, certificate)
		if err != nil {
			return nil, err
		}
		controlPlane.Kubeconfig = kubeconfig
	}

	return controlPlane, nil
}

// LoadFromSecretData implements infodata.Loader
func (s *controlPlaneSecretConfigManager) LoadFromSecretData(secretData map[string][]byte) (infodata.InfoData, error) {
	privateKeyPEM := secretData[ControlPlaneSecretDataKeyPrivateKey(s.Name)]
	certificatePEM := secretData[ControlPlaneSecretDataKeyCertificatePEM(s.Name)]

	if len(privateKeyPEM) == 0 && len(certificatePEM) == 0 {
		return infodata.EmptyInfoData, nil
	}

	return NewCertificateInfoData(privateKeyPEM, certificatePEM), nil
}

// GenerateControlPlane computes a secret for a control plane component of the clusters managed by Gardener.
// It may include a Kubeconfig.
func (s *controlPlaneSecretConfigManager) GenerateControlPlane() (*ControlPlane, error) {
	certificate, err := s.GenerateCertificate()
	if err != nil {
		return nil, err
	}

	controlPlane := &ControlPlane{
		Name: s.Name,

		Certificate: certificate,
		BasicAuth:   s.basicAuth,
		Token:       s.token,
	}

	if s.kubeConfigRequest != nil {
		kubeconfig, err := generateKubeconfig(s, certificate)
		if err != nil {
			return nil, err
		}
		controlPlane.Kubeconfig = kubeconfig
	}

	return controlPlane, nil
}

// SecretData computes the data map which can be used in a Kubernetes secret.
func (c *ControlPlane) SecretData() map[string][]byte {
	data := map[string][]byte{
		v1alpha1.DataKeyCertificateCA: c.Certificate.CA.CertificatePEM,
	}

	if c.Certificate.CertificatePEM != nil && c.Certificate.PrivateKeyPEM != nil {
		data[ControlPlaneSecretDataKeyPrivateKey(c.Name)] = c.Certificate.PrivateKeyPEM
		data[ControlPlaneSecretDataKeyCertificatePEM(c.Name)] = c.Certificate.CertificatePEM
	}

	if c.BasicAuth != nil {
		data[v1alpha1.DataKeyUserName] = []byte(c.BasicAuth.Username)
		data[v1alpha1.DataKeyPassword] = []byte(c.BasicAuth.Password)
	}

	if c.Token != nil {
		data[DataKeyToken] = []byte(c.Token.Token)
	}

	if c.Kubeconfig != nil {
		data[DataKeyKubeconfig] = c.Kubeconfig
	}

	return data
}

// generateKubeconfig generates a Kubernetes Kubeconfig for communicating with the kube-apiserver by using
// a client certificate. If <basicAuthUser> and <basicAuthPass> are non-empty string, a second user object
// containing the Basic Authentication credentials is added to the Kubeconfig.
func generateKubeconfig(secret *controlPlaneSecretConfigManager, certificate *Certificate) ([]byte, error) {
	values := map[string]interface{}{
		"APIServerURL":  secret.kubeConfigRequest.APIServerURL,
		"CACertificate": utils.EncodeBase64(certificate.CA.CertificatePEM),
		"ClusterName":   secret.kubeConfigRequest.ClusterName,
	}

	if certificate.CertificatePEM != nil && certificate.PrivateKeyPEM != nil {
		values["ClientCertificate"] = utils.EncodeBase64(certificate.CertificatePEM)
		values["ClientKey"] = utils.EncodeBase64(certificate.PrivateKeyPEM)
	}

	if secret.basicAuth != nil {
		values["BasicAuthUsername"] = secret.basicAuth.Username
		values["BasicAuthPassword"] = secret.basicAuth.Password
	}

	if secret.token != nil {
		values["Token"] = secret.token.Token
	}

	return utils.RenderLocalTemplate(kubeconfigTemplate, values)
}

const kubeconfigTemplate = `---
apiVersion: v1
kind: Config
current-context: {{ .ClusterName }}
clusters:
- name: {{ .ClusterName }}
  cluster:
    certificate-authority-data: {{ .CACertificate }}
    server: https://{{ .APIServerURL }}
contexts:
- name: {{ .ClusterName }}
  context:
    cluster: {{ .ClusterName }}
{{- if and .ClientCertificate .ClientKey }}
    user: {{ .ClusterName }}
{{- else if .Token }}
    user: {{ .ClusterName }}-token
{{- else if and .BasicAuthUsername .BasicAuthPassword }}
    user: {{ .ClusterName }}-basic-auth
{{- end }}
users:
{{- if and .ClientCertificate .ClientKey }}
- name: {{ .ClusterName }}
  user:
    client-certificate-data: {{ .ClientCertificate }}
    client-key-data: {{ .ClientKey }}
{{- end }}
{{- if .Token }}
- name: {{ .ClusterName }}-token
  user:
    token: {{ .Token }}
{{- end }}
{{- if and .BasicAuthUsername .BasicAuthPassword }}
- name: {{ .ClusterName }}-basic-auth
  user:
    username: {{ .BasicAuthUsername }}
    password: {{ .BasicAuthPassword }}
{{- end  }}`
