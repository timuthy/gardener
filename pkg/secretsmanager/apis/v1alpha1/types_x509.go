// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package v1alpha1

import (
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertType defines a certificate type.
type CertType string

const (
	// CACert indicates that the certificate should be a certificate authority.
	CACert CertType = "ca"
	// ServerCert indicates that the certificate should have the ExtKeyUsageServerAuth usage.
	ServerCert CertType = "server"
	// ClientCert indicates that the certificate should have the ExtKeyUsageClientAuth usage.
	ClientCert CertType = "client"
	// ServerClientCert indicates that the certificate should have both the ExtKeyUsageServerAuth and ExtKeyUsageClientAuth usage.
	ServerClientCert CertType = "both"

	// DataKeyCertificate is the key in a secret data holding the certificate.
	DataKeyCertificate = "tls.crt"
	// DataKeyPrivateKey is the key in a secret data holding the private key.
	DataKeyPrivateKey = "tls.key"
	// DataKeyCertificateCA is the key in a secret data holding the CA certificate.
	DataKeyCertificateCA = "ca.crt"
	// DataKeyPrivateKeyCA is the key in a secret data holding the CA private key.
	DataKeyPrivateKeyCA = "ca.key"
)

const (
	// PKCS1 certificate format
	PKCS1 = iota
	// PKCS8 certificate format
	PKCS8
)

// CertificateSecretConfig contains the specification a to-be-generated CA, server, or client certificate.
// It always contains a 2048-bit RSA private key.
type CertificateSecretConfig struct {
	metav1.TypeMeta

	Name string

	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP

	CertType CertType
	PKCS     int

	Validity *time.Duration
}
