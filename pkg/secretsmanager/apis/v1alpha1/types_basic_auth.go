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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FormatType defines the desired output format.
type FormatType string

const (
	// BasicAuthFormatNormal indicates that the data map should be rendered the normal way (dedicated keys for
	// username and password.
	BasicAuthFormatNormal FormatType = "normal"
	// BasicAuthFormatCSV indicates that the data map should be rendered in the CSV-format.
	BasicAuthFormatCSV FormatType = "csv"

	// DataKeyCSV is the key in a secret data holding the CSV format of a secret.
	DataKeyCSV = "basic_auth.csv"
	// DataKeyUserName is the key in a secret data holding the username.
	DataKeyUserName = "username"
	// DataKeyPassword is the key in a secret data holding the password.
	DataKeyPassword = "password"
)

// BasicAuthSecretConfig contains the specification for a to-be-generated basic authentication secret.
type BasicAuthSecretConfig struct {
	metav1.TypeMeta

	Name   string     `json:"name"`
	Format FormatType `json:"format"`

	Username       string `json:"username"`
	PasswordLength int    `json:"passwordLength"`
}
