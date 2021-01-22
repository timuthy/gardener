// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package botanist

import (
	"fmt"
	"net"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/operation/botanist/controlplane/clusterautoscaler"
	"github.com/gardener/gardener/pkg/operation/botanist/controlplane/etcd"
	"github.com/gardener/gardener/pkg/operation/botanist/controlplane/kubecontrollermanager"
	"github.com/gardener/gardener/pkg/operation/botanist/controlplane/kubescheduler"
	"github.com/gardener/gardener/pkg/operation/botanist/systemcomponents/metricsserver"
	"github.com/gardener/gardener/pkg/operation/common"
	"github.com/gardener/gardener/pkg/secretsmanager/apis/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/secrets"

	"k8s.io/apiserver/pkg/authentication/user"
)

var basicAuthSecretAPIServer = secrets.NewBasicAuthSecretConfigManager(
	v1alpha1.BasicAuthSecretConfig{
		Name:           common.BasicAuthSecretName,
		Format:         v1alpha1.BasicAuthFormatCSV,
		Username:       "admin",
		PasswordLength: 32,
	},
)

var wantedCertificateAuthorities = map[string]*v1alpha1.CertificateSecretConfig{
	v1beta1constants.SecretNameCACluster: {
		Name:       v1beta1constants.SecretNameCACluster,
		CommonName: "kubernetes",
		CertType:   v1alpha1.CACert,
	},
	v1beta1constants.SecretNameCAETCD: {
		Name:       etcd.SecretNameCA,
		CommonName: "etcd",
		CertType:   v1alpha1.CACert,
	},
	v1beta1constants.SecretNameCAFrontProxy: {
		Name:       v1beta1constants.SecretNameCAFrontProxy,
		CommonName: "front-proxy",
		CertType:   v1alpha1.CACert,
	},
	v1beta1constants.SecretNameCAKubelet: {
		Name:       v1beta1constants.SecretNameCAKubelet,
		CommonName: "kubelet",
		CertType:   v1alpha1.CACert,
	},
	v1beta1constants.SecretNameCAMetricsServer: {
		Name:       metricsserver.SecretNameCA,
		CommonName: "metrics-server",
		CertType:   v1alpha1.CACert,
	},
}

var vpaSecrets = map[string]string{
	common.VpaAdmissionControllerImageName: common.VpaAdmissionControllerName,
	common.VpaRecommenderImageName:         common.VpaRecommenderName,
	common.VpaUpdaterImageName:             common.VpaUpdaterName,
}

func (b *Botanist) generateStaticTokenConfig() *secrets.StaticTokenSecretConfig {
	staticTokenConfig := &secrets.StaticTokenSecretConfig{
		Name: common.StaticTokenSecretName,
		Tokens: map[string]secrets.TokenConfig{
			common.KubecfgUsername: {
				Username: common.KubecfgUsername,
				UserID:   common.KubecfgUsername,
				Groups:   []string{user.SystemPrivilegedGroup},
			},
			common.KubeAPIServerHealthCheck: {
				Username: common.KubeAPIServerHealthCheck,
				UserID:   common.KubeAPIServerHealthCheck,
			},
		},
	}

	if b.Shoot.KonnectivityTunnelEnabled {
		staticTokenConfig.Tokens[common.KonnectivityServerUserName] = secrets.TokenConfig{
			Username: common.KonnectivityServerUserName,
			UserID:   common.KonnectivityServerUserName,
		}
	}

	if b.Shoot.WantsVerticalPodAutoscaler {
		for secretName, username := range vpaSecrets {
			staticTokenConfig.Tokens[secretName] = secrets.TokenConfig{
				Username: username,
				UserID:   secretName,
			}
		}
	}

	return staticTokenConfig
}

// generateWantedSecrets returns a list of Secret configuration objects satisfying the secret config interface,
// each containing their specific configuration for the creation of certificates (server/client), RSA key pairs, basic
// authentication credentials, etc.
func (b *Botanist) generateWantedSecretConfigs(basicAuthAPIServer *secrets.BasicAuth, staticToken *secrets.StaticToken, certificateAuthorities map[string]*secrets.Certificate) ([]secrets.ConfigInterface, error) {
	var (
		apiServerIPAddresses = []net.IP{
			net.ParseIP("127.0.0.1"),
			b.Shoot.Networks.APIServer,
		}
		apiServerCertDNSNames = append([]string{
			"kube-apiserver",
			fmt.Sprintf("kube-apiserver.%s", b.Shoot.SeedNamespace),
			fmt.Sprintf("kube-apiserver.%s.svc", b.Shoot.SeedNamespace),
			common.GetAPIServerDomain(b.Shoot.InternalClusterDomain),
		}, kubernetes.DNSNamesForService("kubernetes", "default")...)

		kubeControllerManagerCertDNSNames = kubernetes.DNSNamesForService(kubecontrollermanager.ServiceName, b.Shoot.SeedNamespace)
		kubeSchedulerCertDNSNames         = kubernetes.DNSNamesForService(kubescheduler.ServiceName, b.Shoot.SeedNamespace)

		konnectivityServerDNSNames = append([]string{
			common.GetAPIServerDomain(b.Shoot.InternalClusterDomain),
		}, kubernetes.DNSNamesForService(common.KonnectivityServerCertName, b.Shoot.SeedNamespace)...)

		etcdCertDNSNames = append(
			b.Shoot.Components.ControlPlane.EtcdMain.ServiceDNSNames(),
			b.Shoot.Components.ControlPlane.EtcdEvents.ServiceDNSNames()...,
		)

		endUserCrtValidity = common.EndUserCrtValidity
	)

	if !b.Seed.Info.Spec.Settings.ShootDNS.Enabled {
		if addr := net.ParseIP(b.APIServerAddress); addr != nil {
			apiServerIPAddresses = append(apiServerIPAddresses, addr)
		} else {
			apiServerCertDNSNames = append(apiServerCertDNSNames, b.APIServerAddress)
		}
	}

	if b.Shoot.ExternalClusterDomain != nil {
		apiServerCertDNSNames = append(apiServerCertDNSNames, *(b.Shoot.Info.Spec.DNS.Domain), common.GetAPIServerDomain(*b.Shoot.ExternalClusterDomain))
	}

	secretList := []secrets.ConfigInterface{
		// Secret definition for kube-apiserver
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "kube-apiserver",

					CommonName:   user.APIServerUser,
					Organization: nil,
					DNSNames:     apiServerCertDNSNames,
					IPAddresses:  apiServerIPAddresses,

					CertType: v1alpha1.ServerCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-apiserver to kubelets communication
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "kube-apiserver-kubelet",

					CommonName:   "system:kube-apiserver:kubelet",
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCAKubelet],
			nil,
			nil,
		),

		// Secret definition for kube-aggregator
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "kube-aggregator",

					CommonName:   "system:kube-aggregator",
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCAFrontProxy],
			nil,
			nil,
		),

		// Secret definition for kube-controller-manager
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: kubecontrollermanager.SecretName,

					CommonName:   user.KubeControllerManager,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-controller-manager server
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: kubecontrollermanager.SecretNameServer,

					CommonName:   v1beta1constants.DeploymentNameKubeControllerManager,
					Organization: nil,
					DNSNames:     kubeControllerManagerCertDNSNames,
					IPAddresses:  nil,

					CertType: v1alpha1.ServerCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-scheduler
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: kubescheduler.SecretName,

					CommonName:   user.KubeScheduler,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-scheduler server
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: kubescheduler.SecretNameServer,

					CommonName:   v1beta1constants.DeploymentNameKubeScheduler,
					Organization: nil,
					DNSNames:     kubeSchedulerCertDNSNames,
					IPAddresses:  nil,

					CertType: v1alpha1.ServerCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for cluster-autoscaler
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: clusterautoscaler.SecretName,

					CommonName:   clusterautoscaler.UserName,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for gardener-resource-manager
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "gardener-resource-manager",

					CommonName:   "gardener.cloud:system:gardener-resource-manager",
					Organization: []string{user.SystemPrivilegedGroup},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-proxy
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "kube-proxy",

					CommonName:   user.KubeProxy,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for kube-state-metrics
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "kube-state-metrics",

					CommonName:   "gardener.cloud:monitoring:kube-state-metrics",
					Organization: []string{"gardener.cloud:monitoring"},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for prometheus
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "prometheus",

					CommonName:   "gardener.cloud:monitoring:prometheus",
					Organization: []string{"gardener.cloud:monitoring"},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for prometheus to kubelets communication
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "prometheus-kubelet",

					CommonName:   "gardener.cloud:monitoring:prometheus",
					Organization: []string{"gardener.cloud:monitoring"},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCAKubelet],
			nil,
			nil,
		),

		// Secret definition for gardener
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: v1beta1constants.SecretNameGardener,

					CommonName:   gardencorev1beta1.GardenerName,
					Organization: []string{user.SystemPrivilegedGroup},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: v1beta1constants.SecretNameGardenerInternal,

					CommonName:   gardencorev1beta1.GardenerName,
					Organization: []string{user.SystemPrivilegedGroup},
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(false),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for cloud-config-downloader
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: "cloud-config-downloader",

					CommonName:   "cloud-config-downloader",
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},
				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),

		// Secret definition for monitoring
		secrets.NewBasicAuthSecretConfigManager(
			v1alpha1.BasicAuthSecretConfig{
				Name:   "monitoring-ingress-credentials",
				Format: v1alpha1.BasicAuthFormatNormal,

				Username:       "admin",
				PasswordLength: 32,
			},
		),

		// Secret definition for monitoring for shoot owners
		secrets.NewBasicAuthSecretConfigManager(
			v1alpha1.BasicAuthSecretConfig{
				Name:   "monitoring-ingress-credentials-users",
				Format: v1alpha1.BasicAuthFormatNormal,

				Username:       "admin",
				PasswordLength: 32,
			},
		),

		// Secret definition for ssh-keypair
		&secrets.RSASecretConfig{
			Name:       v1beta1constants.SecretNameSSHKeyPair,
			Bits:       4096,
			UsedForSSH: true,
		},

		// Secret definition for service-account-key
		&secrets.RSASecretConfig{
			Name:       v1beta1constants.SecretNameServiceAccountKey,
			Bits:       4096,
			UsedForSSH: false,
		},

		// Secret definition for etcd server
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: etcd.SecretNameServer,

				CommonName:   "etcd-server",
				Organization: nil,
				DNSNames:     etcdCertDNSNames,
				IPAddresses:  nil,

				CertType: v1alpha1.ServerClientCert,
			},
			certificateAuthorities[v1beta1constants.SecretNameCAETCD],
		),

		// Secret definition for etcd server
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: etcd.SecretNameClient,

				CommonName:   "etcd-client",
				Organization: nil,
				DNSNames:     nil,
				IPAddresses:  nil,

				CertType: v1alpha1.ClientCert,
			},
			certificateAuthorities[v1beta1constants.SecretNameCAETCD],
		),

		// Secret definition for metrics-server
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: metricsserver.SecretNameServer,

				CommonName:   "metrics-server",
				Organization: nil,
				DNSNames:     b.Shoot.Components.SystemComponents.MetricsServer.ServiceDNSNames(),
				IPAddresses:  nil,

				CertType: v1alpha1.ServerClientCert,
			},
			certificateAuthorities[v1beta1constants.SecretNameCAMetricsServer],
		),

		// Secret definition for alertmanager (ingress)
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: common.AlertManagerTLS,

				CommonName:   "alertmanager",
				Organization: []string{"gardener.cloud:monitoring:ingress"},
				DNSNames:     b.ComputeAlertManagerHosts(),
				IPAddresses:  nil,

				CertType: v1alpha1.ServerCert,

				Validity: &endUserCrtValidity,
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
		),

		// Secret definition for grafana (ingress)
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: common.GrafanaTLS,

				CommonName:   "grafana",
				Organization: []string{"gardener.cloud:monitoring:ingress"},
				DNSNames:     b.ComputeGrafanaHosts(),
				IPAddresses:  nil,

				CertType: v1alpha1.ServerCert,

				Validity: &endUserCrtValidity,
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
		),

		// Secret definition for prometheus (ingress)
		secrets.NewCertificateSecretConfigManager(
			v1alpha1.CertificateSecretConfig{
				Name: common.PrometheusTLS,

				CommonName:   "prometheus",
				Organization: []string{"gardener.cloud:monitoring:ingress"},
				DNSNames:     b.ComputePrometheusHosts(),
				IPAddresses:  nil,

				CertType: v1alpha1.ServerCert,

				Validity: &endUserCrtValidity,
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
		),
	}

	// Secret definition for kubecfg
	var kubecfgToken *secrets.Token
	if staticToken != nil {
		var err error
		kubecfgToken, err = staticToken.GetTokenForUsername(common.KubecfgUsername)
		if err != nil {
			return nil, err
		}
	}

	secretList = append(secretList,
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: common.KubecfgSecretName,
				},

				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, false),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			basicAuthAPIServer,
			kubecfgToken,
		))

	// Secret definitions for dependency-watchdog-internal and external probes
	secretList = append(secretList,
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: common.DependencyWatchdogInternalProbeSecretName,

					CommonName:   common.DependencyWatchdogUserName,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},

				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeInClusterAPIServerAddress(false),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),
		secrets.NewControlPlaneSecretConfigManager(
			v1alpha1.ControlPlaneSecretConfig{
				CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
					Name: common.DependencyWatchdogExternalProbeSecretName,

					CommonName:   common.DependencyWatchdogUserName,
					Organization: nil,
					DNSNames:     nil,
					IPAddresses:  nil,

					CertType: v1alpha1.ClientCert,
				},

				KubeConfigRequest: &v1alpha1.KubeConfigRequest{
					ClusterName:  b.Shoot.SeedNamespace,
					APIServerURL: b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true),
				},
			},
			certificateAuthorities[v1beta1constants.SecretNameCACluster],
			nil,
			nil,
		),
	)

	if b.Shoot.KonnectivityTunnelEnabled {
		var konnectivityServerToken *secrets.Token
		if staticToken != nil {
			var err error
			konnectivityServerToken, err = staticToken.GetTokenForUsername(common.KonnectivityServerUserName)
			if err != nil {
				return nil, err
			}
		}
		// Secret definitions for konnectivity-server and konnectivity Agent
		secretList = append(secretList,
			secrets.NewControlPlaneSecretConfigManager(
				v1alpha1.ControlPlaneSecretConfig{
					CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
						Name: common.KonnectivityServerKubeconfig,
					},

					KubeConfigRequest: &v1alpha1.KubeConfigRequest{
						ClusterName:  b.Shoot.SeedNamespace,
						APIServerURL: fmt.Sprintf("%s.%s", v1beta1constants.DeploymentNameKubeAPIServer, b.Shoot.SeedNamespace),
					},
				},
				certificateAuthorities[v1beta1constants.SecretNameCACluster],
				basicAuthAPIServer,
				konnectivityServerToken,
			),
			secrets.NewControlPlaneSecretConfigManager(
				v1alpha1.ControlPlaneSecretConfig{
					CertificateSecretConfig: v1alpha1.CertificateSecretConfig{
						Name:       common.KonnectivityServerCertName,
						CommonName: common.KonnectivityServerCertName,
						DNSNames:   konnectivityServerDNSNames,

						CertType: v1alpha1.ServerCert,
					},
				},
				certificateAuthorities[v1beta1constants.SecretNameCACluster],
				nil,
				nil,
			))
	} else {
		secretList = append(secretList,
			// Secret definition for vpn-shoot (OpenVPN server side)
			secrets.NewCertificateSecretConfigManager(
				v1alpha1.CertificateSecretConfig{
					Name:       "vpn-shoot",
					CommonName: "vpn-shoot",
					CertType:   v1alpha1.ServerCert,
				},
				certificateAuthorities[v1beta1constants.SecretNameCACluster],
			),
			secrets.NewCertificateSecretConfigManager(
				v1alpha1.CertificateSecretConfig{
					Name:       "vpn-seed",
					CommonName: "vpn-seed",
					CertType:   v1alpha1.ClientCert,
				},
				certificateAuthorities[v1beta1constants.SecretNameCACluster],
			),
			&secrets.VPNTLSAuthConfig{
				Name: "vpn-seed-tlsauth",
			},
		)
	}

	if b.Shoot.WantsVerticalPodAutoscaler {
		var (
			commonName = fmt.Sprintf("vpa-webhook.%s.svc", b.Shoot.SeedNamespace)
			dnsNames   = []string{
				"vpa-webhook",
				fmt.Sprintf("vpa-webhook.%s", b.Shoot.SeedNamespace),
				commonName,
			}
		)

		secretList = append(secretList,
			secrets.NewCertificateSecretConfigManager(
				v1alpha1.CertificateSecretConfig{
					Name:       common.VPASecretName,
					CommonName: commonName,
					DNSNames:   dnsNames,
					CertType:   v1alpha1.ServerCert,
				},
				certificateAuthorities[v1beta1constants.SecretNameCACluster],
			))
	}

	return secretList, nil
}
