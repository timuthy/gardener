// Copyright 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/utils/pointer"
)

// SetDefaults_ControllerManagerConfiguration sets defaults for the configuration of the Gardener controller manager.
func SetDefaults_ControllerManagerConfiguration(obj *ControllerManagerConfiguration) {
	if obj.LogLevel == "" {
		obj.LogLevel = LogLevelInfo
	}
	if obj.LogFormat == "" {
		obj.LogFormat = LogFormatJSON
	}

	if obj.LeaderElection == nil {
		obj.LeaderElection = &componentbaseconfigv1alpha1.LeaderElectionConfiguration{}
	}
}

// SetDefaults_ClientConnectionConfiguration sets defaults for the garden client connection.
func SetDefaults_ClientConnectionConfiguration(obj *componentbaseconfigv1alpha1.ClientConnectionConfiguration) {
	if obj.QPS == 0.0 {
		obj.QPS = 50.0
	}
	if obj.Burst == 0 {
		obj.Burst = 100
	}
}

// SetDefaults_LeaderElectionConfiguration sets defaults for the leader election of the Gardener controller manager.
func SetDefaults_LeaderElectionConfiguration(obj *componentbaseconfigv1alpha1.LeaderElectionConfiguration) {
	if obj.ResourceLock == "" {
		// Don't use a constant from the client-go resourcelock package here (resourcelock is not an API package, pulls
		// in some other dependencies and is thereby not suitable to be used in this API package).
		obj.ResourceLock = "leases"
	}

	componentbaseconfigv1alpha1.RecommendedDefaultLeaderElectionConfiguration(obj)

	if obj.ResourceNamespace == "" {
		obj.ResourceNamespace = ControllerManagerDefaultLockObjectNamespace
	}
	if obj.ResourceName == "" {
		obj.ResourceName = ControllerManagerDefaultLockObjectName
	}
}

// SetDefaults_ShootRetryControllerConfiguration sets defaults for the ShootRetryControllerConfiguration.
func SetDefaults_ShootRetryControllerConfiguration(obj *ShootRetryControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.RetryPeriod == nil {
		obj.RetryPeriod = &metav1.Duration{Duration: 10 * time.Minute}
	}
	if obj.RetryJitterPeriod == nil {
		obj.RetryJitterPeriod = &metav1.Duration{Duration: 5 * time.Minute}
	}
}

// SetDefaults_SeedControllerConfiguration sets defaults for the given SeedControllerConfiguration.
func SetDefaults_SeedControllerConfiguration(obj *SeedControllerConfiguration) {
	if obj.SyncPeriod == nil {
		obj.SyncPeriod = &metav1.Duration{Duration: 10 * time.Second}
	}
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.MonitorPeriod == nil {
		obj.MonitorPeriod = &metav1.Duration{Duration: 40 * time.Second}
	}
	if obj.ShootMonitorPeriod == nil {
		obj.ShootMonitorPeriod = &metav1.Duration{Duration: 5 * obj.MonitorPeriod.Duration}
	}
}

// SetDefaults_ProjectControllerConfiguration sets defaults for the ProjectControllerConfiguration.
func SetDefaults_ProjectControllerConfiguration(obj *ProjectControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.MinimumLifetimeDays == nil {
		obj.MinimumLifetimeDays = pointer.Int(30)
	}
	if obj.StaleGracePeriodDays == nil {
		obj.StaleGracePeriodDays = pointer.Int(14)
	}
	if obj.StaleExpirationTimeDays == nil {
		obj.StaleExpirationTimeDays = pointer.Int(90)
	}
	if obj.StaleSyncPeriod == nil {
		obj.StaleSyncPeriod = &metav1.Duration{
			Duration: 12 * time.Hour,
		}
	}
	for i, quota := range obj.Quotas {
		if quota.ProjectSelector == nil {
			obj.Quotas[i].ProjectSelector = &metav1.LabelSelector{}
		}
	}
}

// SetDefaults_ServerConfiguration sets defaults for the ServerConfiguration.
func SetDefaults_ServerConfiguration(obj *ServerConfiguration) {
	if obj.HealthProbes == nil {
		obj.HealthProbes = &Server{}
	}
	if obj.HealthProbes.Port == 0 {
		obj.HealthProbes.Port = 2718
	}

	if obj.Metrics == nil {
		obj.Metrics = &Server{}
	}
	if obj.Metrics.Port == 0 {
		obj.Metrics.Port = 2719
	}
}

// SetDefaults_BastionControllerConfiguration sets defaults for the BastionControllerConfiguration.
func SetDefaults_BastionControllerConfiguration(obj *BastionControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.MaxLifetime == nil {
		obj.MaxLifetime = &metav1.Duration{Duration: 24 * time.Hour}
	}
}

// SetDefaults_CertificateSigningRequestControllerConfiguration sets defaults for the CertificateSigningRequestControllerConfiguration.
func SetDefaults_CertificateSigningRequestControllerConfiguration(obj *CertificateSigningRequestControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_CloudProfileControllerConfiguration sets defaults for the CloudProfileControllerConfiguration.
func SetDefaults_CloudProfileControllerConfiguration(obj *CloudProfileControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_ControllerDeploymentControllerConfiguration sets defaults for the ControllerDeploymentControllerConfiguration.
func SetDefaults_ControllerDeploymentControllerConfiguration(obj *ControllerDeploymentControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_ControllerRegistrationControllerConfiguration sets defaults for the ControllerRegistrationControllerConfiguration.
func SetDefaults_ControllerRegistrationControllerConfiguration(obj *ControllerRegistrationControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_ExposureClassControllerConfiguration sets defaults for the ExposureClassControllerConfiguration.
func SetDefaults_ExposureClassControllerConfiguration(obj *ExposureClassControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_QuotaControllerConfiguration sets defaults for the QuotaControllerConfiguration.
func SetDefaults_QuotaControllerConfiguration(obj *QuotaControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_SecretBindingControllerConfiguration sets defaults for the SecretBindingControllerConfiguration.
func SetDefaults_SecretBindingControllerConfiguration(obj *SecretBindingControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_SeedExtensionsCheckControllerConfiguration sets defaults for the SeedExtensionsCheckControllerConfiguration.
func SetDefaults_SeedExtensionsCheckControllerConfiguration(obj *SeedExtensionsCheckControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.SyncPeriod == nil {
		obj.SyncPeriod = &metav1.Duration{Duration: 30 * time.Second}
	}
}

// SetDefaults_SeedBackupBucketsCheckControllerConfiguration sets defaults for the SeedBackupBucketsCheckControllerConfiguration.
func SetDefaults_SeedBackupBucketsCheckControllerConfiguration(obj *SeedBackupBucketsCheckControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.SyncPeriod == nil {
		obj.SyncPeriod = &metav1.Duration{Duration: 30 * time.Second}
	}
}

// SetDefaults_ShootHibernationControllerConfiguration sets defaults for the ShootHibernationControllerConfiguration.
func SetDefaults_ShootHibernationControllerConfiguration(obj *ShootHibernationControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.TriggerDeadlineDuration == nil {
		obj.TriggerDeadlineDuration = &metav1.Duration{Duration: 2 * time.Hour}
	}
}

// SetDefaults_ShootMaintenanceControllerConfiguration sets defaults for the ShootMaintenanceControllerConfiguration.
func SetDefaults_ShootMaintenanceControllerConfiguration(obj *ShootMaintenanceControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.EnableShootControlPlaneRestarter == nil {
		obj.EnableShootControlPlaneRestarter = pointer.Bool(true)
	}
}

// SetDefaults_ShootQuotaControllerConfiguration sets defaults for the ShootQuotaControllerConfiguration.
func SetDefaults_ShootQuotaControllerConfiguration(obj *ShootQuotaControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.SyncPeriod == nil {
		obj.SyncPeriod = &metav1.Duration{
			Duration: 60 * time.Minute,
		}
	}
}

// SetDefaults_ShootReferenceControllerConfiguration sets defaults for the ShootReferenceControllerConfiguration.
func SetDefaults_ShootReferenceControllerConfiguration(obj *ShootReferenceControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_ShootConditionsControllerConfiguration sets defaults for the ShootConditionsControllerConfiguration.
func SetDefaults_ShootConditionsControllerConfiguration(obj *ShootConditionsControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_EventControllerConfiguration sets defaults for the EventControllerConfiguration.
func SetDefaults_EventControllerConfiguration(obj *EventControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.TTLNonShootEvents == nil {
		obj.TTLNonShootEvents = &metav1.Duration{Duration: 1 * time.Hour}
	}
}

// SetDefaults_ShootStatusLabelControllerConfiguration sets defaults for the ShootStatusLabelControllerConfiguration.
func SetDefaults_ShootStatusLabelControllerConfiguration(obj *ShootStatusLabelControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
}

// SetDefaults_ManagedSeedSetControllerConfiguration sets defaults for the ManagedSeedSetControllerConfiguration.
func SetDefaults_ManagedSeedSetControllerConfiguration(obj *ManagedSeedSetControllerConfiguration) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = pointer.Int(DefaultControllerConcurrentSyncs)
	}
	if obj.MaxShootRetries == nil {
		obj.MaxShootRetries = pointer.Int(3)
	}
}

// SetDefaults_ControllerManagerControllerConfiguration sets defaults for the ControllerManagerControllerConfiguration.
func SetDefaults_ControllerManagerControllerConfiguration(obj *ControllerManagerControllerConfiguration) {
	if obj.Bastion == nil {
		obj.Bastion = &BastionControllerConfiguration{}
	}
	if obj.CertificateSigningRequest == nil {
		obj.CertificateSigningRequest = &CertificateSigningRequestControllerConfiguration{}
	}
	if obj.CloudProfile == nil {
		obj.CloudProfile = &CloudProfileControllerConfiguration{}
	}
	if obj.ControllerDeployment == nil {
		obj.ControllerDeployment = &ControllerDeploymentControllerConfiguration{}
	}
	if obj.ControllerRegistration == nil {
		obj.ControllerRegistration = &ControllerRegistrationControllerConfiguration{}
	}
	if obj.ExposureClass == nil {
		obj.ExposureClass = &ExposureClassControllerConfiguration{}
	}
	if obj.Project == nil {
		obj.Project = &ProjectControllerConfiguration{}
	}
	if obj.Quota == nil {
		obj.Quota = &QuotaControllerConfiguration{}
	}
	if obj.SecretBinding == nil {
		obj.SecretBinding = &SecretBindingControllerConfiguration{}
	}
	if obj.Seed == nil {
		obj.Seed = &SeedControllerConfiguration{}
	}
	if obj.SeedExtensionsCheck == nil {
		obj.SeedExtensionsCheck = &SeedExtensionsCheckControllerConfiguration{}
	}
	if obj.SeedBackupBucketsCheck == nil {
		obj.SeedBackupBucketsCheck = &SeedBackupBucketsCheckControllerConfiguration{}
	}
	if obj.ShootQuota == nil {
		obj.ShootQuota = &ShootQuotaControllerConfiguration{}
	}
	if obj.ShootReference == nil {
		obj.ShootReference = &ShootReferenceControllerConfiguration{}
	}
	if obj.ShootRetry == nil {
		obj.ShootRetry = &ShootRetryControllerConfiguration{}
	}
	if obj.ShootConditions == nil {
		obj.ShootConditions = &ShootConditionsControllerConfiguration{}
	}
	if obj.ShootStatusLabel == nil {
		obj.ShootStatusLabel = &ShootStatusLabelControllerConfiguration{}
	}

	if obj.ManagedSeedSet == nil {
		obj.ManagedSeedSet = &ManagedSeedSetControllerConfiguration{
			SyncPeriod: metav1.Duration{
				Duration: 30 * time.Minute,
			},
		}
	}
}
