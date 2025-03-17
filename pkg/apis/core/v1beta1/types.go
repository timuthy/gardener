// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1beta1

import (
	"encoding/json"
)

const (
	// GardenerSeedLeaseNamespace is the namespace in which Gardenlet will report Seeds'
	// status using Lease resources for each Seed
	GardenerSeedLeaseNamespace = "gardener-system-seed-lease"
	// GardenerShootIssuerNamespace is the namespace in which Gardenlet
	// will sync service account issuer discovery documents
	// of Shoot clusters which require managed issuer
	GardenerShootIssuerNamespace = "gardener-system-shoot-issuer"
	// GardenerSystemPublicNamespace is the namespace which will contain a resources
	// describing gardener installation itself. The resources in this namespace
	// may be visible to all authenticated users.
	GardenerSystemPublicNamespace = "gardener-system-public"
)

// IPFamily is a type for specifying an IP protocol version to use in Gardener clusters.
type IPFamily string

const (
	// IPFamilyIPv4 is the IPv4 IP family.
	IPFamilyIPv4 IPFamily = "IPv4"
	// IPFamilyIPv6 is the IPv6 IP family.
	IPFamilyIPv6 IPFamily = "IPv6"
)

// IsIPv4SingleStack determines whether the given list of IP families specifies IPv4 single-stack networking.
func IsIPv4SingleStack(ipFamilies []IPFamily) bool {
	return len(ipFamilies) == 0 || (len(ipFamilies) == 1 && ipFamilies[0] == IPFamilyIPv4)
}

// IsIPv6SingleStack determines whether the given list of IP families specifies IPv6 single-stack networking.
func IsIPv6SingleStack(ipFamilies []IPFamily) bool {
	return len(ipFamilies) == 1 && ipFamilies[0] == IPFamilyIPv6
}

// AccessRestriction describes an access restriction for a Kubernetes cluster (e.g., EU access-only).
type AccessRestriction struct {
	// Name is the name of the restriction.
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
}

// AccessRestrictionWithOptions describes an access restriction for a Kubernetes cluster (e.g., EU access-only) and
// allows to specify additional options.
type AccessRestrictionWithOptions struct {
	AccessRestriction `json:",inline" protobuf:"bytes,1,opt,name=accessRestriction"`
	// Options is a map of additional options for the access restriction.
	// +optional
	Options map[string]string `json:"options,omitempty" protobuf:"bytes,2,rep,name=options"`
}

// CapabilityValues contains capability values.
// This is a workaround as the Protobuf generator can't handle a map with slice values.
type CapabilityValues struct {
	Values []string `protobuf:"bytes,1,rep,name=values"`
}

// Capabilities of a machine type or machine image.
type Capabilities map[string]CapabilityValues

// CapabilitiesSet is a wrapper for Capabilities.
// This is a workaround as the Protobuf generator can't handle a slice of maps.
type CapabilitiesSet struct {
	Capabilities `protobuf:"bytes,1,rep,name=capabilities,casttype=Capabilities"`
}

// MarshalJSON marshals the CapabilitiesSet object to JSON.
func (c *CapabilitiesSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Capabilities)
}

// UnmarshalJSON unmarshals the given data to a CapabilitiesSet
func (c *CapabilitiesSet) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &c.Capabilities)
}

// UnmarshalJSON unmarshals the CapabilityValues object from JSON.
func (c *CapabilityValues) UnmarshalJSON(bytes []byte) error {
	var values []string
	if err := json.Unmarshal(bytes, &values); err != nil {
		return err
	}

	c.Values = append(c.Values, values...)

	return nil
}

// MarshalJSON marshals the CapabilityValues object to JSON.
func (c CapabilityValues) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Values)
}
