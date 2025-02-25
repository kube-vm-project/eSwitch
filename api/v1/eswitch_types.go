/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type EswitchPortSpec struct {
	// Physical interface name being added to the switch
	Interface string `json:"interface"`
	// The type of XDP mode being used for the interface
	XDPMode string `json:"xdpmode"`
	// Port VLANID to be used on the port itself
	PVID int `json:"pvid,omitempty"`
	// Tagged VLAN traffic to be allowed on the port
	VLANS []uint16 `json:"vlans,omitempty"`
}

// EswitchSpec defines the desired state of Eswitch.
type EswitchSpec struct {
	// Ports contains the configuration for each port being added to the switch
	Ports []EswitchPortSpec `json:"ports"`
	// MAC addresses that are immediately ignored by the switch
	IgnoreMAC []string `json:"ignoreMAC,omitempty"`
}

// EswitchStatus defines the observed state of Eswitch.
type EswitchStatus struct {
	Configured bool `json:"configured"`
	Errors     bool `json:"errors"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Eswitch is the Schema for the eswitches API.
type Eswitch struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EswitchSpec   `json:"spec,omitempty"`
	Status EswitchStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EswitchList contains a list of Eswitch.
type EswitchList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Eswitch `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Eswitch{}, &EswitchList{})
}
