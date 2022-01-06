// Copyright 2021 The Sigstore Authors.
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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterImagePolicySpec defines the desired state of ImagePolicy
type IdentitySpec struct {
	// Secret is the name of the secret that holds the public key
	Secret string `json:"secret,omitempty"`

	// Namespace is the namepace where the secret is stored
	Namespace string `json:"namespace,omitempty"`

	// Issuer is the OIDC identity provider
	Issuer string `json:"issuer,omitempty"`

	// Subject is the OIDC email address of the entity signing the artifact
	Subject string `json:"subject,omitempty"`

	// RekorURL is the URL to the service that hosts the transparency logs
	RekorURL string `json:"rekorurl,omitempty"`

	// FulcioEndpoint is the fulcio service endpoint
	FulcioEndpoint string `json:"fulcioendpoint,omitempty"`

}

//+kubebuilder:object:root=true
//+kubebuilder:resource:path=identities,scope=Cluster

// ClusterImagePolicy is the Schema for the imagepolicies API
type Identity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec IdentitySpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterImagePolicyList contains a list of ClusterImagePolicy
type IdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Identity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Identity{}, &IdentityList{})
}
