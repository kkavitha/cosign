//
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

package webhook

import (
	"context"
	"fmt"
	"errors"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/injection/clients/dynamicclient"
	"k8s.io/client-go/dynamic"
	"k8s.io/apimachinery/pkg/runtime/schema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"crypto/ecdsa"
	"k8s.io/apimachinery/pkg/runtime"
	v1alpha1 "github.com/sigstore/cosign/pkg/cosign/kubernetes/api/v1alpha1"
	"github.com/gobwas/glob"
	listersv1 "k8s.io/client-go/listers/core/v1"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
)

type Validator struct {
	client     kubernetes.Interface
	dynamicClient dynamic.Interface
	lister     listersv1.SecretLister
}

func NewValidator(ctx context.Context) *Validator {
	return &Validator{
		client:     kubeclient.Get(ctx),
		lister:     secretinformer.Get(ctx).Lister(),
		dynamicClient: dynamicclient.Get(ctx),
	}
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ValidatePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	if wp.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &wp.Spec.Template.Spec, opt).ViaField("spec.template.spec")
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) ValidatePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	if p.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &p.Spec, opt).ViaField("spec")
}

// ValidateCronJob implements duckv1.CronJobValidator
func (v *Validator) ValidateCronJob(ctx context.Context, c *duckv1.CronJob) *apis.FieldError {
	if c.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, &c.Spec.JobTemplate.Spec.Template.Spec, opt).ViaField("spec.jobTemplate.spec.template.spec")
}

func (v *Validator) validatePodSpec(ctx context.Context, ps *corev1.PodSpec, opt k8schain.Options) (errs *apis.FieldError) {
	// Read the CRD
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}
	var clusterPolicy = schema.GroupVersionResource{Group: "sigstore.dev", Version: "v1alpha1", Resource: "clusterimagepolicies"}
	var identity = schema.GroupVersionResource{Group: "sigstore.dev", Version: "v1alpha1", Resource: "identities"}
	
	imagePolicy, _ := v.dynamicClient.Resource(clusterPolicy).Get(ctx, "image-policy", metav1.GetOptions{})
	unstructured := imagePolicy.UnstructuredContent()
	
	var imagePolicyType v1alpha1.ClusterImagePolicy
	error1 := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured, &imagePolicyType)
	
	if error1 != nil {
		logging.FromContext(ctx).Warnf("Unable to convert unstructured type to imagepolicy struct: %v", error1)
		return apis.ErrGeneric(error1.Error(), apis.CurrentField)
	}

	checkContainers := func(cs []corev1.Container, field string) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				errs = errs.Also(apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i))
				continue
			}

			// Require digests, otherwise the validation is meaningless
			// since the tag can move.
			if _, ok := ref.(name.Digest); !ok {
				errs = errs.Also(apis.ErrInvalidValue(
					fmt.Sprintf("%s must be an image digest", c.Image),
					"image",
				).ViaFieldIndex(field, i))
				continue
			}
			// Match the pattern
			// if matched, use the respective key to verify
			// Read the keys from the CRD from the namepattern that matches
			identities := []v1alpha1.Identity{}
			matched := false
			validationErrors := []error{}
			for _, imagePattern := range imagePolicyType.Spec.Images {
				imagePatternGlob := glob.MustCompile(imagePattern.NamePattern)
				if(imagePatternGlob.Match(c.Image)){
					// read the list of identities
					identityRefs := imagePattern.Identities
					for _, identityRef := range identityRefs {
						identityResource, errs := getIdentityResource(v, identity, ctx, identityRef)
						if errs != nil {
							continue
						}
						identities = append(identities, identityResource)
					}
					for _, identity := range identities {
						err := valid(ctx, ref, identity, v.lister, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
						validationErrors = append(validationErrors, err)
					}
					matched = true
					break
				}
			}

			// if no pattern matches we deny the resource creation - this is up for discussion
			if !matched {
				errorField := apis.ErrGeneric(errors.New("no pattern matched the image").Error(), "image").ViaFieldIndex(field, i)
				errorField.Details = c.Image
				errs = errs.Also(errorField)
				continue
			}

			if  err != nil {
				errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
				errorField.Details = c.Image
				errs = errs.Also(errorField)
				continue
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return errs
}

func getIdentityResource(v *Validator, identity schema.GroupVersionResource, ctx context.Context, identityRef v1alpha1.IdentityRef) (v1alpha1.Identity, error) {
	unstructuredIdentityResource, _ := v.dynamicClient.Resource(identity).Get(ctx, identityRef.Name, metav1.GetOptions{})

	unstructured := unstructuredIdentityResource.UnstructuredContent()
	var identityResource v1alpha1.Identity
	error1 := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured, &identityResource)
	if error1 != nil {
		logging.FromContext(ctx).Warnf("Unable to convert unstructured type to imagepolicy struct: %v", error1)
		return v1alpha1.Identity{}, error1
	}
	return identityResource, nil
}

// ResolvePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ResolvePodSpecable(ctx context.Context, wp *duckv1.WithPod) {
	if wp.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &wp.Spec.Template.Spec, opt)
}

// ResolvePod implements duckv1.PodValidator
func (v *Validator) ResolvePod(ctx context.Context, p *duckv1.Pod) {
	if p.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}

	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &p.Spec, opt)
}

// ResolveCronJob implements duckv1.CronJobValidator
func (v *Validator) ResolveCronJob(ctx context.Context, c *duckv1.CronJob) {
	if c.DeletionTimestamp != nil {
		// Don't mess with things that are being deleted.
		return
	}
	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &c.Spec.JobTemplate.Spec.Template.Spec, opt)
}

// For testing
var remoteResolveDigest = ociremote.ResolveDigest

func (v *Validator) resolvePodSpec(ctx context.Context, ps *corev1.PodSpec, opt k8schain.Options) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return
	}

	resolveContainers := func(cs []corev1.Container) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				logging.FromContext(ctx).Debugf("Unable to parse reference: %v", err)
				continue
			}

			// If we are in the context of a mutating webhook, then resolve the tag to a digest.
			switch {
			case apis.IsInCreate(ctx), apis.IsInUpdate(ctx):
				digest, err := remoteResolveDigest(ref, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
				if err != nil {
					logging.FromContext(ctx).Debugf("Unable to resolve digest %q: %v", ref.String(), err)
					continue
				}
				cs[i].Image = digest.String()
			}
		}
	}

	resolveContainers(ps.InitContainers)
	resolveContainers(ps.Containers)
}
