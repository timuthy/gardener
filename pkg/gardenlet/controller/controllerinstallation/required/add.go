// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package required

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils"
	predicateutils "github.com/gardener/gardener/pkg/controllerutils/predicate"
	"github.com/gardener/gardener/pkg/extensions"
)

// ControllerName is the name of this controller.
const ControllerName = "controllerinstallation-required"

type extensionInfo struct {
	newObject   func() client.Object
	newListFunc func() client.ObjectList
}

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager, gardenCluster, seedCluster cluster.Cluster) error {
	if r.GardenClient == nil {
		r.GardenClient = gardenCluster.GetClient()
	}
	if r.SeedClient == nil {
		r.SeedClient = seedCluster.GetClient()
	}
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if r.kindToExtensionInfo == nil {
		r.kindToExtensionInfo = map[string]extensionInfo{
			extensionsv1alpha1.BackupBucketResource:            {func() client.Object { return &extensionsv1alpha1.BackupBucket{} }, func() client.ObjectList { return &extensionsv1alpha1.BackupBucketList{} }},
			extensionsv1alpha1.BackupEntryResource:             {func() client.Object { return &extensionsv1alpha1.BackupEntry{} }, func() client.ObjectList { return &extensionsv1alpha1.BackupEntryList{} }},
			extensionsv1alpha1.BastionResource:                 {func() client.Object { return &extensionsv1alpha1.Bastion{} }, func() client.ObjectList { return &extensionsv1alpha1.BastionList{} }},
			extensionsv1alpha1.ContainerRuntimeResource:        {func() client.Object { return &extensionsv1alpha1.ContainerRuntime{} }, func() client.ObjectList { return &extensionsv1alpha1.ContainerRuntimeList{} }},
			extensionsv1alpha1.ControlPlaneResource:            {func() client.Object { return &extensionsv1alpha1.ControlPlane{} }, func() client.ObjectList { return &extensionsv1alpha1.ControlPlaneList{} }},
			extensionsv1alpha1.DNSRecordResource:               {func() client.Object { return &extensionsv1alpha1.DNSRecord{} }, func() client.ObjectList { return &extensionsv1alpha1.DNSRecordList{} }},
			extensionsv1alpha1.ExtensionResource:               {func() client.Object { return &extensionsv1alpha1.Extension{} }, func() client.ObjectList { return &extensionsv1alpha1.ExtensionList{} }},
			extensionsv1alpha1.InfrastructureResource:          {func() client.Object { return &extensionsv1alpha1.Infrastructure{} }, func() client.ObjectList { return &extensionsv1alpha1.InfrastructureList{} }},
			extensionsv1alpha1.NetworkResource:                 {func() client.Object { return &extensionsv1alpha1.Network{} }, func() client.ObjectList { return &extensionsv1alpha1.NetworkList{} }},
			extensionsv1alpha1.OperatingSystemConfigResource:   {func() client.Object { return &extensionsv1alpha1.OperatingSystemConfig{} }, func() client.ObjectList { return &extensionsv1alpha1.OperatingSystemConfigList{} }},
			extensionsv1alpha1.SelfHostedShootExposureResource: {func() client.Object { return &extensionsv1alpha1.SelfHostedShootExposure{} }, func() client.ObjectList { return &extensionsv1alpha1.SelfHostedShootExposureList{} }},
			extensionsv1alpha1.WorkerResource:                  {func() client.Object { return &extensionsv1alpha1.Worker{} }, func() client.ObjectList { return &extensionsv1alpha1.WorkerList{} }},
		}
	}

	c, err := builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		WithOptions(
			controller.Options{
				Reconciler:              r,
				MaxConcurrentReconciles: ptr.Deref(r.Config.ConcurrentSyncs, 0),
				ReconciliationTimeout:   controllerutils.DefaultReconciliationTimeout,
			},
		).
		Watches(
			&gardencorev1beta1.ControllerInstallation{},
			&handler.EnqueueRequestForObject{},
		).
		Build(r)
	if err != nil {
		return err
	}

	// Register watches for all known extension kinds, so that we can directly react on extension deletions and mark the installation as not required.
	for _, extension := range r.kindToExtensionInfo {
		gkv, err := apiutil.GVKForObject(extension.newObject(), kubernetes.SeedScheme)
		utilruntime.Must(err)

		eventHandler := handler.EnqueueRequestsFromMapFunc(r.MapObjectKindToControllerInstallations(
			mgr.GetLogger().WithValues("controller", ControllerName),
			gkv.Kind,
		))

		if err := c.Watch(
			source.Kind[client.Object](
				seedCluster.GetCache(),
				extension.newObject(),
				eventHandler,
				extensions.ObjectPredicate(),
				predicateutils.HasClass(extensionsv1alpha1.ExtensionClassShoot, extensionsv1alpha1.ExtensionClassSeed),
				predicateutils.ForEventTypes(predicateutils.Delete),
			),
		); err != nil {
			return err
		}
	}

	return nil
}

// MapObjectKindToControllerInstallations returns a mapper that maps an extension resource to matching controllerinstallation resources.
func (r *Reconciler) MapObjectKindToControllerInstallations(log logr.Logger, objectKind string) handler.MapFunc {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		extensionObj, ok := object.(*extensionsv1alpha1.Extension)
		if !ok {
			log.Error(nil, "Object is not an Extension", "object", fmt.Sprint("%T", object))
			return nil
		}

		objectType := extensionObj.GetExtensionSpec().GetExtensionType()
		log = log.WithValues("extensionKind", objectKind)

		controllerRegistrationList := &gardencorev1beta1.ControllerRegistrationList{}
		if err := r.GardenClient.List(ctx, controllerRegistrationList); err != nil {
			log.Error(err, "Failed to list ControllerRegistrations")
			return nil
		}

		matchingControllerRegistrations := sets.New[string]()
		for _, controllerRegistration := range controllerRegistrationList.Items {
			for _, resource := range controllerRegistration.Spec.Resources {
				if resource.Kind == objectKind && resource.Type == objectType {
					matchingControllerRegistrations.Insert(controllerRegistration.Name)
					break
				}
			}
		}

		controllerInstallationList := &gardencorev1beta1.ControllerInstallationList{}
		if err := r.GardenClient.List(ctx, controllerInstallationList, client.MatchingFields{core.SeedRefName: r.SeedName}); err != nil {
			log.Error(err, "Failed to list ControllerInstallations")
			return nil
		}

		var requests []reconcile.Request
		for _, obj := range controllerInstallationList.Items {
			if !matchingControllerRegistrations.Has(obj.Spec.RegistrationRef.Name) {
				continue
			}

			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: obj.Name}})
		}

		return requests
	}
}
