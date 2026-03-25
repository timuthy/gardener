// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package required

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardenletconfigv1alpha1 "github.com/gardener/gardener/pkg/apis/config/gardenlet/v1alpha1"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

// Reconciler reconciles ControllerInstallations. It checks whether they are still required by using the
// <KindToRequiredTypes> map.
type Reconciler struct {
	GardenClient client.Client
	SeedClient   client.Client
	Config       gardenletconfigv1alpha1.ControllerInstallationRequiredControllerConfiguration
	Clock        clock.Clock
	SeedName     string

	kindToExtensionInfo map[string]extensionInfo
}

// Reconcile performs the main reconciliation logic.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)

	controllerInstallation := &gardencorev1beta1.ControllerInstallation{}
	if err := r.GardenClient.Get(ctx, request.NamespacedName, controllerInstallation); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	controllerRegistration := &gardencorev1beta1.ControllerRegistration{}
	if err := r.GardenClient.Get(ctx, client.ObjectKey{Name: controllerInstallation.Spec.RegistrationRef.Name}, controllerRegistration); err != nil {
		return reconcile.Result{}, err
	}

	var (
		requiredKindTypes = sets.New[string]()
		message           string
	)

	for _, resource := range controllerRegistration.Spec.Resources {
		extensionInfo, ok := r.kindToExtensionInfo[resource.Kind]
		if !ok {
			return reconcile.Result{}, fmt.Errorf("unknown extension kind: %s", resource.Kind)
		}

		extensions := extensionInfo.newListFunc()
		if err := r.SeedClient.List(ctx, extensions); err != nil {
			return reconcile.Result{}, fmt.Errorf("error listing extension resources: %w", err)
		}

		if err := meta.EachListItem(extensions, func(o runtime.Object) error {
			extensionObj, ok := o.(*extensionsv1alpha1.Extension)
			if !ok {
				return fmt.Errorf("expected *extensionsv1alpha1.Extension but got %T", extensionObj)
			}

			if extensionObj.GetExtensionSpec().GetExtensionType() == resource.Type {
				requiredKindTypes.Insert(fmt.Sprintf("%s/%s", resource.Kind, resource.Type))
			}

			return nil
		}); err != nil {
			return reconcile.Result{}, fmt.Errorf("error processing extension resources: %w", err)
		}
	}

	installationRequired := len(requiredKindTypes) > 0
	if installationRequired {
		message = fmt.Sprintf("extension objects still exist in the seed: %+v", requiredKindTypes.UnsortedList())
	} else {
		message = "no extension objects exist in the seed having the kind/type combinations the controller is responsible for"
	}

	if err := updateControllerInstallationRequiredCondition(ctx, r.GardenClient, r.Clock, controllerInstallation, installationRequired, message); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func updateControllerInstallationRequiredCondition(ctx context.Context, c client.StatusClient, clock clock.Clock, controllerInstallation *gardencorev1beta1.ControllerInstallation, required bool, message string) error {
	var (
		conditionRequired = v1beta1helper.GetOrInitConditionWithClock(clock, controllerInstallation.Status.Conditions, gardencorev1beta1.ControllerInstallationRequired)

		status = gardencorev1beta1.ConditionTrue
		reason = "ExtensionObjectsExist"
	)

	if !required {
		status = gardencorev1beta1.ConditionFalse
		reason = "NoExtensionObjects"
	}

	patch := client.StrategicMergeFrom(controllerInstallation.DeepCopy())
	controllerInstallation.Status.Conditions = v1beta1helper.MergeConditions(
		controllerInstallation.Status.Conditions,
		v1beta1helper.UpdatedConditionWithClock(clock, conditionRequired, status, reason, message),
	)

	return c.Status().Patch(ctx, controllerInstallation, patch)
}
