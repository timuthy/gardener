// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/utils/flow"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	virtualClusterClientSet kubernetes.Interface,
	garden *gardenInfo,
	extension *operatorv1alpha1.Extension,
) (
	reconcile.Result,
	error,
) {
	conditions := NewConditions(r.Clock, extension.Status)

	if garden.garden == nil {
		conditions.installed = v1beta1helper.UpdatedConditionWithClock(r.Clock, conditions.installed, gardencorev1beta1.ConditionFalse, ConditionNoGardenFound, "No garden found")
		return reconcile.Result{}, r.updateExtensionStatus(ctx, log, extension, conditions)
	}

	reconcileCtx, cancel := controllerutils.GetMainReconciliationContext(ctx, controllerutils.DefaultReconciliationTimeout)
	defer cancel()

	if !controllerutil.ContainsFinalizer(extension, operatorv1alpha1.FinalizerName) {
		log.Info("Adding finalizer")
		if err := controllerutils.AddFinalizers(reconcileCtx, r.RuntimeClientSet.Client(), extension, operatorv1alpha1.FinalizerName); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	var (
		reconcileResult reconcile.Result
		g               = flow.NewGraph("Extension reconciliation")

		deployExtensionInRuntime = g.Add(flow.Task{
			Name: "Deploying extension in runtime cluster",
			Fn: func(ctx context.Context) error {
				return r.runtime.Reconcile(ctx, log, extension)
			},
		})

		checkGarden = g.Add(flow.Task{
			Name: "Checking if garden is reconciled",
			Fn: func(ctx context.Context) error {
				if !garden.reconciled {
					log.Info("Garden is not yet in 'Reconcile Succeeded' state, re-queueing", "requeueAfter", requeueGardenResourceNotReady)
					reconcileResult = reconcile.Result{RequeueAfter: requeueGardenResourceNotReady}
					return fmt.Errorf("garden is not yet successfully reconciled")
				}
				return nil
			},
			Dependencies: flow.NewTaskIDs(deployExtensionInRuntime),
		})

		_ = g.Add(flow.Task{
			Name: "Deploying Admission Controller",
			Fn: func(ctx context.Context) error {
				if garden.genericTokenKubeconfigSecretName == nil {
					return fmt.Errorf("generic kubeconfig secret name is not set for garden")
				}
				return r.admission.Reconcile(ctx, log, virtualClusterClientSet, *garden.genericTokenKubeconfigSecretName, extension)
			},
			Dependencies: flow.NewTaskIDs(checkGarden),
		})

		_ = g.Add(flow.Task{
			Name: "Deploying ControllerRegistration and ControllerDeployment",
			Fn: func(ctx context.Context) error {
				return r.controllerRegistration.Reconcile(ctx, log, virtualClusterClientSet.Client(), extension)
			},
			Dependencies: flow.NewTaskIDs(checkGarden),
		})
	)

	if flowErr := g.Compile().Run(reconcileCtx, flow.Opts{
		Log: log,
	}); flowErr != nil {
		conditions.installed = v1beta1helper.UpdatedConditionWithClock(r.Clock, conditions.installed, gardencorev1beta1.ConditionFalse, ConditionReconcileFailed, flowErr.Error())
		return reconcileResult, errors.Join(flowErr, r.updateExtensionStatus(ctx, log, extension, conditions))
	}

	conditions.installed = v1beta1helper.UpdatedConditionWithClock(r.Clock, conditions.installed, gardencorev1beta1.ConditionTrue, ConditionReconcileSuccess, "Extension has been reconciled successfully")
	return reconcileResult, r.updateExtensionStatus(ctx, log, extension, conditions)
}
