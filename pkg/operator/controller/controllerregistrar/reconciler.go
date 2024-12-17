// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controllerregistrar

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
)

// cancelableManager is a 'manager.Manager' implementation and wrapper that holds a context
// which can be used to stop all Runnables added through this manager.
type cancelableManager struct {
	ctx context.Context
	manager.Manager
}

// Add adds the given runnable to the underlying manager with the context hold by the cancelableManager.
func (c *cancelableManager) Add(runnable manager.Runnable) error {
	runFn := manager.RunnableFunc(func(ctx context.Context) error {
		return runnable.Start(c.ctx)
	})

	return c.Manager.Add(runFn)
}

// Reconciler adds the controllers to the manager.
type Reconciler struct {
	Manager     manager.Manager
	Controllers []Controller

	controllersCancel context.CancelFunc
}

// Controller contains a function for registering a controller.
type Controller struct {
	Name             string
	AddToManagerFunc func(context.Context, manager.Manager, *operatorv1alpha1.Garden) (bool, error)
	added            bool
}

// Reconcile performs the controller registration.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)

	garden := &operatorv1alpha1.Garden{}
	if err := r.Manager.GetClient().Get(ctx, request.NamespacedName, garden); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Garden is gone, stopping all controllers")
			r.stopControllers(log)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if r.allControllersAdded() {
		log.Info("Controllers were already added")
		return reconcile.Result{}, nil
	}

	var requeueAfter time.Duration

	for i, controller := range r.Controllers {
		if !controller.added {
			if done, err := controller.AddToManagerFunc(ctx, r.Manager, garden); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed adding %s controller to manager: %w", controller.Name, err)
			} else if done {
				log.Info("Successfully added controller to manager", "controllerName", controller.Name)
				r.Controllers[i].added = true
			} else {
				log.Info("Controller is not yet ready to be added to the manager", "controllerName", controller.Name)
				requeueAfter = 2 * time.Second
			}
		}
	}

	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func (r *Reconciler) allControllersAdded() bool {
	for _, controller := range r.Controllers {
		if !controller.added {
			return false
		}
	}
	return true
}

func (r *Reconciler) stopControllers(log logr.Logger) {
	r.controllersCancel()
	for i, controller := range r.Controllers {
		log.Info("Stopped controller", "name", controller.Name)
		r.Controllers[i].added = false
	}
}
