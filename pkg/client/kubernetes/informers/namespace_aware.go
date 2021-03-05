// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package informers

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"k8s.io/client-go/informers/internalinterfaces"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type InformerFn func(client kubernetes.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer

// NewSecretInformer
func NewNamespaceAwareInformer(client kubernetes.Interface, resyncPeriod time.Duration, indexers cache.Indexers, fn InformerFn) *NamespaceAwareIndexInformer {

	indexers["foo"] = func(obj interface{}) ([]string, error) {
		return nil, nil
	}

	return &NamespaceAwareIndexInformer{
		client:       client,
		resyncPeriod: resyncPeriod,
		indexer:      cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, indexers),
		informerFn:   fn,

		stopChs:        make(map[string]chan struct{}),
		indexInformers: make(map[string]cache.SharedIndexInformer),
	}
}

var _ cache.SharedIndexInformer = &NamespaceAwareIndexInformer{}

type NamespaceAwareIndexInformer struct {
	client       kubernetes.Interface
	resyncPeriod time.Duration
	indexer      cache.Indexer
	informerFn   InformerFn
	startedLock  sync.Mutex

	handler            cache.WatchErrorHandler
	eventHandlers      []cache.ResourceEventHandler
	eventHandlerResync []eventHandlerResync
	tweakListOptions   internalinterfaces.TweakListOptionsFunc

	started        bool
	stopChs        map[string]chan struct{}
	indexInformers map[string]cache.SharedIndexInformer
}

type eventHandlerResync struct {
	handler      cache.ResourceEventHandler
	resyncPeriod time.Duration
}

func (s *NamespaceAwareIndexInformer) AddEventHandler(handler cache.ResourceEventHandler) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	s.eventHandlers = append(s.eventHandlers, handler)
	for _, indexInformer := range s.indexInformers {
		indexInformer.AddEventHandler(handler)
	}
}

func (s *NamespaceAwareIndexInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	s.eventHandlerResync = append(s.eventHandlerResync, eventHandlerResync{
		handler:      handler,
		resyncPeriod: resyncPeriod,
	})
	for _, indexInformer := range s.indexInformers {
		indexInformer.AddEventHandlerWithResyncPeriod(handler, resyncPeriod)
	}
}

func (s *NamespaceAwareIndexInformer) GetStore() cache.Store {
	return s.indexer
}

func (s NamespaceAwareIndexInformer) GetController() cache.Controller {
	// GetController is deprecated and not called in related logic.
	return nil
}

func (s *NamespaceAwareIndexInformer) Run(stopCh <-chan struct{}) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()
	if s.started {
		return
	}

	go func() {
		defer func() {
			for _, stop := range s.stopChs {
				close(stop)
			}
		}()
		<-stopCh
	}()
	for namespace, indexInformer := range s.indexInformers {
		go indexInformer.Run(s.stopChs[namespace])
	}
	s.started = true
}

func (s *NamespaceAwareIndexInformer) HasSynced() bool {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	for _, indexInformer := range s.indexInformers {
		if !indexInformer.HasSynced() {
			return false
		}
	}
	return true
}

func (s NamespaceAwareIndexInformer) LastSyncResourceVersion() string {
	// TODO: visit again later
	return ""
}

func (s *NamespaceAwareIndexInformer) SetWatchErrorHandler(handler cache.WatchErrorHandler) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.started {
		return fmt.Errorf("informer has already started")
	}

	s.handler = handler
	for _, indexInformer := range s.indexInformers {
		if err := indexInformer.SetWatchErrorHandler(handler); err != nil {
			return err
		}
	}
	return nil
}

func (s *NamespaceAwareIndexInformer) AddIndexers(indexers cache.Indexers) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.started {
		return fmt.Errorf("informer has already started")
	}

	return s.indexer.AddIndexers(indexers)
}

func (s *NamespaceAwareIndexInformer) GetIndexer() cache.Indexer {
	return s.indexer
}

func (s *NamespaceAwareIndexInformer) Add(ctx context.Context, namespace string) {
	fmt.Printf("** DEBUG: Add informer for namespace: %s\n", namespace)
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if _, ok := s.indexInformers[namespace]; ok {
		return
	}

	informer := s.informerFn(s.client, namespace, s.resyncPeriod, s.indexer.GetIndexers(), s.tweakListOptions)
	indexer := informer.GetIndexer()
	reflect.ValueOf(indexer).Elem().Set(reflect.ValueOf(s.indexer).Elem())

	for _, handler := range s.eventHandlers {
		informer.AddEventHandler(handler)
	}
	for _, e := range s.eventHandlerResync {
		informer.AddEventHandlerWithResyncPeriod(e.handler, e.resyncPeriod)
	}

	stopCh := make(chan struct{})
	s.stopChs[namespace] = stopCh

	if s.started {
		go informer.Run(stopCh)
		cacheTimeout, cancel := context.WithDeadline(ctx, time.Now().Add(time.Minute))
		defer cancel()
		cache.WaitForCacheSync(cacheTimeout.Done(), informer.HasSynced)
	}

	s.indexInformers[namespace] = informer
}

func (s *NamespaceAwareIndexInformer) Remove(namespace string) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	_, ok := s.indexInformers[namespace]
	if !ok {
		return
	}

	// TODO: Delete elements from Store and Indexer

	stopCh := s.stopChs[namespace]
	defer close(stopCh)
	delete(s.indexInformers, namespace)
}
