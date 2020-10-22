# Info

Forked from https://github.com/kubernetes/kubernetes/tree/v1.18.8 to support [Resource Quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
for Gardener offered resources, e.g. group `core.gardener.cloud`. This local copy will be obsolete after vendoring Gardener to Kubernetes 1.20.x with [k8s.io/kubernetes#93537](https://github.com/kubernetes/kubernetes/pull/93537).

# Adjustments

## ./kubernetes/pkg/quota/install/registry.go

- Core evaluators (Pod, Service, PVC) removed, not needed for G-API server
- `NewQuotaConfigurationForControllers` removed since covered by KCM

Diff
```
@@ -19,20 +19,12 @@ package install
 import (
    "k8s.io/apimachinery/pkg/runtime/schema"
    quota "k8s.io/kubernetes/pkg/quota/v1"
-	core "k8s.io/kubernetes/pkg/quota/v1/evaluator/core"
    generic "k8s.io/kubernetes/pkg/quota/v1/generic"
 )
 
 // NewQuotaConfigurationForAdmission returns a quota configuration for admission control.
 func NewQuotaConfigurationForAdmission() quota.Configuration {
-	evaluators := core.NewEvaluators(nil)
-	return generic.NewConfiguration(evaluators, DefaultIgnoredResources())
-}
-
-// NewQuotaConfigurationForControllers returns a quota configuration for controllers.
-func NewQuotaConfigurationForControllers(f quota.ListerForResourceFunc) quota.Configuration {
-	evaluators := core.NewEvaluators(f)
-	return generic.NewConfiguration(evaluators, DefaultIgnoredResources())
+	return generic.NewConfiguration(nil, DefaultIgnoredResources())
 }
 
 // ignoredResources are ignored by quota by default
```


