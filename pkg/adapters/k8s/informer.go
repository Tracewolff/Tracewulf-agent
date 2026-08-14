package k8s

import (
	"fmt"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func StartInformer(podCache *Cache, stopCh <-chan struct{}) error {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create clientset: %w", err)
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Status.PodIP == "" {
				return
			}
			podCache.Set(pod.Status.PodIP, PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok || pod.Status.PodIP == "" {
				return
			}
			podCache.Set(pod.Status.PodIP, PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			})
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if pod.Status.PodIP != "" {
				podCache.Delete(pod.Status.PodIP)
			}
		},
	})

	go podInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, podInformer.HasSynced) {
		return fmt.Errorf("failed to sync informer cache")
	}

	return nil
}
