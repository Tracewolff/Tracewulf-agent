package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func zoneFromLabels(labels map[string]string) string {
	if z, ok := labels["topology.kubernetes.io/zone"]; ok {
		return z
	}
	if z, ok := labels["failure-domain.beta.kubernetes.io/zone"]; ok {
		return z
	}
	return "unknown"
}

func StartInformer(podCache *Cache, stopCh <-chan struct{}) error {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(homedir.HomeDir(), ".kube", "config")
	}

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
			podCache.SetPod(pod.Status.PodIP, PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Node:      pod.Spec.NodeName,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok || pod.Status.PodIP == "" {
				return
			}
			podCache.SetPod(pod.Status.PodIP, PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Node:      pod.Spec.NodeName,
			})
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if pod.Status.PodIP != "" {
				podCache.DeletePod(pod.Status.PodIP)
			}
		},
	})

	svcInformer := factory.Core().V1().Services().Informer()
	svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok || svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
				return
			}
			podCache.SetService(svc.Spec.ClusterIP, ServiceInfo{
				Name:      svc.Name,
				Namespace: svc.Namespace,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svc, ok := newObj.(*corev1.Service)
			if !ok || svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
				return
			}
			podCache.SetService(svc.Spec.ClusterIP, ServiceInfo{
				Name:      svc.Name,
				Namespace: svc.Namespace,
			})
		},
		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}
			if svc.Spec.ClusterIP != "" {
				podCache.DeleteService(svc.Spec.ClusterIP)
			}
		},
	})

	nodeInformer := factory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			podCache.SetNode(node.Name, NodeInfo{
				Name: node.Name,
				Zone: zoneFromLabels(node.Labels),
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node, ok := newObj.(*corev1.Node)
			if !ok {
				return
			}
			podCache.SetNode(node.Name, NodeInfo{
				Name: node.Name,
				Zone: zoneFromLabels(node.Labels),
			})
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			podCache.DeleteNode(node.Name)
		},
	})

	go podInformer.Run(stopCh)
	go svcInformer.Run(stopCh)
	go nodeInformer.Run(stopCh)

	if !cache.WaitForCacheSync(
		stopCh,
		podInformer.HasSynced,
		svcInformer.HasSynced,
		nodeInformer.HasSynced,
	) {
		return fmt.Errorf("failed to sync informer cache")
	}

	return nil
}
