package controller

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"log"
	"main/internal/ebpf"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog"
)

type Controller struct {
	stopper   chan struct{}
	informer  cache.SharedIndexInformer
	Clientset *kubernetes.Clientset
	Config    *rest.Config
	Ch        chan ebpf.Metric
	Ebpfs     map[int]*ebpf.Ebpf
}

func NewController(ch chan ebpf.Metric) Controller {
	// config, err := rest.InClusterConfig()
	config := OutOfClusterAuth()
	// if config != nil {
	// 	log.Panic(err)
	// }
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}
	return Controller{
		Clientset: clientset,
		Config:    config,
		Ch:        ch,
		Ebpfs:     make(map[int]*ebpf.Ebpf),
	}

}
func (c *Controller) Run() {
	factory := informers.NewSharedInformerFactory(c.Clientset, 0)
	informer := factory.Core().V1().Endpoints().Informer()
	stopper := make(chan struct{})
	defer runtime.HandleCrash()

	nodename := os.Getenv("nodename")
	if nodename == "" {
		log.Fatalf("nodename need to set !")
	}

	//监听endpoint资源的变化,用于初始化ebpf程序
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			newEndpoint := obj.(*corev1.Endpoints)
			// var oldEndpoint *corev1.Endpoints
			c.addAndUpdate(newEndpoint, nodename)
			// log.Printf("%+v %s\n", newEndpoint, "Added")
		},
		// DeleteFunc: func(obj interface{}) {
		// 	endpoint := obj.(*corev1.Endpoints)

		// },
		// UpdateFunc: func(oldObj interface{}, newObj interface{}) {
		// 	// oldEndpoint := oldObj.(*corev1.Endpoints)
		// 	newEndpoint := newObj.(*corev1.Endpoints)
		// 	log.Printf("nnnnnnnnnnnnnn %v%s\n", newEndpoint, "Updated")
		// 	// log.Printf("oooooooooooooo %v%s\n", oldEndpoint, "Updated")
		// 	c.addAndUpdate(newEndpoint, "cn-hangzhou.172.16.174.45")
		// },
	})
	c.stopper = stopper
	c.informer = informer
	go c.informer.Run(c.stopper)
}

func (c *Controller) addAndUpdate(new *corev1.Endpoints, nodename string) {
	ports := []int32{0}
	for _, subsets := range new.Subsets {
		for _, address := range subsets.Addresses {
			if address.NodeName != nil && *address.NodeName == nodename {
				// log.Printf("endpoint ip: %v, node: %v, type: %v, pod: %v, ns: %v\n",
				// 	address.IP, *address.NodeName, address.TargetRef.Kind,
				// 	address.TargetRef.Name, address.TargetRef.Namespace)
				index, err := c.getNetfaceIndex(address.TargetRef.Name,
					address.TargetRef.Namespace)
				if err != nil {
					log.Printf("Get netface index error: %v [%s][%s]\n",
						err, address.TargetRef.Namespace, address.TargetRef.Name)
					break
				}
				if index == 2 {
					ports = getPorts(subsets.Ports)
				}
				_, ok := c.Ebpfs[index]
				if ok {
					//会有多个endpint对应一个pod的不同端口的情况, 对于普通类型的pod流量去全采集
					if index != 2 {
						log.Printf("normal interface of ebpf existed, skip [%s][%s]\n",
							address.TargetRef.Namespace, address.TargetRef.Name)
						break
					} else {
						//index位2代表是network模式的pod,对于这些类型的pod,
						//统一使用一次socket的syscall，然后使用端口来设置其元数据,
						//这里只能准确关联到 IN 方向的请求
						c.Ebpfs[2].AppendPod(ports, address.TargetRef.Name,
							address.TargetRef.Namespace, new.Name)
						log.Printf("hostnetwork interface of ebpf existed, skip [%s][%s]\n",
							address.TargetRef.Namespace, address.TargetRef.Name)
						break
					}
				}
				ebpf := ebpf.NewEbpf(index, address.IP, ports, *address.NodeName, address.TargetRef.Name,
					address.TargetRef.Namespace, new.Name, c.Ch)
				err = ebpf.Load()
				if err != nil {
					log.Printf("Load ebpf error[%s][%s][%s]: %v\n", *address.NodeName,
						address.TargetRef.Namespace, address.TargetRef.Name, err)
					break
				}
				c.Ebpfs[index] = ebpf
			}
		}
	}
}

func (c *Controller) getNetfaceIndex(pod string, namespace string) (int, error) {
	var result string
	var err error
	var container string
	result, err = c.ExecPod(pod, namespace, "")

	if err != nil && strings.Contains(err.Error(), "container name must be specified") {
		container, err = c.getContainerName(pod, namespace)
		if err != nil {
			return 0, err
		}
		result, err = c.ExecPod(pod, namespace, container)
	}
	if err != nil {
		return 0, err
	}
	s := strings.Trim(result, "\n")
	id, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (c *Controller) getContainerName(pod string, namespace string) (string, error) {
	p, err := c.Clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return p.Spec.Containers[0].Name, nil
}

func (c *Controller) ExecPod(pod string, namespace string, container string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	execOpt := &corev1.PodExecOptions{
		Stdin:  false,
		Stdout: true,
		Stderr: true,
		TTY:    false,
		//TODO: 一个pod中有多个container的时候如何进入default容器
		Container: container,
		Command: []string{
			"cat",
			"/sys/class/net/eth0/iflink",
		},
	}

	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(execOpt, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return "", errors.New("NewSPDYExecutor: " + err.Error())
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return "", errors.New("exec.Stream:" + err.Error())
	}
	if len(stderr.Bytes()) > 0 {
		return "", errors.New(stderr.String())
	}
	return stdout.String(), nil

}

func getPorts(e []corev1.EndpointPort) []int32 {
	var ports []int32
	for _, v := range e {
		ports = append(ports, v.Port)
	}
	return ports
}

func OutOfClusterAuth() (config *rest.Config) {

	var err error
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig",
			filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		klog.Infoln(err.Error())
		os.Exit(3)
	}
	return
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
