package k8s

import "sync"

type PodInfo struct {
	Name      string
	Namespace string
	Node      string
}

type ServiceInfo struct {
	Name      string
	Namespace string
}

type NodeInfo struct {
	Name string
	Zone string
}

type Cache struct {
	mu     sync.RWMutex
	ipMap  map[string]PodInfo
	svcMap map[string]ServiceInfo
	nodeMap map[string]NodeInfo
}

func NewCache() *Cache {
	return &Cache{
		ipMap:   make(map[string]PodInfo),
		svcMap:  make(map[string]ServiceInfo),
		nodeMap: make(map[string]NodeInfo),
	}
}

func (c *Cache) SetPod(ip string, info PodInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ipMap[ip] = info
}

func (c *Cache) DeletePod(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ipMap, ip)
}

func (c *Cache) LookupPod(ip string) (PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.ipMap[ip]
	return info, ok
}

func (c *Cache) SetService(ip string, info ServiceInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.svcMap[ip] = info
}

func (c *Cache) DeleteService(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.svcMap, ip)
}

func (c *Cache) LookupService(ip string) (ServiceInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.svcMap[ip]
	return info, ok
}

func (c *Cache) SetNode(name string, info NodeInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeMap[name] = info
}

func (c *Cache) DeleteNode(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodeMap, name)
}

func (c *Cache) LookupNode(name string) (NodeInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.nodeMap[name]
	return info, ok
}
