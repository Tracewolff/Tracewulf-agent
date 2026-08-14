package k8s

import "sync"

type PodInfo struct {
	Name      string
	Namespace string
}

type Cache struct {
	mu    sync.RWMutex
	ipMap map[string]PodInfo
}

func NewCache() *Cache {
	return &Cache{ipMap: make(map[string]PodInfo)}
}

func (c *Cache) Set(ip string, info PodInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ipMap[ip] = info
}

func (c *Cache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ipMap, ip)
}

func (c *Cache) Lookup(ip string) (PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.ipMap[ip]
	return info, ok
}
