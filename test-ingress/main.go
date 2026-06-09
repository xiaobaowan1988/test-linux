// test-ingress: minimal Kubernetes Ingress controller for arm64 test environment.
//
// Listens on :80. On each request:
//   1. Match Host + path prefix against current Ingress rules.
//   2. Look up Service ClusterIP:port — kube-proxy handles the DNAT to pod IPs.
//
// Watches /apis/networking.k8s.io/v1/ingresses and /api/v1/services from the
// kube-apiserver using a polling loop (every 5s).

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	apiServer   = "https://127.0.0.1:6443"
	bearerToken = "kubelet-static-token"
	listenAddr  = ":80"
)

// ── Kubernetes API types (minimal) ────────────────────────────────────────────

type IngressList struct {
	Items []Ingress `json:"items"`
}

type Ingress struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Rules []IngressRule `json:"rules"`
	} `json:"spec"`
}

type IngressRule struct {
	Host string     `json:"host"`
	HTTP *HTTPPaths `json:"http"`
}

type HTTPPaths struct {
	Paths []HTTPPath `json:"paths"`
}

type HTTPPath struct {
	Path     string `json:"path"`
	PathType string `json:"pathType"`
	Backend  struct {
		Service struct {
			Name string `json:"name"`
			Port struct {
				Number int `json:"number"`
			} `json:"port"`
		} `json:"service"`
	} `json:"backend"`
}

type ServiceList struct {
	Items []Service `json:"items"`
}

type Service struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		ClusterIP string `json:"clusterIP"`
		Ports     []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
}

// ── Route table ───────────────────────────────────────────────────────────────

type route struct {
	host      string
	path      string
	pathType  string
	svcName   string
	svcPort   int
	namespace string
}

type routeTable struct {
	mu       sync.RWMutex
	routes   []route
	clusterIPs map[string]string // "ns/name:port" → "clusterIP:port"
}

var table = &routeTable{
	clusterIPs: make(map[string]string),
}

// ── API client ────────────────────────────────────────────────────────────────

var apiClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	Timeout: 10 * time.Second,
}

func apiGet(path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", apiServer+path, nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API %s: %d", path, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ── Watcher loop ──────────────────────────────────────────────────────────────

func watchLoop() {
	for {
		refresh()
		time.Sleep(5 * time.Second)
	}
}

func refresh() {
	// Fetch all Ingresses
	data, err := apiGet("/apis/networking.k8s.io/v1/ingresses")
	if err != nil {
		log.Printf("fetch ingresses: %v", err)
		return
	}
	var ingList IngressList
	if err := json.Unmarshal(data, &ingList); err != nil {
		return
	}

	var newRoutes []route
	for _, ing := range ingList.Items {
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				newRoutes = append(newRoutes, route{
					host:      rule.Host,
					path:      p.Path,
					pathType:  p.PathType,
					svcName:   p.Backend.Service.Name,
					svcPort:   p.Backend.Service.Port.Number,
					namespace: ing.Metadata.Namespace,
				})
			}
		}
	}

	// Fetch all Services → build ClusterIP map
	data, err = apiGet("/api/v1/services")
	if err != nil {
		log.Printf("fetch services: %v", err)
		return
	}
	var svcList ServiceList
	if err := json.Unmarshal(data, &svcList); err != nil {
		return
	}

	newCIPs := make(map[string]string)
	for _, svc := range svcList.Items {
		if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
			continue
		}
		for _, p := range svc.Spec.Ports {
			key := fmt.Sprintf("%s/%s:%d", svc.Metadata.Namespace, svc.Metadata.Name, p.Port)
			newCIPs[key] = fmt.Sprintf("%s:%d", svc.Spec.ClusterIP, p.Port)
		}
	}

	table.mu.Lock()
	table.routes = newRoutes
	table.clusterIPs = newCIPs
	table.mu.Unlock()

	if len(newRoutes) > 0 {
		log.Printf("routes refreshed: %d ingress rules, %d services with ClusterIP",
			len(newRoutes), len(newCIPs))
		for _, r := range newRoutes {
			key := fmt.Sprintf("%s/%s:%d", r.namespace, r.svcName, r.svcPort)
			cip := newCIPs[key]
			log.Printf("  %s%s → %s (ClusterIP→%s)", r.host, r.path, key, cip)
		}
	}
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

func match(r route, host, path string) bool {
	if r.host != "" && r.host != host {
		return false
	}
	switch r.pathType {
	case "Exact":
		return path == r.path
	default:
		return strings.HasPrefix(path, r.path)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	path := req.URL.Path

	table.mu.RLock()
	var matched *route
	for i := range table.routes {
		if match(table.routes[i], host, path) {
			matched = &table.routes[i]
			break
		}
	}
	var target string
	if matched != nil {
		key := fmt.Sprintf("%s/%s:%d", matched.namespace, matched.svcName, matched.svcPort)
		target = table.clusterIPs[key]
	}
	table.mu.RUnlock()

	if matched == nil {
		http.Error(w, "no matching ingress rule", http.StatusNotFound)
		log.Printf("no route: host=%s path=%s", host, path)
		return
	}
	if target == "" {
		http.Error(w, "no ClusterIP for "+matched.svcName, http.StatusBadGateway)
		log.Printf("no ClusterIP for %s/%s", matched.namespace, matched.svcName)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   target,
	})
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error %s→%s: %v", host+path, target, err)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
	}
	log.Printf("proxy %s%s → ClusterIP %s (via kube-proxy)", host, path, target)
	proxy.ServeHTTP(w, req)
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("test-ingress controller starting, listen=%s (ClusterIP mode via kube-proxy)", listenAddr)

	for i := 0; i < 30; i++ {
		if _, err := apiGet("/healthz"); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	go watchLoop()

	hostname, _ := os.Hostname()
	log.Printf("ingress controller ready on %s%s", hostname, listenAddr)

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: http.HandlerFunc(handler),
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
