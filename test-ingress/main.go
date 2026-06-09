// test-ingress: minimal Kubernetes Ingress controller for arm64 test environment.
//
// Listens on :80. On each request:
//   1. Match Host + path prefix against current Ingress rules.
//   2. Look up Endpoints for the target Service (bypasses kube-proxy since we
//      have no kube-proxy running; ClusterIP is not routable).
//   3. Forward to the first ready endpoint address:port.
//
// Watches /apis/networking.k8s.io/v1/ingresses and /api/v1/endpoints from the
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
	Host string      `json:"host"`
	HTTP *HTTPPaths  `json:"http"`
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

type EndpointsList struct {
	Items []Endpoints `json:"items"`
}

type Endpoints struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Subsets []struct {
		Addresses []struct {
			IP string `json:"ip"`
		} `json:"addresses"`
		Ports []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"subsets"`
}

// ── Route table ───────────────────────────────────────────────────────────────

type route struct {
	host      string
	path      string
	pathType  string // Prefix | Exact | ImplementationSpecific
	svcName   string
	svcPort   int
	namespace string
}

type routeTable struct {
	mu        sync.RWMutex
	routes    []route
	endpoints map[string][]string // "ns/svcName:port" → ["ip:port", ...]
}

var table = &routeTable{
	endpoints: make(map[string][]string),
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

	// Fetch all Endpoints
	data, err = apiGet("/api/v1/endpoints")
	if err != nil {
		log.Printf("fetch endpoints: %v", err)
		return
	}
	var epList EndpointsList
	if err := json.Unmarshal(data, &epList); err != nil {
		return
	}

	newEP := make(map[string][]string)
	for _, ep := range epList.Items {
		for _, sub := range ep.Subsets {
			for _, addr := range sub.Addresses {
				for _, port := range sub.Ports {
					key := fmt.Sprintf("%s/%s:%d", ep.Metadata.Namespace, ep.Metadata.Name, port.Port)
					newEP[key] = append(newEP[key], fmt.Sprintf("%s:%d", addr.IP, port.Port))
				}
			}
		}
	}

	table.mu.Lock()
	table.routes = newRoutes
	table.endpoints = newEP
	table.mu.Unlock()

	if len(newRoutes) > 0 {
		log.Printf("routes refreshed: %d ingress rules, %d endpoint sets", len(newRoutes), len(newEP))
		for _, r := range newRoutes {
			log.Printf("  %s%s → %s/%s:%d", r.host, r.path, r.namespace, r.svcName, r.svcPort)
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
	default: // Prefix or ImplementationSpecific
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
	var targets []string
	if matched != nil {
		key := fmt.Sprintf("%s/%s:%d", matched.namespace, matched.svcName, matched.svcPort)
		targets = table.endpoints[key]
	}
	table.mu.RUnlock()

	if matched == nil {
		http.Error(w, "no matching ingress rule", http.StatusNotFound)
		log.Printf("no route for host=%s path=%s", host, path)
		return
	}
	if len(targets) == 0 {
		http.Error(w, "no endpoints for "+matched.svcName, http.StatusBadGateway)
		log.Printf("no endpoints for %s/%s", matched.namespace, matched.svcName)
		return
	}

	target := targets[0]
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   target,
	})
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error %s: %v", target, err)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
	}
	log.Printf("proxy %s%s → %s", host, path, target)
	proxy.ServeHTTP(w, req)
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("test-ingress controller starting, listen=%s", listenAddr)

	// Wait for apiserver to be reachable
	for i := 0; i < 30; i++ {
		if _, err := apiGet("/healthz"); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	go watchLoop()

	// Announce where we're listening
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
