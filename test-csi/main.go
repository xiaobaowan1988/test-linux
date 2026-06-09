// test-csi: minimal CSI hostpath driver for Kubernetes arm64 test environment.
//
// Architecture:
//   - CSI gRPC server  : /var/lib/kubelet/plugins/test.csi.k8s.io/csi.sock
//   - Kubelet registrar: /var/lib/kubelet/plugins_registry/test.csi.k8s.io-reg.sock
//   - Built-in provisioner goroutine: watches PVCs, creates host dirs + PV objects
//
// Volume backend: directories under /var/lib/test-csi-volumes/<volumeHandle>/
// NodePublishVolume bind-mounts that directory into the pod target path.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "test-csi/registration"
)

const (
	driverName  = "test.csi.k8s.io"
	driverVer   = "v0.1.0"
	csiSock     = "/var/lib/kubelet/plugins/test.csi.k8s.io/csi.sock"
	regSock     = "/var/lib/kubelet/plugins_registry/test.csi.k8s.io-reg.sock"
	volumeRoot  = "/var/lib/test-csi-volumes"
	apiServer   = "https://127.0.0.1:6443"
	bearerToken = "kubelet-static-token"
	nodeID      = "test-node"
	storageClass = "test-csi"
)

// ── HTTP client for kube-apiserver ────────────────────────────────────────────

var apiClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	Timeout: 10 * time.Second,
}

func apiDo(method, path string, body []byte) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, apiServer+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

// ── CSI driver struct (implements all three CSI services) ─────────────────────

type driver struct{}

// Identity Service ─────────────────────────────────────────────────────────────

func (d *driver) GetPluginInfo(_ context.Context, _ *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: driverName, VendorVersion: driverVer}, nil
}

func (d *driver) GetPluginCapabilities(_ context.Context, _ *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{
		Capabilities: []*csi.PluginCapability{
			{Type: &csi.PluginCapability_Service_{
				Service: &csi.PluginCapability_Service{
					Type: csi.PluginCapability_Service_CONTROLLER_SERVICE,
				},
			}},
		},
	}, nil
}

func (d *driver) Probe(_ context.Context, _ *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{}, nil
}

// Controller Service ───────────────────────────────────────────────────────────

func (d *driver) CreateVolume(_ context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	volID := "csi-" + req.Name
	volPath := filepath.Join(volumeRoot, volID)
	if err := os.MkdirAll(volPath, 0750); err != nil {
		return nil, status.Errorf(codes.Internal, "mkdir %s: %v", volPath, err)
	}
	log.Printf("CreateVolume: %s → %s", req.Name, volPath)
	return &csi.CreateVolumeResponse{
		Volume: &csi.Volume{
			VolumeId:      volID,
			CapacityBytes: req.CapacityRange.GetRequiredBytes(),
		},
	}, nil
}

func (d *driver) DeleteVolume(_ context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	volPath := filepath.Join(volumeRoot, req.VolumeId)
	if err := os.RemoveAll(volPath); err != nil {
		return nil, status.Errorf(codes.Internal, "remove %s: %v", volPath, err)
	}
	log.Printf("DeleteVolume: %s", req.VolumeId)
	return &csi.DeleteVolumeResponse{}, nil
}

func (d *driver) ControllerGetCapabilities(_ context.Context, _ *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	return &csi.ControllerGetCapabilitiesResponse{
		Capabilities: []*csi.ControllerServiceCapability{
			{Type: &csi.ControllerServiceCapability_Rpc{
				Rpc: &csi.ControllerServiceCapability_RPC{
					Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
				},
			}},
		},
	}, nil
}

func (d *driver) ValidateVolumeCapabilities(_ context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
			VolumeCapabilities: req.VolumeCapabilities,
		},
	}, nil
}

// Stubs for unused Controller RPCs
func (d *driver) ListVolumes(_ context.Context, _ *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) GetCapacity(_ context.Context, _ *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) CreateSnapshot(_ context.Context, _ *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) DeleteSnapshot(_ context.Context, _ *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ListSnapshots(_ context.Context, _ *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ControllerExpandVolume(_ context.Context, _ *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ControllerGetVolume(_ context.Context, _ *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ControllerModifyVolume(_ context.Context, _ *csi.ControllerModifyVolumeRequest) (*csi.ControllerModifyVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ControllerPublishVolume(_ context.Context, _ *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) ControllerUnpublishVolume(_ context.Context, _ *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

// Node Service ─────────────────────────────────────────────────────────────────

func (d *driver) NodeGetInfo(_ context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: nodeID}, nil
}

func (d *driver) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

func (d *driver) NodePublishVolume(_ context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	src := filepath.Join(volumeRoot, req.VolumeId)
	tgt := req.TargetPath

	if err := os.MkdirAll(src, 0750); err != nil {
		return nil, status.Errorf(codes.Internal, "mkdir src %s: %v", src, err)
	}
	if err := os.MkdirAll(tgt, 0750); err != nil {
		return nil, status.Errorf(codes.Internal, "mkdir tgt %s: %v", tgt, err)
	}
	// bind mount
	if err := syscall.Mount(src, tgt, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return nil, status.Errorf(codes.Internal, "bind mount %s→%s: %v", src, tgt, err)
	}
	if req.Readonly {
		if err := syscall.Mount("", tgt, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			log.Printf("WARN: remount ro failed: %v", err)
		}
	}
	log.Printf("NodePublishVolume: %s → %s", src, tgt)
	return &csi.NodePublishVolumeResponse{}, nil
}

func (d *driver) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if err := syscall.Unmount(req.TargetPath, syscall.MNT_DETACH); err != nil && !os.IsNotExist(err) {
		log.Printf("NodeUnpublishVolume umount %s: %v (ignored)", req.TargetPath, err)
	}
	os.Remove(req.TargetPath)
	log.Printf("NodeUnpublishVolume: %s", req.TargetPath)
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// Stubs for unused Node RPCs
func (d *driver) NodeStageVolume(_ context.Context, _ *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) NodeUnstageVolume(_ context.Context, _ *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) NodeGetVolumeStats(_ context.Context, _ *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}
func (d *driver) NodeExpandVolume(_ context.Context, _ *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

// ── Kubelet plugin registration server ────────────────────────────────────────

type registrar struct {
	pb.UnimplementedRegistrationServer
}

func (r *registrar) GetInfo(_ context.Context, _ *pb.InfoRequest) (*pb.PluginInfo, error) {
	log.Println("registrar: GetInfo called")
	return &pb.PluginInfo{
		Type:              "CSIPlugin",
		Name:              driverName,
		Endpoint:          csiSock,
		SupportedVersions: []string{"1.0.0"},
	}, nil
}

func (r *registrar) NotifyRegistrationStatus(_ context.Context, s *pb.RegistrationStatus) (*pb.RegistrationStatusResponse, error) {
	if s.PluginRegistered {
		log.Printf("registrar: kubelet registered %s successfully", driverName)
	} else {
		log.Printf("registrar: kubelet registration error: %s", s.Error)
	}
	return &pb.RegistrationStatusResponse{}, nil
}

// ── Built-in provisioner ───────────────────────────────────────────────────────
// Polls for unbound PVCs with storageClassName=test-csi, creates the hostpath
// directory via CreateVolume and then posts a PV object to bind the claim.

type pvcList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			StorageClassName string `json:"storageClassName"`
			Resources        struct {
				Requests map[string]string `json:"requests"`
			} `json:"resources"`
			VolumeName string `json:"volumeName"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

func runProvisioner() {
	d := &driver{}
	log.Println("provisioner: started, watching for PVCs with storageClass=" + storageClass)
	for {
		time.Sleep(3 * time.Second)
		// Fetch all PVCs (no field selector to avoid encoding issues), filter in code
		data, code, err := apiDo("GET", "/api/v1/persistentvolumeclaims", nil)
		if err != nil {
			log.Printf("provisioner: list PVCs: %v", err)
			continue
		}
		if code != 200 {
			log.Printf("provisioner: list PVCs: HTTP %d", code)
			continue
		}
		var list pvcList
		if err := json.Unmarshal(data, &list); err != nil {
			log.Printf("provisioner: unmarshal: %v", err)
			continue
		}
		for _, pvc := range list.Items {
			if pvc.Spec.StorageClassName != storageClass {
				continue
			}
			// Only provision Pending PVCs
			if pvc.Status.Phase != "Pending" {
				continue
			}
			pvName := "test-csi-" + pvc.Metadata.Namespace + "-" + pvc.Metadata.Name
			storage := pvc.Spec.Resources.Requests["storage"]
			if storage == "" {
				storage = "1Gi"
			}

			// CreateVolume: make hostpath directory
			ctx := context.Background()
			cvResp, err := d.CreateVolume(ctx, &csi.CreateVolumeRequest{
				Name: pvName,
				CapacityRange: &csi.CapacityRange{RequiredBytes: 0},
				VolumeCapabilities: []*csi.VolumeCapability{
					{
						AccessType: &csi.VolumeCapability_Mount{
							Mount: &csi.VolumeCapability_MountVolume{},
						},
						AccessMode: &csi.VolumeCapability_AccessMode{
							Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
						},
					},
				},
			})
			if err != nil {
				log.Printf("provisioner: CreateVolume failed for %s/%s: %v", pvc.Metadata.Namespace, pvc.Metadata.Name, err)
				continue
			}

			// Create PV object
			pvJSON := fmt.Sprintf(`{
  "apiVersion": "v1",
  "kind": "PersistentVolume",
  "metadata": {"name": %q},
  "spec": {
    "capacity": {"storage": %q},
    "accessModes": ["ReadWriteOnce"],
    "persistentVolumeReclaimPolicy": "Delete",
    "storageClassName": %q,
    "csi": {
      "driver":       %q,
      "volumeHandle": %q
    },
    "claimRef": {
      "apiVersion": "v1",
      "kind":       "PersistentVolumeClaim",
      "namespace":  %q,
      "name":       %q,
      "uid":        %q
    }
  }
}`, pvName, storage, storageClass, driverName,
				cvResp.Volume.VolumeId,
				pvc.Metadata.Namespace, pvc.Metadata.Name, pvc.Metadata.UID)

			_, code, err := apiDo("POST", "/api/v1/persistentvolumes", []byte(pvJSON))
			if err != nil || (code != 200 && code != 201) {
				log.Printf("provisioner: create PV %s failed (code=%d): %v", pvName, code, err)
			} else {
				log.Printf("provisioner: created PV %s for PVC %s/%s", pvName, pvc.Metadata.Namespace, pvc.Metadata.Name)
			}
		}
	}
}

// ── main ───────────────────────────────────────────────────────────────────────

func serveCSI() {
	if err := os.MkdirAll(filepath.Dir(csiSock), 0750); err != nil {
		log.Fatalf("mkdir csi dir: %v", err)
	}
	os.Remove(csiSock)
	lis, err := net.Listen("unix", csiSock)
	if err != nil {
		log.Fatalf("csi listen: %v", err)
	}
	srv := grpc.NewServer()
	d := &driver{}
	csi.RegisterIdentityServer(srv, d)
	csi.RegisterControllerServer(srv, d)
	csi.RegisterNodeServer(srv, d)
	log.Printf("CSI gRPC server listening on %s", csiSock)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("csi serve: %v", err)
	}
}

func serveRegistrar() {
	dir := filepath.Dir(regSock)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Fatalf("mkdir reg dir: %v", err)
	}
	os.Remove(regSock)
	lis, err := net.Listen("unix", regSock)
	if err != nil {
		log.Fatalf("reg listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterRegistrationServer(srv, &registrar{})
	log.Printf("Registration server listening on %s", regSock)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("reg serve: %v", err)
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	if err := os.MkdirAll(volumeRoot, 0750); err != nil {
		log.Fatalf("mkdir volumeRoot: %v", err)
	}
	// Ensure registry dir exists before creating socket
	os.MkdirAll(strings.TrimSuffix(regSock, filepath.Base(regSock)), 0750)

	go serveCSI()
	go serveRegistrar()
	go runProvisioner()

	// block forever
	select {}
}
