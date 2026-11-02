package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// RPCMethod describes one Connect procedure exposed by the server.
type RPCMethod struct {
	Service    string
	Method     string
	Input      string
	Output     string
	FullMethod string
}

// ListRPCMethods enumerates every registered sso.v1 RPC. Because the generated
// descriptors are linked into the binary, this list is the authoritative
// coverage check for the CLI.
func ListRPCMethods() ([]RPCMethod, error) {
	var out []RPCMethod
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Package() != "sso.v1" {
			return true
		}
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				md := methods.Get(j)
				out = append(out, RPCMethod{
					Service:    string(svc.Name()),
					Method:     string(md.Name()),
					Input:      string(md.Input().Name()),
					Output:     string(md.Output().Name()),
					FullMethod: fmt.Sprintf("%s/%s", svc.FullName(), md.Name()),
				})
			}
		}
		return true
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("no sso.v1 RPC descriptors are registered")
	}
	return out, nil
}

// FindRPCMethod resolves "Service/Method" (or "Service.Method") to its
// descriptor.
func FindRPCMethod(name string) (protoreflect.ServiceDescriptor, protoreflect.MethodDescriptor, error) {
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	name = strings.ReplaceAll(name, ".", "/")
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("expected <Service>/<Method>, got %q", name)
	}
	svcName := parts[0]
	if !strings.Contains(svcName, ".") {
		svcName = "sso.v1." + svcName
	}
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svcName))
	if err != nil {
		return nil, nil, fmt.Errorf("unknown service %q: %w", parts[0], err)
	}
	svc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, nil, fmt.Errorf("%q is not a service", parts[0])
	}
	md := svc.Methods().ByName(protoreflect.Name(parts[1]))
	if md == nil {
		return nil, nil, fmt.Errorf("unknown method %q on %s", parts[1], parts[0])
	}
	return svc, md, nil
}

// DescribeRPC returns a JSON template containing every input field with its
// zero value, suitable for editing and passing back to CallRPC.
func DescribeRPC(name string) (string, error) {
	_, md, err := FindRPCMethod(name)
	if err != nil {
		return "", err
	}
	msg := dynamicpb.NewMessage(md.Input())
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
		UseProtoNames:   true,
	}.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// CallRPC invokes any unary sso.v1 RPC with a JSON-encoded request. It speaks
// the Connect unary JSON protocol directly so the request and response types
// can be resolved at runtime instead of compile time.
func CallRPC(ctx context.Context, cfg *config.Context, name string, data []byte) ([]byte, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint")
	}
	_, md, err := FindRPCMethod(name)
	if err != nil {
		return nil, err
	}

	reqMsg := dynamicpb.NewMessage(md.Input())
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, reqMsg); err != nil {
			return nil, fmt.Errorf("invalid request JSON: %w", err)
		}
	}
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(reqMsg)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(cfg.ServerEndpoint, "/") + "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Connect-Protocol-Version", "1")
	if cfg.UserAuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.UserAuthToken)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		var connectErr struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(payload, &connectErr) == nil && connectErr.Message != "" {
			return nil, fmt.Errorf("%s: %s", connectErr.Code, connectErr.Message)
		}
		return nil, fmt.Errorf("rpc failed (HTTP %d): %s", resp.StatusCode, truncate(string(payload), 300))
	}

	outMsg := dynamicpb.NewMessage(md.Output())
	if err := protojson.Unmarshal(payload, outMsg); err != nil {
		return nil, fmt.Errorf("invalid response JSON: %w", err)
	}
	return protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}.Marshal(outMsg)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
