package main

import (
	"context"
	"encoding/json"
	"fmt"
	auth "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	hook "k8s.io/apiserver/pkg/util/webhook"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

func main() {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "status": map[string]bool{"allowed": false, "denied": true}})
	}))
	defer server.Close()
	scheme := runtime.NewScheme()
	auth.AddToScheme(scheme)
	cfg := server.Client()
	_ = cfg
	file, err := os.CreateTemp("", "owned-sar-client-go-*.json")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(map[string]interface{}{"apiVersion": "v1", "kind": "Config", "clusters": []interface{}{map[string]interface{}{"name": "fixture", "cluster": map[string]interface{}{"server": server.URL}}}, "contexts": []interface{}{map[string]interface{}{"name": "fixture", "context": map[string]interface{}{"cluster": "fixture"}}}, "current-context": "fixture"}); err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	config, err := hook.LoadKubeconfig(file.Name(), nil)
	if err != nil {
		panic(err)
	}
	config.Host = server.URL + "/v1/kubernetes/subjectaccessreviews"
	config.Timeout = 3 * time.Second
	gw, err := hook.NewGenericWebhook(scheme, serializer.NewCodecFactory(scheme), config, []schema.GroupVersion{auth.SchemeGroupVersion}, wait.Backoff{})
	if err != nil {
		panic(err)
	}
	res := gw.RestClient.Post().Body(&auth.SubjectAccessReview{}).Do(context.Background())
	if res.Error() != nil {
		panic(res.Error())
	}
	fmt.Println(<-seen)
}
