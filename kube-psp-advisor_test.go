package main

import (
	"sort"
	"strings"
	"testing"
)

var (
	workloadDir = "./test-yaml"

	expectedYamls = []string{
		"test-yaml/base-busybox.yaml",
		"test-yaml/psp-grant.yaml",
		"test-yaml/srcYamls/busy-box.yaml",
		"test-yaml/srcYamls/nginx.yaml",
		"test-yaml/targetYamls/busy-box.yaml",
		"test-yaml/targetYamls/nginx.yaml",
		"test-yaml/targetYamls/web-deployment.yaml",
		"test-yaml/test-opa.yaml",
	}
)

func TestReadYamls(t *testing.T) {
	yamls, err := getWorkLoadYamls(workloadDir)

	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(yamls)

	if strings.Join(yamls, ";") != strings.Join(expectedYamls, ";") {
		t.Fatalf("expected: %s\nactual: %s\n", expectedYamls, yamls)
	}
}
