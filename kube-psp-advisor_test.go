package main

import (
	"sort"
	"strings"
	"testing"
)

var (
	workloadDir = "./test-yaml"

	expectedYamls = []string{"test-yaml/base-busybox.yaml", "test-yaml/psp-grant.yaml", "test-yaml/testSrcDir/testdir/busy-box.yaml", "test-yaml/testTargetDir/testdir/busy-box.yaml"}
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

func TestReadYamlFile(t *testing.T) {
	testYaml := "test-yaml/base-busybox.yaml"
	yamls, err := getWorkLoadYamls(testYaml)

	if err != nil {
		t.Fatal(err)
	}

	if len(yamls) != 1 && yamls[0] != "test-yaml/base-busybox.yaml" {
		t.Fatalf("expected: %s\nactual: %s\n", testYaml, yamls[0])
	}
}
