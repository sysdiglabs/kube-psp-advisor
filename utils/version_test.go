package utils

import (
	"testing"
)

func TestCompareVersionVersion(t *testing.T) {
	v1 := "v1.12.1"
	v2 := "v1.11.2"

	ret, err := CompareVersion(v1, v2)
	if err != nil {
		t.Fatal(err)
	}

	if !ret {
		t.Fatal("Version comparison failed.")
	}
}
