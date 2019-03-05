package utils

import (
	"github.com/hashicorp/go-version"
)

// CompareVersion compare two versions
func CompareVersion(v1, v2 string) (bool, error) {
	version1, err := version.NewVersion(v1)

	if err != nil {
		return false, err
	}

	version2, err := version.NewVersion(v2)

	if err != nil {
		return false, err
	}

	return version1.GreaterThan(version2), nil
}
