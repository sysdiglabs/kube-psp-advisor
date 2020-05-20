package types

import (
	"testing"
)

var (
	prList = PortRangeList{
		&PortRange{Min: 1, Max: 1},
		&PortRange{Min: 2, Max: 2},
		&PortRange{Min: 3, Max: 3},
		&PortRange{Min: 5, Max: 5},
		&PortRange{Min: 6, Max: 6},
		&PortRange{Min: 7, Max: 7},
		&PortRange{Min: 50, Max: 50},
		&PortRange{Min: 99, Max: 99},
	}

	expectedPrList = PortRangeList{
		&PortRange{Min: 1, Max: 3},
		&PortRange{Min: 5, Max: 7},
		&PortRange{Min: 50, Max: 50},
		&PortRange{Min: 99, Max: 99},
	}
)

func TestPortRange(t *testing.T) {
	newPrList := prList.Consolidate()

	if len(newPrList) != 4 {
		t.Errorf("length is not 3: %+v", newPrList)
	}

	for i := range expectedPrList {
		if newPrList[i].Min != expectedPrList[i].Min || newPrList[i].Max != expectedPrList[i].Max {
			t.Errorf("expected port range: %v; actual port range: %v", *expectedPrList[i], *newPrList[i])
		}
	}
}
