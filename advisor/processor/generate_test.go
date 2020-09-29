package processor

import "testing"

func TestGetFieldSelector(t *testing.T) {
	p := Processor{
		excludeNamespaces: []string{
			"ns1",
			"",
			"ns3",
			"ns4",
			"",
		},
	}

	expected := "metadata.namespace!=ns1,metadata.namespace!=ns3,metadata.namespace!=ns4"

	if p.getFieldSelector() != expected {
		t.Fatalf("expected field selector to match %s", expected)
	}
}
