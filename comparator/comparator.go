package comparator

import (
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"k8s.io/api/policy/v1beta1"
)

type Comparator struct {
	escalationReport *types.EscalationReport
}

func NewComparator() (*Comparator, error) {
	return &Comparator{
		escalationReport: types.NewEscalationReport(),
	}, nil
}

func (c *Comparator) ComparePSP(psp1, psp2 v1beta1.PodSecurityPolicy) bool {
	c.escalationReport.GenerateEscalationReport(psp1, psp2)

	return c.escalationReport.NoChanges()
}
