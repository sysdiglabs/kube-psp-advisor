package types

import (
	"fmt"
	"sort"
)

type PortRangeList []*PortRange

type PortRange struct {
	Min int32
	Max int32
}

func NewPortRange(min, max int32) *PortRange {
	return &PortRange{
		Min: min,
		Max: max,
	}
}

func (pl PortRangeList) Consolidate() PortRangeList {
	newPortRangeList := PortRangeList{}

	max := pl.GetMax()

	min := pl.GetMin()

	if min == -1 {
		return newPortRangeList
	}

	tmpPl := make(PortRangeList, max+1)

	for _, pr := range pl {
		tmpPl[pr.Min] = pr
	}

	pr := tmpPl[min]
	i := min

	for ; i <= max; i++ {
		if tmpPl[i] != nil {
			pr.Max = tmpPl[i].Max
		} else {
			// there is a break
			newPortRangeList = append(newPortRangeList, pr)

			// look for next port range
			for {
				i++
				if i > max {
					break
				}

				if tmpPl[i] != nil {
					pr = tmpPl[i]
					break
				}
			}
		}
	}

	newPortRangeList = append(newPortRangeList, pr)

	sort.Sort(newPortRangeList)

	return newPortRangeList
}

func (pl PortRangeList) GetMin() int32 {
	min := int32(-1)

	for _, pr := range pl {
		if pr != nil {
			if min == int32(-1) {
				min = pr.Min
			}

			if pr.Min < min {
				min = pr.Min
			}
		}
	}

	return min
}

func (pl PortRangeList) GetMax() int32 {
	max := int32(-1)

	for _, pr := range pl {
		if pr != nil {
			if pr.Max > max {
				max = pr.Max
			}
		}
	}

	return max
}

func (pl PortRangeList) String() string {
	ret := "["

	for idx, pr := range pl {
		ret += fmt.Sprintf("{%d %d}", pr.Min, pr.Max)

		if idx < len(pl)-1 {
			ret += ", "
		}
	}

	ret += "]"

	return ret
}

func (pl PortRangeList) Less(i, j int) bool { return pl[i].Min < pl[j].Min }

func (pl PortRangeList) Len() int { return len(pl) }

func (pl PortRangeList) Swap(i, j int) { pl[j], pl[i] = pl[i], pl[j] }
