package filters

import (
	"encoding/binary"
	"unsafe"
	"regexp"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type ContainerFilter struct {
	*BPFStringFilter
}

func NewContainerFilter(mapName string) *ContainerFilter {
	return &ContainerFilter{
		BPFStringFilter: NewBPFStringFilter(mapName),
	}
}

func (f *ContainerFilter) UpdateBPF(bpfModule *bpf.Module, cts *containers.Containers, policyID uint) error {
	
	if !f.Enabled() {
		return nil
	}

	filterMap, err := bpfModule.GetMap(f.mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	filterVal := make([]byte, 16)

	parseFilter := func(filter string) (string, string) {
		re := regexp.MustCompile(`(\w+):([\w\-_]+)`)
		match := re.FindStringSubmatch(filter)
		if len(match) != 3 {
			return "", ""
		}
		return match[1], match[2]
	}

	cgroupIDsNotEqual := make(map[uint32]bool)

	// first initialize notEqual values since equality should take precedence
	for _, notEqualFilter := range f.NotEqual() {
		label, value := parseFilter(notEqualFilter)
		if label == "" || value  == "" {
			return errfmt.Errorf("Invalid label or value in filter clause")
		}

		cgroupIDs := cts.FindContainerCgroupID32LSB(label, value)
		for _, cgroupID := range cgroupIDs {
			cgroupIDsNotEqual[cgroupID] = true
			var equalInPolicies, equalitySetInPolicies uint64
			curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupID))
			if err == nil {
				equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
				equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
			}
	
			// filterNotEqual == 0, so clear n bitmask bit
			utils.ClearBit(&equalInPolicies, policyID)
			utils.SetBit(&equalitySetInPolicies, policyID)
	
			binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
			binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
			if err = filterMap.Update(unsafe.Pointer(&cgroupID), unsafe.Pointer(&filterVal[0])); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	// now - setup equality filters
	for _, equalFilter := range f.Equal() {
		label, value := parseFilter(equalFilter)
		if label == "" || value  == "" {
			return errfmt.Errorf("Invalid label or value in filter clause")
		}

		cgroupIDs := cts.FindContainerCgroupID32LSB(label, value)
		for _, cgroupID := range cgroupIDs {
			if cgroupIDsNotEqual[cgroupID] {
				continue
			}
			var equalInPolicies, equalitySetInPolicies uint64
			curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupID))
			if err == nil {
				equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
				equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
			}
	
			// filterEqual == 1, so set n bitmask bit
			utils.SetBit(&equalInPolicies, policyID)
			utils.SetBit(&equalitySetInPolicies, policyID)
	
			binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
			binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
			if err = filterMap.Update(unsafe.Pointer(&cgroupID), unsafe.Pointer(&filterVal[0])); err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}
