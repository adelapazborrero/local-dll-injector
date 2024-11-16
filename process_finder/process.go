package process

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/JamesHovious/w32"
)

func getProcessName(id uint32) string {
	snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, id)
	if snapshot == w32.ERROR_INVALID_HANDLE {
		return "<UNKNOWN>"
	}
	defer w32.CloseHandle(snapshot)

	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))
	if w32.Module32First(snapshot, &me) {
		serviceName := w32.UTF16PtrToString(&me.SzModule[0])
		return strings.ToLower(serviceName)
	}

	return "<UNKNOWN>"
}

func listProcesses() []uint32 {
	sz := uint32(1000)
	procs := make([]uint32, sz)
	var bytesReturned uint32
	if w32.EnumProcesses(procs, sz, &bytesReturned) {
		return procs[:int(bytesReturned)/4]
	}
	return []uint32{}
}

func FindByName(name string) (uint32, error) {
	for _, pid := range listProcesses() {
		if getProcessName(pid) == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("Process given not found")
}
