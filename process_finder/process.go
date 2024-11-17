package process

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getProcessName(id uint32) string {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, id)
	if err == windows.ERROR_INVALID_HANDLE {
		return "<UNKNOWN>"
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	err = windows.Module32First(snapshot, &me)
	if err != nil {
		return "<UNKNOWN>"
	}

	// serviceName := w32.UTF16PtrToString(&me.SzModule[0])
	serviceName := windows.UTF16PtrToString(&me.Module[0])
	return strings.ToLower(serviceName)

}

func listProcesses() []uint32 {
	sz := uint32(1000)
	procs := make([]uint32, sz)
	var bytesReturned uint32

	err := windows.EnumProcesses(procs, &bytesReturned)
	if err != nil {
		return []uint32{}
	}
	return procs[:int(bytesReturned)/4]
}

func FindByName(name string) (uint32, error) {
	for _, pid := range listProcesses() {
		if getProcessName(pid) == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("Process given not found")
}
