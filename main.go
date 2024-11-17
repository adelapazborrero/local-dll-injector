package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/adelapazborrero/injector/process"
	"golang.org/x/sys/windows"
)

func main() {
	processName := flag.String("p", "", "Process name to inject the DLL")
	dllPath := flag.String("d", "", "DLL to inject into the process")

	flag.Parse()

	if *processName == "" || *dllPath == "" {
		fmt.Println("Process name and DLL path are required")
		fmt.Println("Example: injector.exe -p explorer.exe -d mydll.dll")
		return
	}

	_, err := os.Stat(*dllPath)
	if err != nil {
		fmt.Println("Path of given DLL does not exist")
		return
	}

	// Get the process ID
	procID, err := process.FindByName(*processName)
	if err != nil {
		fmt.Println(err)
		return
	}
	dPath := *dllPath
	pId := uintptr(procID)

	kernel32 := windows.NewLazyDLL("kernel32.dll")

	processHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pId),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Process opened")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	allocatedMemory, _, err := VirtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(dPath)+1), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Printf("failed to allocate memory: %s\n", err.Error())
	}
	fmt.Println("Memory allocated")

	bPtrDpath, err := windows.BytePtrFromString(dPath)
	if err != nil {
		log.Fatal(err)
	}

	Zero := uintptr(0)
	err = windows.WriteProcessMemory(processHandle, allocatedMemory, bPtrDpath, uintptr(len(dPath)+1), &Zero)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("DLL path written")

	LoadLibAddr, err := syscall.GetProcAddress(syscall.Handle(kernel32.Handle()), "LoadLibraryA")
	if err != nil {
		log.Fatal(err)
	}

	tHandle, _, _ := kernel32.NewProc("CreateRemoteThread").Call(uintptr(processHandle), 0, 0, LoadLibAddr, allocatedMemory, 0, 0)
	defer syscall.CloseHandle(syscall.Handle(tHandle))
	fmt.Println("DLL Injected")

}
