package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/JamesHovious/w32"
	process "github.com/adelapazborrero/injector/process_finder"
)

func main() {
	processName := flag.String("p", "", "Process name that will be use to inject the dell")
	dllPath := flag.String("d", "", "Dll to inject into the process")

	flag.Parse()

	if *processName == "" || *dllPath == "" {
		fmt.Println("Process name and Dll path are required")
		fmt.Println("Example: injector.exe -p \"explorer.exe\" -d \"mydll.dll\"")
		return
	}

	if _, err := os.Stat(*dllPath); err != nil {
		fmt.Println("Path of given dll does not exist")
		return
	}

	// Get the process id
	procID, err := process.FindByName(*processName)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Open the found process
	hProc, handleErr := w32.OpenProcess(w32.PROCESS_ALL_ACCESS, false, uint32(procID))
	if handleErr != nil {
		fmt.Println("handleErr:", handleErr)
	}

	// Load kernel32
	kernel32DLL, dllLoadErr := syscall.LoadLibrary("kernel32.dll")
	if dllLoadErr != nil {
		fmt.Println("dllLoadErr:", dllLoadErr)
	}
	addr, addrErr := syscall.GetProcAddress(syscall.Handle(kernel32DLL), "LoadLibraryA")
	if addrErr != nil {
		fmt.Println("addrErr:", addrErr)
	}

	// Allocate memory into the found process
	arg, allocErr := w32.VirtualAllocEx(hProc, 0, len(*dllPath)*2, w32.MEM_RESERVE|w32.MEM_COMMIT, w32.PAGE_READWRITE)
	if allocErr != nil {
		fmt.Println("allocErr:", allocErr)
	}

	// Write the dll into the allocated memory
	writeErr := w32.WriteProcessMemory(hProc, uint32(arg), []byte(*dllPath), 0)
	if writeErr != nil {
		fmt.Println("writeErr:", writeErr)
	}

	// create thread out of the injected DLL to run it
	_, _, threadErr := w32.CreateRemoteThread(hProc, nil, 0, uint32(addr), arg, 0)
	if threadErr != nil {
		fmt.Println("threadErr:", threadErr)
	}
}
