package main

import (
	"fmt"

	"github.com/atsika/myproc"
)

func main() {
	// Look for the function AddDllDirectory in kernel32.dll (forward: api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory)
	kernel32 := myproc.NewDLL("kernel32.dll")
	AddDllDirectory := myproc.NewProc(kernel32, "AddDllDirectory")

	// Print in which DLL the function is located, the function name and its address
	fmt.Printf("%s -> %s (%#2x)", AddDllDirectory.Name, AddDllDirectory.Dll.Name, AddDllDirectory.Addr())

	// Output: AddDllDirectory -> kernelbase.dll (0x7ffb2be113a0)
}
