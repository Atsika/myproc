package main

import (
	"fmt"

	"github.com/atsika/myproc"
)

func main() {
	kernel32 := myproc.NewDLL("kernel32.dll")
	fmt.Printf("[string] kernel32 => %#2x\n", kernel32.Handle)

	kernel32 = myproc.NewDLL(uint32(0xa3e6f6c3))
	fmt.Printf("[hash]   kernel32 => %#2x\n", kernel32.Handle)

	GetProcessHeap := myproc.NewProc(kernel32, "GetProcessHeap")
	fmt.Printf("[string]  GetProcessHeap => %#2x\n", GetProcessHeap.Addr())

	GetProcessHeap = myproc.NewProc(kernel32, uint16(0x2d5))
	fmt.Printf("[ordinal] GetProcessHeap => %#2x\n", GetProcessHeap.Addr())

	GetProcessHeap = myproc.NewProc(kernel32, uint32(0x967288f2))
	fmt.Printf("[hash]    GetProcessHeap => %#2x\n", GetProcessHeap.Addr())

	hHeap, _, _ := GetProcessHeap.Call()
	fmt.Printf("Heap Handle: %#2x\n", hHeap)
}
