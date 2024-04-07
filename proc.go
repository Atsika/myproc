package myproc

import (
	"reflect"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sizeofUint16 = unsafe.Sizeof(uint16(0))
	sizeofUint32 = unsafe.Sizeof(uint32(0))
)

// NewProc is the reimplementation of GetProcAddress using binary search (3x faster) with a linear search fallback.
// It implements search by name, ordinal or hash.
func NewProc[T ~string | ~uint16 | ~uint32](dll *windows.DLL, procedure T) *windows.Proc {

	if dll == nil || dll.Handle == 0 {
		return nil
	}

	var procName string
	var procAddr uintptr
	// In case this is a forwarded function
	var parent string

	switch reflect.TypeOf(procedure).Kind() {
	case reflect.String:
		procName = any(procedure).(string)
	}

	proc := new(windows.Proc)
	proc.Dll = dll

	module := unsafe.Pointer(dll.Handle)
	dataDir := GetDataDirectory(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Add(module, dataDir.VirtualAddress))

	procAddr = ResolveFunctionAddr(dll, procedure)

	// Check if this is a forwarded function
	for IsForwardedFunction(procAddr, exportDir, dataDir.Size) {
		forwardName := windows.BytePtrToString((*byte)(unsafe.Pointer(procAddr)))
		forward := strings.Split(forwardName, ".")

		// Check if it starts with api or ext
		if strings.HasPrefix(forward[0], "api-") || strings.HasPrefix(forward[0], "ext-") {
			host := ResolveApiSet(forward[0], parent)
			// Forwarded again ?
			if !strings.HasPrefix(host, "api-") && !strings.HasPrefix(host, "ext-") {
				parent = host
			}

			// Set new dll
			proc.Dll = NewDLL(host)
			module = unsafe.Pointer(proc.Dll.Handle)
			dataDir = GetDataDirectory(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
			exportDir = (*IMAGE_EXPORT_DIRECTORY)(unsafe.Add(module, dataDir.VirtualAddress))
			// Resolve again
			procAddr = ResolveFunctionAddr(proc.Dll, forward[1])
		} else {
			procAddr = ResolveFunctionAddr(NewDLL(forward[0]+".dll"), forward[1])
		}
	}

	if procAddr != 0 {
		// Set proc name
		if procName != "" {
			proc.Name = procName
		} else {
			proc.Name = ResolveFunctionName(proc.Dll, procedure)
		}
		goto Found
	}

	return nil

Found:
	// trick to set unexported addr field in windows.Proc structure
	addr := reflect.ValueOf(proc).Elem().FieldByName("addr")
	reflect.NewAt(addr.Type(), unsafe.Pointer(addr.UnsafeAddr())).Elem().Set(reflect.ValueOf(procAddr))

	return proc
}

// ResokveFunctionAddr returns the address of a function. Search by name, ordinal or hash.
func ResolveFunctionAddr[T ~string | ~uint16 | ~uint32](dll *windows.DLL, procedure T) uintptr {

	if dll == nil || dll.Handle == 0 {
		return 0
	}

	var procName string
	var procOrdinal uint16
	var procHash uint32
	var procAddr uintptr

	switch reflect.TypeOf(procedure).Kind() {
	case reflect.String:
		procName = any(procedure).(string)
	case reflect.Uint16:
		procOrdinal = any(procedure).(uint16)
	case reflect.Uint32:
		procHash = any(procedure).(uint32)
	}

	if procHash == 0 && procName != "" {
		procHash = Hash(strings.ToLower(procName))
	}

	module := unsafe.Pointer(dll.Handle)
	dataDir := GetDataDirectory(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Add(module, dataDir.VirtualAddress))

	addrOfFunctions := unsafe.Add(module, exportDir.AddressOfFunctions)
	addrOfNames := unsafe.Add(module, exportDir.AddressOfNames)
	addrOfNameOrdinals := unsafe.Add(module, exportDir.AddressOfNameOrdinals)

	// ordinal search
	if procOrdinal != 0 {
		procOrdinal = procOrdinal - uint16(exportDir.Base)
		rva := *(*uint32)(unsafe.Add(addrOfFunctions, procOrdinal*uint16(sizeofUint32)))
		procAddr = uintptr(module) + uintptr(rva)
	}

	// binary search
	if procName != "" {
		left := uintptr(0)
		right := uintptr(exportDir.NumberOfNames - 1)

		for left != right {
			middle := left + ((right - left) >> 1)
			currentName := windows.BytePtrToString((*byte)(unsafe.Add(module, *(*uint32)(unsafe.Add(addrOfNames, middle*sizeofUint32)))))
			if Hash(currentName) == procHash {
				index := *(*uint16)(unsafe.Add(addrOfNameOrdinals, middle*sizeofUint16))
				procAddr = uintptr(module) + uintptr(*(*uint32)(unsafe.Add(addrOfFunctions, index*uint16(sizeofUint32))))
				return procAddr
			} else if currentName < procName {
				left = middle + 1
			} else {
				right = middle - 1
			}
		}
	}

	// linear search
	if procAddr == 0 {
		for i := uintptr(0); i < uintptr(exportDir.NumberOfNames); i++ {
			currentName := windows.BytePtrToString((*byte)(unsafe.Add(module, *(*uint32)(unsafe.Add(addrOfNames, i*sizeofUint32)))))
			if Hash(currentName) == procHash {
				index := *(*uint16)(unsafe.Add(addrOfNameOrdinals, i*sizeofUint16))
				procAddr = uintptr(module) + uintptr(*(*uint32)(unsafe.Add(addrOfFunctions, index*uint16(sizeofUint32))))
				return procAddr
			}
		}
	}

	return 0
}

// ResolveFunctionName returns the name of a function. Search by ordinal or hash. string is only used to comply with generics.
func ResolveFunctionName[T ~string | ~uint16 | ~uint32](dll *windows.DLL, procedure T) string {
	var procOrdinal uint16
	var procHash uint32

	switch reflect.TypeOf(procedure).Kind() {
	case reflect.Uint16:
		procOrdinal = any(procedure).(uint16)
	case reflect.Uint32:
		procHash = any(procedure).(uint32)
	case reflect.String: // This should never happened
		return ""
	}

	module := unsafe.Pointer(dll.Handle)
	dataDir := GetDataDirectory(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Add(module, dataDir.VirtualAddress))

	addrOfNames := unsafe.Add(module, exportDir.AddressOfNames)
	addrOfNameOrdinals := unsafe.Add(module, exportDir.AddressOfNameOrdinals)

	if procOrdinal != 0 {
		// Map each function name to an ordinal (inspired from PE-bear)
		ordinalToName := make(map[uint16]uintptr)
		nameOrdRVA := addrOfNameOrdinals
		for i := uintptr(0); i < uintptr(exportDir.NumberOfNames); i++ {
			nameOrdinal := *(*uint16)(unsafe.Add(addrOfNameOrdinals, i*sizeofUint16))
			ordinalToName[nameOrdinal] = i
			nameOrdRVA = unsafe.Add(nameOrdRVA, sizeofUint16)
		}

		// If a name exist for this ordinal, retrieve it
		nameIndex, ok := ordinalToName[procOrdinal]
		if ok {
			return windows.BytePtrToString((*byte)(unsafe.Add(module, *(*uint32)(unsafe.Add(addrOfNames, nameIndex*sizeofUint32)))))
		}
	}

	// linear search
	if procHash != 0 {
		for i := uintptr(0); i < uintptr(exportDir.NumberOfNames); i++ {
			currentName := windows.BytePtrToString((*byte)(unsafe.Add(module, *(*uint32)(unsafe.Add(addrOfNames, i*sizeofUint32)))))
			if Hash(currentName) == procHash {
				return currentName
			}
		}
	}

	return ""
}

// IsForwardedFunction checks if the proc is valid, if not it's a forwarded function
func IsForwardedFunction(procAddr uintptr, exportDir *IMAGE_EXPORT_DIRECTORY, exportDirSize uint32) bool {
	if procAddr >= uintptr(unsafe.Pointer(exportDir)) && procAddr < uintptr(unsafe.Pointer(exportDir))+uintptr(exportDirSize) {
		return true
	}
	return false
}
