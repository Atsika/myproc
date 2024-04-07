package myproc

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetDosHeader returns the IMAGE_DOS_HEADER of a module
func GetDosHeader(module unsafe.Pointer) *IMAGE_DOS_HEADER {
	return (*IMAGE_DOS_HEADER)(module)
}

// GetNtHeaders returns the IMAGE_NT_HEADERS of a module
func GetNtHeaders(module unsafe.Pointer) *IMAGE_NT_HEADERS {
	dosHdrs := GetDosHeader(unsafe.Pointer(module))
	return (*IMAGE_NT_HEADERS)(unsafe.Add(unsafe.Pointer(module), dosHdrs.E_lfanew))
}

// GetDataDirectory returns the IMAGE_DATA_DIRECTORY of a module specified by the entry index
func GetDataDirectory(module unsafe.Pointer, entry int) *IMAGE_DATA_DIRECTORY {
	ntHdrs := GetNtHeaders(module)
	return (*IMAGE_DATA_DIRECTORY)(unsafe.Pointer(&ntHdrs.OptionalHeader.DataDirectory[entry]))
}

// ImageFirstSection returns the first section by parsing NT headers
func ImageFirstSection(ntHdrs *IMAGE_NT_HEADERS) *IMAGE_SECTION_HEADER {
	return (*IMAGE_SECTION_HEADER)(unsafe.Pointer((uintptr(unsafe.Pointer(ntHdrs)) + unsafe.Offsetof(ntHdrs.OptionalHeader) + uintptr(ntHdrs.FileHeader.SizeOfOptionalHeader))))
}

// GetSectionHeader returns the IMAGE_SECTION_HEADER specified by the section name for the given module or nil if the section is not found
func GetSectionHeader(module unsafe.Pointer, sectionName string) *IMAGE_SECTION_HEADER {
	ntHdrs := GetNtHeaders(module)
	section := ImageFirstSection(ntHdrs)

	for i := uint16(0); i < ntHdrs.FileHeader.NumberOfSections; i++ {
		if windows.BytePtrToString((*byte)(unsafe.Pointer(&section.Name))) == sectionName {
			return section
		}
		section = (*IMAGE_SECTION_HEADER)(unsafe.Add(unsafe.Pointer(section), unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
	}

	return nil
}
