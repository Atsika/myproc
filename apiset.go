package myproc

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Resolve API Set V6
// Thanks to these references:
// https://lucasg.github.io/2017/10/15/Api-set-resolution/
// https://github.com/ajkhoury/ApiSet

// ResolveApiSet returns the name of the real function host.
func ResolveApiSet(apiSet string, parentName string) string {
	apiNamespace := GetApiSetNamespace()

	// api-ms-win-core-apiquery-l1-1-0.dll -> api-ms-win-core-apiquery-l1-1
	apiToResolve := apiSet[:strings.LastIndex(apiSet, "-")]

	entry := apiNamespace.SearchForApiSet(apiToResolve)
	if entry == nil {
		return ""
	}

	hostLibEntry := new(API_SET_VALUE_ENTRY)

	if entry.ValueCount > 1 && parentName != "" {
		hostLibEntry = apiNamespace.SearchForApiSetHost(entry, parentName)
	} else if entry.ValueCount > 0 {
		hostLibEntry = apiNamespace.GetNsValueEntry(entry, 0)
	}

	name := apiNamespace.GetApiSetValueEntryValue(hostLibEntry)

	return name
}

// GetApiSetNamespace returns an API_SET_NAMESPACE structure from PEB
func GetApiSetNamespace() *API_SET_NAMESPACE {
	return GetPEB().ApiSetMap
}

func (apins *API_SET_NAMESPACE) SearchForApiSet(apiToResolve string) *API_SET_NAMESPACE_ENTRY {
	lower := strings.ToLower(apiToResolve)
	hashKey := uint32(0)

	for i := 0; i < len(lower); i++ {
		hashKey = hashKey*apins.HashFactor + uint32(lower[i])
	}

	// binary search
	low := uint32(0)
	middle := uint32(0)
	high := apins.Count - 1

	hashEntry := new(API_SET_HASH_ENTRY)

	for high >= low {
		middle = (high + low) >> 1
		hashEntry = apins.GetHashEntry(middle)

		if hashKey < hashEntry.Hash {
			high = middle - 1
		} else if hashKey > hashEntry.Hash {
			low = middle + 1
		} else {
			break
		}
	}

	// not found
	if high < low {
		return nil
	}

	foundEntry := apins.GetNsEntry(hashEntry.Index)
	name := apins.GetValueName(foundEntry)

	// equivalent to truncate after last hyphen
	if strings.HasPrefix(lower, strings.ToLower(name)) {
		return nil
	}

	return foundEntry
}

func (apins *API_SET_NAMESPACE) SearchForApiSetHost(entry *API_SET_NAMESPACE_ENTRY, apiToResolve string) *API_SET_VALUE_ENTRY {

	foundEntry := apins.GetNsValueEntry(entry, 0)

	high := entry.ValueCount - 1
	if high == 0 {
		return foundEntry
	}

	apiSetHostEntry := new(API_SET_VALUE_ENTRY)

	for low := uint32(1); low <= high; {
		middle := (low + high) >> 1
		apiSetHostEntry = apins.GetNsValueEntry(entry, middle)

		switch name := apins.GetValueEntryName(apiSetHostEntry); {
		case apiToResolve == name:
			return apins.GetNsValueEntry(entry, middle)
		case apiToResolve < name:
			high = middle - 1
		case apiToResolve > name:
			low = middle + 1
		}
	}

	return nil
}

func (apins *API_SET_NAMESPACE) GetHashEntry(index uint32) *API_SET_HASH_ENTRY {
	return (*API_SET_HASH_ENTRY)(unsafe.Add(unsafe.Pointer(apins), apins.HashOffset+index*uint32(unsafe.Sizeof(API_SET_HASH_ENTRY{}))))
}

func (apins *API_SET_NAMESPACE) GetNsEntry(index uint32) *API_SET_NAMESPACE_ENTRY {
	return (*API_SET_NAMESPACE_ENTRY)(unsafe.Add(unsafe.Pointer(apins), apins.EntryOffset+index*uint32(unsafe.Sizeof(API_SET_NAMESPACE_ENTRY{}))))
}

func (apins *API_SET_NAMESPACE) GetValueName(entry *API_SET_NAMESPACE_ENTRY) string {
	name := (*uint16)(unsafe.Add(unsafe.Pointer(apins), entry.NameOffset))
	return windows.UTF16PtrToString(name)
}

func (apins *API_SET_NAMESPACE) GetNsValueEntry(entry *API_SET_NAMESPACE_ENTRY, index uint32) *API_SET_VALUE_ENTRY {
	return (*API_SET_VALUE_ENTRY)(unsafe.Add(unsafe.Pointer(apins), entry.ValueOffset+index*uint32(unsafe.Sizeof(API_SET_VALUE_ENTRY{}))))
}

func (apins *API_SET_NAMESPACE) GetApiSetValueEntryValue(entry *API_SET_VALUE_ENTRY) string {
	value := (*uint16)(unsafe.Add(unsafe.Pointer(apins), entry.ValueOffset))
	name := unsafe.Slice(value, entry.ValueLength/2)
	return windows.UTF16ToString(name)
}

func (apins *API_SET_NAMESPACE) GetValueEntryName(entry *API_SET_VALUE_ENTRY) string {
	value := (*uint16)(unsafe.Add(unsafe.Pointer(apins), entry.NameOffset))
	name := unsafe.Slice(value, entry.NameLength/2)
	return windows.UTF16ToString(name)
}
