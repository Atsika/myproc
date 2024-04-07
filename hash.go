package myproc

import "strings"

var Hash = fnv1a

// fnv1a hashing algorithm
func fnv1a(str string) uint32 {
	str = strings.ToLower(str)
	var hash uint32 = 0x811c9dc5
	for i := 0; i < len(str); i++ {
		hash ^= uint32(str[i])
		hash *= 0x01000193
	}
	return hash
}
