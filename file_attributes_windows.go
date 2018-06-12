package attributes

import (
	"fmt"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	advapiLib, _                                           = syscall.LoadLibrary("advapi32.dll")
	setFileSecurity, _                                     = syscall.GetProcAddress(advapiLib, "SetFileSecurityW")
	getNamedSecurityInfo, _                                = syscall.GetProcAddress(advapiLib, "GetNamedSecurityInfoW")
	convertSidToStringSid, _                               = syscall.GetProcAddress(advapiLib, "ConvertSidToStringSidW")
	convertSecurityDescriptorToStringSecurityDescriptor, _ = syscall.GetProcAddress(advapiLib, "ConvertSecurityDescriptorToStringSecurityDescriptorW")
	convertStringSecurityDescriptorToSecurityDescriptor, _ = syscall.GetProcAddress(advapiLib, "ConvertStringSecurityDescriptorToSecurityDescriptorW")
	kernel32Lib, _                                         = syscall.LoadLibrary("Kernel32.dll")
	localFree, _                                           = syscall.GetProcAddress(kernel32Lib, "LocalFree")
)

const (
	fileSecurityInfo             uint32 = 1
	ownerSecurityInformation     uint32 = 1
	groupSecurityInformation     uint32 = 2
	daclSecurityInformation      uint32 = 4
	attributeSecurityInformation uint32 = 32
	desiredSecurityInformation          = ownerSecurityInformation | groupSecurityInformation | daclSecurityInformation | attributeSecurityInformation
	sddlRevision                 uint32 = 1
	securityDescriptorTag               = "securityDescriptor"
	ownerTag                            = "owner"
	groupTag                            = "group"
	daclTag                             = "dacl"
)

type WidowsFileAttributes struct {
	windowsFileName []uint16
}

func NewWidowsFileAttributes(filePath string) (*WidowsFileAttributes, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("WidowsFileAttributes only works on Windows")
	}

	windowsFileName, err := syscall.UTF16FromString(filePath)

	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to Windows equivalent", filePath)
	}

	return &WidowsFileAttributes{windowsFileName: windowsFileName}, nil
}

func (attributes *WidowsFileAttributes) GetSecurityDescriptor() (map[string]string, error) {
	securityInfoMap, err := attributes.securityInfo()

	if err != nil {
		return nil, err
	}

	securityDescriptor := securityInfoMap[securityDescriptorTag]

	if securityDescriptor == nil {
		return nil, fmt.Errorf("failed to get a security descriptor from a call to GetNamedSecurityInfoW")
	}

	defer freeWindowsSecurityDescriptor(securityDescriptor)

	securityDescriptorString, err := securityDescriptorString(securityDescriptor)

	if err != nil {
		return nil, err
	}

	ownerSid := securityInfoMap[ownerTag]

	if ownerSid == nil {
		return nil, fmt.Errorf("failed to get owner sid from a call to GetNamedSecurityInfoW")
	}

	ownerSidString, err := stringFromSid(ownerSid)

	if err != nil {
		return nil, err
	}

	groupSid := securityInfoMap[groupTag]

	if groupSid == nil {
		return nil, fmt.Errorf("failed to get group sid from a call to GetNamedSecurityInfoW")
	}

	groupSidString, err := stringFromSid(groupSid)

	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	result[daclTag] = securityDescriptorString
	result[ownerTag] = ownerSidString
	result[groupTag] = groupSidString

	return result, nil
}

func (attributes *WidowsFileAttributes) securityInfo() (map[string]*byte, error) {
	if len(attributes.windowsFileName) == 0 {
		return nil, fmt.Errorf("file name is not set")
	}

	var numArgs uintptr = 8
	var securityDescriptor *byte = nil
	var ownerSid *byte = nil
	var groupSid *byte = nil

	returnVal, _, callErr := syscall.Syscall9(
		uintptr(getNamedSecurityInfo),
		numArgs,
		uintptr(unsafe.Pointer(&attributes.windowsFileName[0])),
		uintptr(fileSecurityInfo),
		uintptr(desiredSecurityInformation),
		uintptr(unsafe.Pointer(&ownerSid)),
		uintptr(unsafe.Pointer(&groupSid)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&securityDescriptor)),
		0,
	)

	if returnVal != 0 {
		return nil, callErr
	}

	result := make(map[string]*byte)

	result[securityDescriptorTag] = securityDescriptor
	result[ownerTag] = ownerSid
	result[groupTag] = groupSid

	return result, nil
}

func freeWindowsSecurityDescriptor(securityDescriptor *byte) uint32 {
	var numArgs = 1

	returnVal, _, _ := syscall.Syscall(
		uintptr(localFree),
		uintptr(numArgs),
		uintptr(unsafe.Pointer(securityDescriptor)),
		0,
		0,
	)

	return uint32(returnVal)
}

func securityDescriptorString(securityDescriptor *byte) (string, error) {
	var numArgs uintptr = 5
	var securityDescriptorUnicodeText *uint16 = nil
	var securityDescriptorUnicodeTextLen uint32 = 0

	// Turn the security descriptor into a string we can save in an NFI-compatible way
	returnVal, _, callErr := syscall.Syscall6(
		uintptr(convertSecurityDescriptorToStringSecurityDescriptor),
		numArgs,
		uintptr(unsafe.Pointer(securityDescriptor)),
		uintptr(sddlRevision),
		uintptr(desiredSecurityInformation),
		uintptr(unsafe.Pointer(&securityDescriptorUnicodeText)),
		uintptr(unsafe.Pointer(&securityDescriptorUnicodeTextLen)),
		0,
	)

	if returnVal == 0 {
		return "", fmt.Errorf("call to ConvertSecurityDescriptorToStringSecurityDescriptor failed with error: %v", callErr)
	}

	defer freeWindowsUnicodeText(securityDescriptorUnicodeText)

	return unicodeStringToString(securityDescriptorUnicodeText), nil
}

func freeWindowsUnicodeText(allocatedMemory *uint16) uint32 {
	var numArgs = 1

	returnVal, _, _ := syscall.Syscall(
		uintptr(localFree),
		uintptr(numArgs),
		uintptr(unsafe.Pointer(allocatedMemory)),
		0,
		0,
	)

	return uint32(returnVal)
}

func unicodeStringToString(unicodeString *uint16) string {
	if unicodeString != nil {
		unicodeStringSlice := make([]uint16, 0)
		for unicodeStringCursor := uintptr(unsafe.Pointer(unicodeString)); ; unicodeStringCursor += 2 {
			unicodeCharacter := *(*uint16)(unsafe.Pointer(unicodeStringCursor))
			if unicodeCharacter == 0 {
				return string(utf16.Decode(unicodeStringSlice))
			}
			unicodeStringSlice = append(unicodeStringSlice, unicodeCharacter)
		}
	}
	return ""
}

func stringFromSid(sid *byte) (string, error) {
	var numArgs uintptr = 2
	var sidUnicodeText *uint16 = nil

	returnVal, _, callErr := syscall.Syscall(
		uintptr(convertSidToStringSid),
		numArgs,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&sidUnicodeText)),
		0,
	)

	if returnVal == 0 {
		return "", callErr
	}

	defer freeWindowsUnicodeText(sidUnicodeText)

	return unicodeStringToString(sidUnicodeText), nil
}

func (attributes *WidowsFileAttributes) SetSecurityDescriptor(securityDescriptorString string) error {
	windowsSecurityDescriptorText, err := syscall.UTF16FromString(securityDescriptorString)

	if err != nil {
		return fmt.Errorf("failed to convert %s to Windows equivalent", securityDescriptorString)
	}

	var numArgs uintptr = 4
	var securityDescriptor *byte = nil
	var securityDescriptorSize uint32 = 0

	returnVal, _, callErr := syscall.Syscall6(
		uintptr(convertStringSecurityDescriptorToSecurityDescriptor),
		numArgs,
		uintptr(unsafe.Pointer(&windowsSecurityDescriptorText[0])),
		uintptr(sddlRevision),
		uintptr(unsafe.Pointer(&securityDescriptor)),
		uintptr(unsafe.Pointer(&securityDescriptorSize)),
		0,
		0,
	)

	if returnVal == 0 {
		return fmt.Errorf("call to ConvertStringSecurityDescriptorToSecurityDescriptor failed with error: %v", callErr)
	}

	defer freeWindowsSecurityDescriptor(securityDescriptor)

	numArgs = 3

	if len(attributes.windowsFileName) == 0 {
		return fmt.Errorf("file name is not set")
	}

	returnVal, _, callErr = syscall.Syscall(
		uintptr(setFileSecurity),
		numArgs,
		uintptr(unsafe.Pointer(&attributes.windowsFileName[0])),
		uintptr(desiredSecurityInformation),
		uintptr(unsafe.Pointer(securityDescriptor)),
	)

	if returnVal == 0 {
		return fmt.Errorf("call to SetFileSecurity failed with error: %v", callErr)
	}

	return nil
}

