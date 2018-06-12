package attributes

import (
	"testing"
	"os/exec"
	"strings"
)

const fileName = ".\\aFile.txt"

func TestGettingSecurityDescriptorString(t *testing.T) {
	metadata, err := NewWidowsFileAttributes(fileName)
	if err != nil {
		t.Fatalf("NewWidowsFileAttributes(fileName) failed with error :%v", err)
	}

	securityInfoMap, err := metadata.GetSecurityDescriptor()
	if err != nil {
		t.Fatalf("metadata.GetSecurityDescriptor() failed with error :%v", err)
	}

	if securityInfoMap == nil {
		t.Fatal("metadata.GetSecurityDescriptor() returned nil")
	}

	if len(securityInfoMap[ownerTag]) == 0 {
		t.Fatal("securityInfoMap[ownerTag] was empty")
	}

	if len(securityInfoMap[groupTag]) == 0 {
		t.Fatal("securityInfoMap[groupTag] was empty")
	}

	if len(securityInfoMap[daclTag]) == 0 {
		t.Fatal("securityInfoMap[daclTag] was empty")
	}
}

func TestSettingSecurityDescriptorString(t *testing.T) {
	metadata, err := NewWidowsFileAttributes(fileName)
	if err != nil {
		t.Fatalf("NewWidowsFileAttributes(fileName) failed with error :%v", err)
	}

	securityInfoMap, err := metadata.GetSecurityDescriptor()
	if err != nil {
		t.Fatal("GetSecurityDescriptor failed")
	}

	securityDescriptorString := securityInfoMap[daclTag]

	icaclsCommand := exec.Command("icacls", fileName, "/deny", "Everyone:(WD)")
	err = icaclsCommand.Run()
	if err != nil {
		t.Fatal("Failure resetting file security.")
	}

	securityInfoMapAfterCallingIcacls, err := metadata.GetSecurityDescriptor()
	if err != nil {
		t.Fatal("GetSecurityDescriptor failed")
	}

	securityDescriptorAfterCallingIcacls := securityInfoMapAfterCallingIcacls[daclTag]

	if securityDescriptorAfterCallingIcacls == securityDescriptorString {
		t.Fatal("securityDescriptorAfterCallingIcacls should not equal securityDescriptorString")
	}

	err = metadata.SetSecurityDescriptor(securityDescriptorString)
	if err != nil {
		t.Fatal("SetSecurityDescriptor failed")
	}

	securityInfoMapAfterResetting, err := metadata.GetSecurityDescriptor()
	if err != nil {
		t.Fatal("GetSecurityDescriptor failed")
	}

	securityDescriptorAfterResetting := securityInfoMapAfterResetting[daclTag]

	if strings.Compare(securityDescriptorAfterResetting, securityDescriptorString) != 0 {
		t.Fatal("securityDescriptorAfterResetting should equal securityDescriptorString")
	}
}

