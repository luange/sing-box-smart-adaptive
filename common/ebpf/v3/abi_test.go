package v3

import (
	"testing"
	"unsafe"
)

func TestABISizes(t *testing.T) {
	// Must match abi.h _Static_assert values.
	assertSize(t, "Control", unsafe.Sizeof(Control{}), 32)
	assertSize(t, "PolicyValue", unsafe.Sizeof(PolicyValue{}), 20)
	assertSize(t, "FlowKey", unsafe.Sizeof(FlowKey{}), 40)
	assertSize(t, "FlowValue", unsafe.Sizeof(FlowValue{}), 24)
	assertSize(t, "DNSIPKey", unsafe.Sizeof(DNSIPKey{}), 20)
	assertSize(t, "DNSIPValue", unsafe.Sizeof(DNSIPValue{}), 40)
	assertSize(t, "LPM4Key", unsafe.Sizeof(LPM4Key{}), 8)
	assertSize(t, "LPM6Key", unsafe.Sizeof(LPM6Key{}), 20)
}

func assertSize(t *testing.T, name string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Fatalf("%s size=%d want %d", name, got, want)
	}
}

func TestValidateControl(t *testing.T) {
	if err := ValidateControl(Control{ABIVersion: ABIVersion}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateControl(Control{ABIVersion: 99}); err == nil {
		t.Fatal("expected abi mismatch")
	}
	if err := ValidateControl(Control{ABIVersion: ABIVersion, ActiveBank: 2}); err == nil {
		t.Fatal("expected bank error")
	}
}

func TestClampCapacity(t *testing.T) {
	if ClampCapacity(0, 8192, 65536) != 8192 {
		t.Fatal("default")
	}
	if ClampCapacity(100, 8192, 65536) != 100 {
		t.Fatal("value")
	}
	if ClampCapacity(999999, 8192, 65536) != 65536 {
		t.Fatal("max")
	}
}
