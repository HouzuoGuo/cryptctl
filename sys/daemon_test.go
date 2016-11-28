package sys

import "testing"

func TestSystemctl(t *testing.T) {
	if err := SystemctlEnableStart("does-not-exist"); err == nil {
		t.Fatal(err)
	}
	if err := SystemctlEnableRestart("does-not-exist"); err == nil {
		t.Fatal(err)
	}
	if err := SystemctlDisableStop("does-not-exist"); err == nil {
		t.Fatal(err)
	}
	if SystemctlIsRunning("does-not-exist") {
		t.Fatal("cannot be running")
	}
	if !SystemctlIsRunning("systemd-journald.service") {
		t.Fatal("journald is not running")
	}
}
