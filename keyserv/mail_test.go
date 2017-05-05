// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"testing"
)

func TestMailerValidateConfig(t *testing.T) {
	m := Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	m = Mailer{Recipients: []string{"a@b"}, FromAddress: "me@a", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	m = Mailer{Recipients: []string{}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25a"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: ""}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
}

func TestMailerSend(t *testing.T) {
	m := Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.Send("abc", "123"); err == nil {
		t.Fatal("did not error")
	}
}

func TestMailerReadFromSysconfig(t *testing.T) {
	m := Mailer{}
	mailConf := GetDefaultKeySvcConf()
	m.ReadFromSysconfig(mailConf)
	if len(m.Recipients) != 0 || m.FromAddress != "" || m.AgentAddressPort != "" {
		t.Fatal(m)
	}
	mailConf.SetStrArray("EMAIL_RECIPIENTS", []string{"a", "b"})
	mailConf.Set("EMAIL_FROM_ADDRESS", "c")
	mailConf.Set("EMAIL_AGENT_AND_PORT", "d")
	m.ReadFromSysconfig(mailConf)
	if len(m.Recipients) != 2 || m.FromAddress != "c" || m.AgentAddressPort != "d" {
		t.Fatal(m)
	}
}
