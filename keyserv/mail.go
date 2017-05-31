// cryptctl - Copyright (c) 2017 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"errors"
	"fmt"
	"github.com/HouzuoGuo/cryptctl/sys"
	"net/smtp"
	"strconv"
	"strings"
)

const (
	SRV_CONF_MAIL_RECIPIENTS     = "EMAIL_RECIPIENTS"
	SRV_CONF_MAIL_FROM_ADDR      = "EMAIL_FROM_ADDRESS"
	SRV_CONF_MAIL_AGENT_AND_PORT = "EMAIL_AGENT_AND_PORT"
	SRV_CONF_MAIL_AGENT_USERNAME = "EMAIL_AGENT_USERNAME"
	SRV_CONF_MAIL_AGENT_PASSWORD = "EMAIL_AGENT_PASSWORD"
)

// Return true only if both at-sign and full-stop are in the string.
func IsMailAddressComplete(addr string) bool {
	return strings.Contains(addr, "@")
}

// Parameters for sending notification emails.
type Mailer struct {
	Recipients       []string // List of Email addresses that receive notifications
	FromAddress      string   // FROM address of the notifications
	AgentAddressPort string   // Address and port number of mail transportation agent for sending notifications
	AuthUsername     string   // (Optional) Username for plain authentication, if the SMTP server requires it.
	AuthPassword     string   // (Optional) Password for plain authentication, if the SMTP server requires it.
}

// Return true only if all mail parameters are present.
func (mail *Mailer) ValidateConfig() error {
	errs := make([]error, 0, 0)
	// Validate recipient addresses
	if mail.Recipients == nil || len(mail.Recipients) == 0 {
		errs = append(errs, errors.New("Recipient address is empty"))
	} else {
		for _, addr := range mail.Recipients {
			if !IsMailAddressComplete(addr) {
				errs = append(errs, fmt.Errorf("Recipient address \"%s\" must contain an at-sign", addr))
			}
		}
	}
	// Validate from address
	if mail.FromAddress == "" {
		errs = append(errs, errors.New("Mail-from address is empty"))
	} else if !IsMailAddressComplete(mail.FromAddress) {
		errs = append(errs, fmt.Errorf("Mail-from address \"%s\" must contain an at-sign", mail.FromAddress))
	}
	// Validate MTA
	if mail.AgentAddressPort == "" {
		errs = append(errs, errors.New("Mail agent (address and port) is empty"))
	} else {
		colon := strings.Index(mail.AgentAddressPort, ":")
		if colon == -1 {
			errs = append(errs, fmt.Errorf("Mail agent \"%s\" must contain address and port number", mail.FromAddress))
		} else if _, err := strconv.Atoi(mail.AgentAddressPort[colon+1:]); err != nil {
			errs = append(errs, fmt.Errorf("Failed to parse integer from port number from \"%s\"", mail.FromAddress))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}

// Deliver an email to all recipients.
func (mail *Mailer) Send(subject, text string) error {
	if mail.Recipients == nil || len(mail.Recipients) == 0 {
		return fmt.Errorf("No recipient specified for mail \"%s\"", subject)
	}
	var auth smtp.Auth
	if mail.AuthUsername != "" {
		auth = smtp.PlainAuth("", mail.AuthUsername, mail.AuthPassword, mail.AgentAddressPort)
	}
	// Construct appropriate mail headers
	mailBody := fmt.Sprintf("MIME-Version: 1.0\r\nContent-type: text/plain; charset=utf-8\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		mail.FromAddress, strings.Join(mail.Recipients, ", "), subject, text)
	return smtp.SendMail(mail.AgentAddressPort, auth, mail.FromAddress, mail.Recipients, []byte(mailBody))
}

// Read mail settings from keys in sysconfig file.
func (mail *Mailer) ReadFromSysconfig(sysconf *sys.Sysconfig) {
	mail.Recipients = sysconf.GetStringArray(SRV_CONF_MAIL_RECIPIENTS, []string{})
	mail.FromAddress = sysconf.GetString(SRV_CONF_MAIL_FROM_ADDR, "")
	mail.AgentAddressPort = sysconf.GetString(SRV_CONF_MAIL_AGENT_AND_PORT, "")
	mail.AuthUsername = sysconf.GetString(SRV_CONF_MAIL_AGENT_USERNAME, "")
	mail.AuthPassword = sysconf.GetString(SRV_CONF_MAIL_AGENT_PASSWORD, "")
}
