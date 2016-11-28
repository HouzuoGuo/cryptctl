package keyrpc

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
	msg := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, text)
	if err := smtp.SendMail(mail.AgentAddressPort, nil, mail.FromAddress, mail.Recipients, []byte(msg)); err != nil {
		return fmt.Errorf("Send: failed to send email to \"%v\" - %v", mail.Recipients, err)
	}
	return nil
}

// Read mail settings from keys in sysconfig file.
func (mail *Mailer) ReadFromSysconfig(sysconf *sys.Sysconfig) {
	mail.Recipients = sysconf.GetStringArray(SRV_CONF_MAIL_RECIPIENTS, []string{})
	mail.FromAddress = sysconf.GetString(SRV_CONF_MAIL_FROM_ADDR, "")
	mail.AgentAddressPort = sysconf.GetString(SRV_CONF_MAIL_AGENT_AND_PORT, "")
}
