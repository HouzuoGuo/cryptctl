// cryptctl - Copyright (c) 2016 SUSE Linux GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package sys

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Make a best effort at determining this computer's host name (FQDN preferred) and IP address.
func GetHostnameAndIP() (hostname string, ip string) {
	var err error
	if hostname, err = os.Hostname(); err != nil {
		log.Printf("GetHostname: cannot determine system host name - %v", err) // non-fatal
	}
	// Determine FQDN and IP address if possible
	hostnameAddresses, err := net.LookupIP(hostname)
	if err == nil {
		var addressText string
		for _, hostnameAddress := range hostnameAddresses {
			ipAddrBytes, err := hostnameAddress.MarshalText()
			addressText = string(ipAddrBytes)
			if err != nil {
				continue
			}
			fqdn, err := net.LookupAddr(string(addressText))
			if err == nil && len(fqdn) > 0 {
				hostname = fqdn[0]
				if ip == "" {
					ip = string(addressText)
				}
				break
			}
		}
		// Even if FQDN cannot be determined, the IP address should still be recorded.
		if ip == "" {
			ip = addressText
		}
	}
	hostname = strings.TrimSuffix(hostname, ".")
	ip = strings.TrimSuffix(ip, ".")
	return
}

// Call systemctl start on the service.
func SystemctlStart(svc string) error {
	if out, err := exec.Command("systemctl", "start", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to start service \"%s\" -  %v %s", svc, err, out)
	}
	return nil
}

// Cal systemctl enable and then systemctl start on the service.
func SystemctlEnableStart(svc string) error {
	if out, err := exec.Command("systemctl", "enable", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to enable service \"%s\" -  %v %s", svc, err, out)
	}
	if out, err := exec.Command("systemctl", "start", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to start service \"%s\" -  %v %s", svc, err, out)
	}
	return nil
}

// Cal systemctl enable and then systemctl start on thing. Panic on error.
func SystemctlEnableRestart(svc string) error {
	if out, err := exec.Command("systemctl", "enable", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to enable service \"%s\" -  %v %s", svc, err, out)
	}
	if out, err := exec.Command("systemctl", "restart", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to restart service \"%s\" -  %v %s", svc, err, out)
	}
	return nil
}

// Cal systemctl to get main PID of a service. Return 0 on failure.
func SystemctlGetMainPID(svc string) (mainPID int) {
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", svc).CombinedOutput()
	if err != nil {
		return 0
	}
	idNum := regexp.MustCompile("[0-9]+").FindString(string(out))
	if idNum == "" {
		return 0
	}
	mainPID, err = strconv.Atoi(idNum)
	if err != nil {
		return 0
	}
	return
}

// Cal systemctl disable and then systemctl stop on thing. Panic on error.
func SystemctlDisableStop(svc string) error {
	if out, err := exec.Command("systemctl", "disable", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to disable service \"%s\" -  %v %s", svc, err, out)
	}
	if out, err := exec.Command("systemctl", "stop", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to stop service \"%s\" -  %v %s", svc, err, out)
	}
	return nil
}

// Return true only if systemctl suggests that the thing is running.
func SystemctlIsRunning(svc string) bool {
	if _, err := exec.Command("systemctl", "is-active", svc).CombinedOutput(); err == nil {
		return true
	}
	return false
}
