//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"f-forti/internal/netcfg"
)

// Local (non-GPO) NRPT. The DNS client service watches this key.
const (
	nrptLocal  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptGPO    = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	nrptPrefix = "FVPN-"
	// ConfigOptions: 0x8 = use GenericDNSServers for this namespace.
	nrptConfigGenericDNS = 0x8
)

func writeNRPT(rules []netcfg.DNSRule) (warnings []string, err error) {
	if n := gpoRuleCount(); n > 0 {
		warnings = append(warnings, fmt.Sprintf("%d NRPT rules are set by Group Policy; Windows may ignore local NRPT rules and internal names may not resolve", n))
	}
	if err := deleteNRPT(); err != nil {
		return warnings, err
	}
	for i, r := range rules {
		var names []string
		for _, d := range r.Domains {
			// ".example.test" matches names under it, "example.test" the name itself.
			names = append(names, "."+d, d)
		}
		var servers []string
		for _, s := range r.Servers {
			servers = append(servers, s.String())
		}
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, fmt.Sprintf(`%s\%s%d`, nrptLocal, nrptPrefix, i+1), registry.SET_VALUE)
		if err != nil {
			return warnings, err
		}
		errs := []error{
			k.SetDWordValue("Version", 2),
			k.SetStringsValue("Name", names),
			k.SetStringValue("GenericDNSServers", strings.Join(servers, "; ")),
			k.SetDWordValue("ConfigOptions", nrptConfigGenericDNS),
			k.SetStringValue("IPSECCARestriction", ""),
		}
		k.Close()
		if err := errors.Join(errs...); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

// deleteNRPT removes every rule we own (by prefix).
func deleteNRPT() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		if strings.HasPrefix(n, nrptPrefix) {
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptLocal+`\`+n); err != nil && !errors.Is(err, registry.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func gpoRuleCount() int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGPO, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	return len(names)
}
