package authorization

import (
	"net"
	"strings"

	"github.com/authelia/authelia/internal/configuration/schema"
	"github.com/authelia/authelia/internal/logging"
)

func selectMatchingNetworkGroups(networks []string, aclNetworks []schema.ACLNetwork) []schema.ACLNetwork {
	selectedNetworkGroups := []schema.ACLNetwork{}

	for _, network := range networks {
		for _, n := range aclNetworks {
			for _, ng := range n.Name {
				if network == ng {
					selectedNetworkGroups = append(selectedNetworkGroups, n)
				}
			}
		}
	}

	return selectedNetworkGroups
}

func parseCIDR(ip net.IP, network string) bool {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		logging.Logger().Errorf("Failed to parse network %s: %s", network, err)
	}

	if ipNet.Contains(ip) {
		return true
	}

	return false
}

// isIPMatching check whether user's IP is in one of the network ranges.
func isIPMatching(ip net.IP, networks []string, aclNetworks []schema.ACLNetwork) bool {
	// If no network is provided in the rule, we match any network
	if len(networks) == 0 {
		return true
	}

	matchingNetworkGroups := selectMatchingNetworkGroups(networks, aclNetworks)

	for _, network := range networks {
		switch {
		case ip.String() == network:
			return true
		case strings.Contains(network, "/"):
			if !parseCIDR(ip, network) {
				continue
			}

			return true
		case net.ParseIP(network) == nil && !strings.Contains(network, "/"):
			for _, n := range matchingNetworkGroups {
				for _, networks := range n.Networks {
					switch {
					case ip.String() == networks:
						return true
					case strings.Contains(networks, "/"):
						if !parseCIDR(ip, networks) {
							continue
						}

						return true
					}
				}
			}
		}
	}

	return false
}
