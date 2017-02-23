//
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"fmt"
	"net"

	hyper "github.com/clearcontainers/container-vm-agent/api"
	"github.com/vishvananda/netlink"
)

func findLinkFromHwAddr(hwAddr net.HardwareAddr) (netlink.Link, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Index starts at 0, that's why we can initialize it at -1
	// to identify a case where we didn't find the interface.
	index := -1
	for _, iface := range ifaces {
		if iface.HardwareAddr.String() == hwAddr.String() {
			index = iface.Index
			break
		}
	}

	if index == -1 {
		return nil, fmt.Errorf("Could not find the link corresponding to HwAddr '%s'", hwAddr.String())
	}

	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return nil, err
	}

	return link, nil
}

func setupInterfaces(ifaces []hyper.NetIface) error {
	// Loopback interface
	loIface := hyper.NetIface{
		Name:    loName,
		IPAddr:  loIPAddr,
		NetMask: loNetMask,
	}

	ifaces = append(ifaces, loIface)

	for _, iface := range ifaces {
		var link netlink.Link
		if iface.HwAddr.String() != "" {
			// Find the interface link from its hardware address
			var err error
			link, err := findLinkFromHwAddr(iface.HwAddr)
			if err != nil {
				return err
			}

			// Rename it
			if err := netlink.LinkSetName(link, iface.Name); err != nil {
				return err
			}
		} else {
			// Find the interface link from its name
			var err error
			link, err = netlink.LinkByName(iface.Name)
			if err != nil {
				return err
			}
		}

		// Add an IP address
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", iface.IPAddr, iface.NetMask))
		if err != nil {
			return fmt.Errorf("Could not parse the IP address %s: %s", iface.IPAddr, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}

		// Set the link up
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}

	return nil
}

func setupRoutes(routes []hyper.Route) error {
	for _, route := range routes {
		_, dst, err := net.ParseCIDR(route.Dest)
		if err != nil {
			return fmt.Errorf("Could not parse route destination %s: %s", route.Dest, err)
		}

		netRoute := &netlink.Route{
			Dst: dst,
			Src: net.ParseIP(route.Src),
			Gw:  net.ParseIP(route.Gateway),
		}

		if err := netlink.RouteAdd(netRoute); err != nil {
			return fmt.Errorf("Could not add route dest(%s)/src(%s)/gw(%s)/dev(%s): %s", route.Dest, route.Src, route.Gateway, route.Device, err)
		}
	}

	return nil
}

func setupDNS(dns []string) error {
	return nil
}

func (p *pod) setupNetwork() error {
	if err := setupInterfaces(p.network.Interfaces); err != nil {
		return fmt.Errorf("Could not setup network interfaces: %s", err)
	}

	if err := setupRoutes(p.network.Routes); err != nil {
		return fmt.Errorf("Could not setup network routes: %s", err)
	}

	if err := setupDNS(p.network.DNS); err != nil {
		return fmt.Errorf("Could not setup network DNS: %s", err)
	}

	return nil
}

func removeInterfaces(ifaces []hyper.NetIface) error {
	// Loopback interface
	loIface := hyper.NetIface{
		Name:    loName,
		IPAddr:  loIPAddr,
		NetMask: loNetMask,
	}

	ifaces = append(ifaces, loIface)

	for _, iface := range ifaces {
		// Find the interface by name
		link, err := netlink.LinkByName(iface.Name)
		if err != nil {
			return err
		}

		// Set the link down
		if err := netlink.LinkSetDown(link); err != nil {
			return err
		}

		// Remove the IP address
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", iface.IPAddr, iface.NetMask))
		if err != nil {
			return fmt.Errorf("Could not parse the IP address %s: %s", iface.IPAddr, err)
		}
		if err := netlink.AddrDel(link, addr); err != nil {
			return err
		}
	}

	return nil
}

func removeRoutes(routes []hyper.Route) error {
	for _, route := range routes {
		_, dst, err := net.ParseCIDR(route.Dest)
		if err != nil {
			return fmt.Errorf("Could not parse route destination %s: %s", route.Dest, err)
		}

		netRoute := &netlink.Route{
			Dst: dst,
			Src: net.ParseIP(route.Src),
			Gw:  net.ParseIP(route.Gateway),
		}

		if err := netlink.RouteDel(netRoute); err != nil {
			return fmt.Errorf("Could not remove route dest(%s)/src(%s)/gw(%s)/dev(%s): %s", route.Dest, route.Src, route.Gateway, route.Device, err)
		}
	}

	return nil
}

func removeDNS(dns []string) error {
	return nil
}

func (p *pod) removeNetwork() error {
	if err := removeInterfaces(p.network.Interfaces); err != nil {
		return fmt.Errorf("Could not remove network interfaces: %s", err)
	}

	if err := removeRoutes(p.network.Routes); err != nil {
		return fmt.Errorf("Could not remove network routes: %s", err)
	}

	if err := removeDNS(p.network.DNS); err != nil {
		return fmt.Errorf("Could not remove network DNS: %s", err)
	}

	return nil
}
