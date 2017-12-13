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

	hyper "github.com/clearcontainers/agent/api"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func findLinkFromHwAddr(netHandle *netlink.Handle, hwAddr string) (netlink.Link, error) {
	links, err := netHandle.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		lAttrs := link.Attrs()
		if lAttrs == nil {
			continue
		}

		if lAttrs.HardwareAddr.String() == hwAddr {
			return link, nil
		}
	}

	return nil, fmt.Errorf("Could not find the link corresponding to HwAddr %q", hwAddr)
}

func getStrNetMaskFromIPv4(ip net.IP) (string, error) {
	ipMask := ip.DefaultMask()
	if ipMask == nil {
		return "", fmt.Errorf("Could not deduce IP network mask from %v", ip)
	}

	ipMaskInt, _ := ipMask.Size()

	return fmt.Sprintf("%d", ipMaskInt), nil
}

func setupInterface(netHandle *netlink.Handle, iface hyper.NetIface, link netlink.Link) error {
	lAttrs := link.Attrs()
	if lAttrs != nil && (lAttrs.Flags&net.FlagUp) == net.FlagUp {
		// The link is up, makes sure we get it down before
		// doing any modification.
		if err := netHandle.LinkSetDown(link); err != nil {
			return err
		}
	}

	// Rename the link
	if iface.Name != "" {
		if err := netHandle.LinkSetName(link, iface.Name); err != nil {
			return err
		}
	}

	// Set MTU
	if iface.MTU > 0 {
		if err := netHandle.LinkSetMTU(link, iface.MTU); err != nil {
			return err
		}
	}

	for _, ipAddress := range iface.IPAddresses {
		netMask := ipAddress.NetMask

		// Determine the network mask if not provided in the expected format
		netMaskIP := net.ParseIP(netMask)
		if netMaskIP != nil {
			ip := net.ParseIP(ipAddress.IPAddr)
			if ip == nil {
				return fmt.Errorf("Invalid IP address %q", ipAddress.IPAddr)
			}

			tmpNetMask, err := getStrNetMaskFromIPv4(ip)
			if err != nil {
				return err
			}

			netMask = tmpNetMask
		}

		// Add an IP address
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ipAddress.IPAddr, netMask))
		if err != nil {
			return fmt.Errorf("Could not parse the IP address %s: %v", ipAddress.IPAddr, err)
		}
		if err := netHandle.AddrAdd(link, addr); err != nil {
			return err
		}
	}

	// Set the link up
	return netHandle.LinkSetUp(link)
}

func setupInterfaces(netHandle *netlink.Handle, ifaces []hyper.NetIface) error {
	for _, iface := range ifaces {
		var link netlink.Link

		fieldLogger := agentLog.WithFields(logrus.Fields{
			"mac-address":    iface.HwAddr,
			"interface-name": iface.Name,
		})

		if iface.HwAddr != "" {
			fieldLogger.Info("Getting interface from MAC address")

			// Find the interface link from its hardware address
			var err error
			link, err = findLinkFromHwAddr(netHandle, iface.HwAddr)
			if err != nil {
				return err
			}
		} else if iface.Name != "" {
			fieldLogger.Info("Getting interface from name")

			// Find the interface link from its name
			var err error
			link, err = netHandle.LinkByName(iface.Name)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Interface HwAddr and Name are both empty")
		}

		fieldLogger.WithField("link", fmt.Sprintf("%+v", link)).Infof("Link found")

		if err := setupInterface(netHandle, iface, link); err != nil {
			return err
		}
	}

	return nil
}

func setupRoutes(netHandle *netlink.Handle, routes *[]hyper.Route) error {
	initRouteList, err := netHandle.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var finalRouteList []hyper.Route
	defer func() {
		// Update the route list.
		*routes = finalRouteList
	}()

	for _, route := range *routes {
		var dst *net.IPNet
		var err error

		// Find link index from route's device name
		link, err := netHandle.LinkByName(route.Device)
		if err != nil {
			return fmt.Errorf("Could not find link from device name %s: %v", route.Device, err)
		}

		linkAttrs := link.Attrs()
		if linkAttrs == nil {
			return fmt.Errorf("Could not find link index for device %v", route.Device)
		}

		if route.Dest != "" && route.Dest != "default" {
			destIP := net.ParseIP(route.Dest)
			if destIP != nil {
				// Add the missing network mask
				netMask, err := getStrNetMaskFromIPv4(destIP)
				if err != nil {
					return err
				}

				route.Dest += "/" + netMask
			}

			existingRoute := findExistingDestRoute(linkAttrs.Index, initRouteList, route.Dest)
			if existingRoute != nil {
				agentLog.WithField("route-destination", route.Dest).Info("Route destination already exists, deleting")
				if err := netHandle.RouteDel(existingRoute); err != nil {
					return fmt.Errorf("Could not delete route dest(%s)/src(%s)/gw(%s)/devIndex(%d): %v",
						existingRoute.Dst, existingRoute.Src, existingRoute.Gw, linkAttrs.Index, err)
				}
			}

			_, dst, err = net.ParseCIDR(route.Dest)
			if err != nil {
				return fmt.Errorf("Could not parse route destination %s: %v", route.Dest, err)
			}
		}

		netRoute := &netlink.Route{
			LinkIndex: linkAttrs.Index,
			Dst:       dst,
			Src:       net.ParseIP(route.Src),
			Gw:        net.ParseIP(route.Gateway),
		}

		if err := netHandle.RouteReplace(netRoute); err != nil {
			return fmt.Errorf("Could not add/replace route dest(%s)/src(%s)/gw(%s)/dev(%s): %v",
				route.Dest, route.Src, route.Gateway, route.Device, err)
		}

		// Only save the routes that we are actually adding. Don't add
		// skipped routes already existing, otherwise it could cause
		// issues when trying to remove them.
		finalRouteList = append(finalRouteList, route)
	}

	return nil
}

func findExistingDestRoute(ifaceIdx int, routeList []netlink.Route, dest string) *netlink.Route {
	for _, route := range routeList {
		if route.LinkIndex == ifaceIdx && route.Dst.String() == dest {
			return &route
		}
	}

	return nil
}

func setupDNS(netHandle *netlink.Handle, dns []string) error {
	return nil
}

func (p *pod) setupNetwork() error {
	netHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer netHandle.Delete()

	if err := setupInterfaces(netHandle, p.network.Interfaces); err != nil {
		return fmt.Errorf("Could not setup network interfaces: %v", err)
	}

	if err := setupRoutes(netHandle, &p.network.Routes); err != nil {
		return fmt.Errorf("Could not setup network routes: %v", err)
	}

	if err := setupDNS(netHandle, p.network.DNS); err != nil {
		return fmt.Errorf("Could not setup network DNS: %v", err)
	}

	return nil
}

func removeInterfaces(netHandle *netlink.Handle, ifaces []hyper.NetIface) error {
	for _, iface := range ifaces {
		// Find the interface by name
		link, err := netHandle.LinkByName(iface.Name)
		if err != nil {
			return err
		}

		// Set the link down
		if err := netHandle.LinkSetDown(link); err != nil {
			return err
		}

		for _, ipAddress := range iface.IPAddresses {
			netMask := ipAddress.NetMask

			// Determine the network mask if not provided in the expected format
			netMaskIP := net.ParseIP(netMask)
			if netMaskIP != nil {
				ip := net.ParseIP(ipAddress.IPAddr)
				if ip == nil {
					return fmt.Errorf("Invalid IP address %q", ipAddress.IPAddr)
				}

				tmpNetMask, err := getStrNetMaskFromIPv4(ip)
				if err != nil {
					return err
				}

				netMask = tmpNetMask
			}

			// Remove the IP address
			addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ipAddress.IPAddr, netMask))
			if err != nil {
				return fmt.Errorf("Could not parse the IP address %s: %v", ipAddress.IPAddr, err)
			}
			if err := netHandle.AddrDel(link, addr); err != nil {
				return err
			}
		}
	}

	return nil
}

func removeRoutes(netHandle *netlink.Handle, routes []hyper.Route) error {
	for _, route := range routes {
		var dst *net.IPNet
		var err error

		if route.Dest != "" && route.Dest != "default" {
			destIP := net.ParseIP(route.Dest)
			if destIP != nil {
				// Add the missing network mask
				netMask, err := getStrNetMaskFromIPv4(destIP)
				if err != nil {
					return err
				}

				route.Dest += "/" + netMask
			}

			_, dst, err = net.ParseCIDR(route.Dest)
			if err != nil {
				return fmt.Errorf("Could not parse route destination %s: %v", route.Dest, err)
			}
		}

		netRoute := &netlink.Route{
			Dst: dst,
			Src: net.ParseIP(route.Src),
			Gw:  net.ParseIP(route.Gateway),
		}

		if err := netHandle.RouteDel(netRoute); err != nil {
			return fmt.Errorf("Could not remove route dest(%s)/src(%s)/gw(%s)/dev(%s): %v", route.Dest, route.Src, route.Gateway, route.Device, err)
		}
	}

	return nil
}

func removeDNS(netHandle *netlink.Handle, dns []string) error {
	return nil
}

func (p *pod) removeNetwork() error {
	netHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer netHandle.Delete()

	if err := removeDNS(netHandle, p.network.DNS); err != nil {
		return fmt.Errorf("Could not remove network DNS: %v", err)
	}

	if err := removeRoutes(netHandle, p.network.Routes); err != nil {
		return fmt.Errorf("Could not remove network routes: %v", err)
	}

	if err := removeInterfaces(netHandle, p.network.Interfaces); err != nil {
		return fmt.Errorf("Could not remove network interfaces: %v", err)
	}

	return nil
}
