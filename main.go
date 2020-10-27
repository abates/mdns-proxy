package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"docker.io/go-docker"
	"docker.io/go-docker/api/types"
)

func GetBridgeInterfaces() ([]net.Interface, error) {
	ints, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	sysInterfaces := make(map[string]net.Interface)

	for _, i := range ints {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			_, n, _ := net.ParseCIDR(a.String())
			sysInterfaces[n.String()] = i
		}
	}

	cli, err := docker.NewEnvClient()
	if err != nil {
		return nil, err
	}

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	matchedInterfaces := make(map[string]net.Interface)
	for _, container := range containers {
		for _, network := range container.NetworkSettings.Networks {
			nr, err := cli.NetworkInspect(context.Background(), network.NetworkID, types.NetworkInspectOptions{})
			if err != nil {
				return nil, err
			}
			if nr.Driver == "bridge" {
				for _, config := range nr.IPAM.Config {
					if i, found := sysInterfaces[config.Subnet]; found {
						matchedInterfaces[i.Name] = i
					}
				}
			}
		}
	}
	interfaces := []net.Interface{}
	for _, i := range matchedInterfaces {
		interfaces = append(interfaces, i)
	}
	return interfaces, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [def interface] <fwd interface> ...\n", os.Args[0])
		os.Exit(1)
	}

	proxy := New()

	fixAddress := ""
	defName := os.Args[1]
	if strings.Contains(defName, ":") {
		parts := strings.Split(defName, ":")
		defName = parts[0]
		fixAddress = parts[1]
	}

	defInterface, err := net.InterfaceByName(defName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to lookup interface %s: %v", os.Args[1], err)
		os.Exit(2)
	}
	proxy.AddInterface(defInterface, ForwardQuestions(), ForwardAnswers())

	for _, name := range os.Args[2:] {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to lookup interface %s: %v", name, err)
			os.Exit(3)
		}
		if fixAddress == "" {
			proxy.AddInterface(iface, ForwardAnswers())
		} else {
			proxy.AddInterface(iface, ForwardAnswers(), FixAddress(fixAddress))
		}
	}

	proxy.Run()
}
