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

package api

import (
	"syscall"
)

// HyperCmd defines the command type.
type HyperCmd uint32

// Control command string IDs
const (
	VersionCmd HyperCmd = iota
	StartPodCmd
	GetPodDeprecatedCmd
	StopPodDeprecatedCmd
	DestroyPodCmd
	RestartContainerDeprecatedCmd
	ExecCmd
	FinishCmdDeprecatedCmd
	ReadyCmd
	AckCmd
	ErrorCmd
	WinsizeCmd
	PingCmd
	FinishPodDeprecatedCmd
	NextCmd
	WriteFileCmd
	ReadFileCmd
	NewContainerCmd
	KillContainerCmd
	OnlineCPUMemCmd
	SetupInterfaceCmd
	SetupRouteCmd
	RemoveContainerCmd
	PsContainerCmd
	ProcessAsyncEventCmd
)

var stringCmdList = map[HyperCmd]string{
	StartPodCmd:        "startpod",
	DestroyPodCmd:      "destroypod",
	NewContainerCmd:    "newcontainer",
	KillContainerCmd:   "killcontainer",
	RemoveContainerCmd: "removecontainer",
	ExecCmd:            "execcmd",
	ReadyCmd:           "ready",
	AckCmd:             "ack",
	ErrorCmd:           "error",
	PingCmd:            "ping",
	WinsizeCmd:         "winsize",
	PsContainerCmd:     "pscontainer",
}

// IPAddress describes an IP address and its network mask.
type IPAddress struct {
	IPAddr  string `json:"ipAddress"`
	NetMask string `json:"netMask"`
}

// NetIface describes a pod network interface.
type NetIface struct {
	Name        string      `json:"newDeviceName"`
	IPAddresses []IPAddress `json:"ipAddresses"`
	MTU         int         `json:"mtu"`
	HwAddr      string      `json:"macAddr"`
}

// Route describes a pod network route.
type Route struct {
	Src     string `json:"src"`
	Dest    string `json:"dest"`
	Gateway string `json:"gateway,omitempty"`
	Device  string `json:"device,omitempty"`
}

// Network fully describes a pod network with its interfaces, routes and dns
// related information.
type Network struct {
	Interfaces []NetIface `json:"interfaces"`
	DNS        []string   `json:"dns"`
	Routes     []Route    `json:"routes"`
}

// EnvironmentVar describes an environment variable and its value.
type EnvironmentVar struct {
	Env   string `json:"env"`
	Value string `json:"value"`
}

// Fsmap describes a filesystem map related to a container.
type Fsmap struct {
	Source       string `json:"source"`
	Path         string `json:"path"`
	AbsolutePath bool   `json:"absolutePath"`
	ReadOnly     bool   `json:"readOnly"`
	DockerVolume bool   `json:"dockerVolume"`
}

// Process describes a process running on a container.
type Process struct {
	ID               string           `json:"id"`
	User             string           `json:"user,omitempty"`
	Group            string           `json:"group,omitempty"`
	AdditionalGroups []string         `json:"additionalGroups,omitempty"`
	Terminal         bool             `json:"terminal"`
	Stdio            uint64           `json:"stdio"`
	Stderr           uint64           `json:"stderr"`
	Args             []string         `json:"args"`
	Envs             []EnvironmentVar `json:"envs,omitempty"`
	Workdir          string           `json:"workdir"`
	NoNewPrivileges  bool             `json:"noNewPrivileges"`
}

// DecodedMessage describes messages going through CTL channel.
type DecodedMessage struct {
	Code    uint32
	Message []byte
}

// TtyMessage describes messages going through IO channel.
type TtyMessage struct {
	Session uint64
	Message []byte
}

// StartPod describes the format expected by a STARTPOD command.
type StartPod struct {
	ID         string     `json:"hostname"`
	Interfaces []NetIface `json:"interfaces,omitempty"`
	DNS        []string   `json:"dns,omitempty"`
	Routes     []Route    `json:"routes,omitempty"`
	ShareDir   string     `json:"shareDir"`
}

// SystemMountsInfo describes additional information for system mounts that the agent
// needs to handle
type SystemMountsInfo struct {
	// Indicates if /dev has been passed as a bind mount for the host /dev
	BindMountDev bool `json:"bindMountDev"`

	// Size of /dev/shm assigned on the host.
	DevShmSize int `json:"devShmSize"`
}

// NewContainer describes the format expected by a NEWCONTAINER command.
type NewContainer struct {
	ID               string           `json:"id"`
	RootFs           string           `json:"rootfs"`
	Image            string           `json:"image"`
	FsType           string           `json:"fstype,omitempty"`
	Fsmap            []Fsmap          `json:"fsmap"`
	Process          Process          `json:"process"`
	SystemMountsInfo SystemMountsInfo `json:"systemMountsInfo"`
}

// KillContainer describes the format expected by a KILLCONTAINER command.
type KillContainer struct {
	ID           string         `json:"container"`
	Signal       syscall.Signal `json:"signal"`
	AllProcesses bool           `json:"allProcesses"`
}

// RemoveContainer describes the format expected by a REMOVECONTAINER command.
type RemoveContainer struct {
	ID string `json:"container"`
}

// PsContainer describes the format expected by a PSCONTAINER command.
type PsContainer struct {
	ID     string   `json:"container"`
	Format string   `json:"format"`
	Args   []string `json:"psargs"`
}

// Exec describes the format expected by a EXECCMD command.
type Exec struct {
	ContainerID string  `json:"container"`
	Process     Process `json:"process"`
}

// Winsize describes the format expected by a WINSIZE command.
type Winsize struct {
	Sequence uint64 `json:"seq"`
	Row      uint16 `json:"row"`
	Column   uint16 `json:"column"`
}

// CmdToString translates a command into its corresponding string.
func CmdToString(cmd HyperCmd) string {
	strCmd, exist := stringCmdList[cmd]
	if !exist {
		return ""
	}

	return strCmd
}
