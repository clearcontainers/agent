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

type HyperCmd uint32

// Control command string IDs
const (
	StartPodCmd HyperCmd = iota
	DestroyPodCmd
	NewContainerCmd
	KillContainerCmd
	RemoveContainerCmd
	ExecCmd
	ReadyCmd
	AckCmd
	ErrorCmd
	PingCmd
)

var stringCmdList = map[HyperCmd]string{
	StartPodCmd:        "startpod",
	DestroyPodCmd:      "destroypod",
	NewContainerCmd:    "newcontainer",
	KillContainerCmd:   "killcontainer",
	RemoveContainerCmd: "removecontainer",
	ExecCmd:            "exec",
	ReadyCmd:           "ready",
	AckCmd:             "ack",
	ErrorCmd:           "error",
	PingCmd:            "ping",
}

type Process struct {
	ID       string   `json:"id"`
	User     string   `json:"user,omitempty"`
	Group    string   `json:"group,omitempty"`
	Terminal bool     `json:"terminal"`
	Stdio    uint64   `json:"stdio,omitempty"`
	Stderr   uint64   `json:"stderr,omitempty"`
	Args     []string `json:"args"`
	Envs     []string `json:"envs,omitempty"`
	Workdir  string   `json:"workdir"`
}

type DecodedMessage struct {
	Code    uint32
	Message []byte
}

type TtyMessage struct {
	Session uint64
	Message []byte
}

type StartPod struct {
	ID       string `json:"id"`
	ShareDir string `json:"shareDir"`
}

type NewContainer struct {
	ID      string  `json:"id"`
	RootFs  string  `json:"rootfs"`
	Process Process `json:"process"`
}

type KillContainer struct {
	ID     string         `json:"id"`
	Signal syscall.Signal `json:"signal"`
}

type RemoveContainer struct {
	ID string `json:"id"`
}

type Exec struct {
	ContainerID string  `json"containerId"`
	Process     Process `json:"process"`
}

func CmdToString(cmd HyperCmd) string {
	strCmd, exist := stringCmdList[cmd]
	if exist == false {
		return ""
	}

	return strCmd
}
