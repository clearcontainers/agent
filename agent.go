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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	hyper "github.com/clearcontainers/container-vm-agent/api"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

const (
	virtIOPath         = "/sys/class/virtio-ports"
	devRootPath        = "/dev"
	ctlChannelName     = "sh.hyper.channel.0"
	ttyChannelName     = "sh.hyper.channel.1"
	ctlHeaderSize      = 8
	ttyHeaderSize      = 12
	mountShareDirDest  = "/tmp/shareDir"
	type9pFs           = "9p"
	containerMountDest = "/tmp/hyper"
	loName             = "lo"
	loIPAddr           = "127.0.0.1"
	loNetMask          = "0"
	loType             = "loopback"
	loGateway          = "localhost"
)

type process struct {
	process   libcontainer.Process
	stdin     *os.File
	stdout    *os.File
	stderr    *os.File
	seqStdio  uint64
	seqStderr uint64
}

type container struct {
	container libcontainer.Container
	config    configs.Config
	processes map[string]*process
}

type pod struct {
	id         string
	running    bool
	containers map[string]*container
	ctl        *os.File
	tty        *os.File
	stdinList  map[uint64]*os.File
	network    hyper.Network
	stdinLock  sync.Mutex
	stdoutLock sync.Mutex
}

type cmdCb func(*pod, []byte) error

var callbackList = map[hyper.HyperCmd]cmdCb{
	hyper.StartPodCmd:        startPodCb,
	hyper.DestroyPodCmd:      destroyPodCb,
	hyper.NewContainerCmd:    newContainerCb,
	hyper.KillContainerCmd:   killContainerCb,
	hyper.RemoveContainerCmd: removeContainerCb,
	hyper.ExecCmd:            execCb,
	hyper.ReadyCmd:           readyCb,
	hyper.PingCmd:            pingCb,
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			fmt.Printf("init went wrong: %s\n", err)
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

func main() {
	// Initialiaze wait group waiting for loops to be terminated
	var wgLoops sync.WaitGroup
	wgLoops.Add(1)
	wgLoops.Add(1)

	// Initialize unique pod structure
	pod := &pod{
		containers: make(map[string]*container),
		running:    false,
		stdinList:  make(map[uint64]*os.File),
	}

	// Open serial ports and write on both CTL and TTY channels
	if err := pod.openChannels(); err != nil {
		fmt.Printf("Could not open channels: %s\n", err)
		return
	}

	defer pod.closeChannels()

	// Run CTL loop
	go pod.controlLoop(&wgLoops)

	// Run TTY loop
	go pod.streamsLoop(&wgLoops)

	wgLoops.Wait()
}

func (p *pod) controlLoop(wg *sync.WaitGroup) {
	// Send READY right after it has connected.
	p.sendCmd(hyper.ReadyCmd, []byte{})

	for {
		reply := hyper.AckCmd
		cmd, data, err := p.readCtl()
		if err != nil {
			if err == io.EOF {
				time.Sleep(time.Millisecond)
				continue
			}

			fmt.Printf("CTL channel read failed: %s\n", err)
			break
		}

		if err := p.runCmd(cmd, data); err != nil {
			fmt.Printf("%s error: %s\n", hyper.CmdToString(cmd), err)
			reply = hyper.ErrorCmd
		}

		if err := p.sendCmd(reply, []byte{}); err != nil {
			fmt.Printf("CTL channel reply failed: %s\n", err)
			break
		}
	}

	wg.Done()
}

func (p *pod) streamsLoop(wg *sync.WaitGroup) {
	// Wait for reading something on TTY
	for {
		seq, data, err := p.readTty()
		if err != nil {
			if err == io.EOF {
				time.Sleep(time.Millisecond)
				continue
			}

			fmt.Printf("TTY channel read failed: %s\n", err)
			break
		}

		if seq == uint64(0) || data == nil {
			continue
		}

		// Lock the list before we access it.
		p.stdinLock.Lock()

		file, exist := p.stdinList[seq]
		if exist == false {
			p.stdinLock.Unlock()
			continue
		}

		file.Write(data)

		p.stdinLock.Unlock()
	}

	wg.Done()
}

func (p *pod) registerStdin(seq uint64, stdin *os.File) error {
	p.stdinLock.Lock()
	defer p.stdinLock.Unlock()

	if _, exist := p.stdinList[seq]; exist == true {
		return fmt.Errorf("Sequence number %d already registered", seq)
	}

	p.stdinList[seq] = stdin

	return nil
}

func (p *pod) unregisterStdin(seq uint64) {
	p.stdinLock.Lock()
	defer p.stdinLock.Unlock()

	delete(p.stdinList, seq)
}

func (p *pod) openChannels() error {
	ctlPath, err := findVirtualSerialPath(ctlChannelName)
	if err != nil {
		return err
	}

	ttyPath, err := findVirtualSerialPath(ttyChannelName)
	if err != nil {
		return err
	}

	ctl, err := os.OpenFile(ctlPath, os.O_RDWR, os.ModeDevice)
	if err != nil {
		return err
	}

	tty, err := os.OpenFile(ttyPath, os.O_RDWR, os.ModeDevice)
	if err != nil {
		ctl.Close()
		return err
	}

	p.ctl = ctl
	p.tty = tty

	return nil
}

func (p *pod) closeChannels() {
	if p.ctl != nil {
		p.ctl.Close()
		p.ctl = nil
	}

	if p.tty != nil {
		p.tty.Close()
		p.tty = nil
	}
}

func findVirtualSerialPath(serialName string) (string, error) {
	dir, err := os.Open(virtIOPath)
	if err != nil {
		return "", err
	}

	defer dir.Close()

	ports, err := dir.Readdirnames(0)
	if err != nil {
		return "", err
	}

	for _, port := range ports {
		path := filepath.Join(virtIOPath, port, "name")
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return "", err
		}

		if strings.Contains(string(content), serialName) == true {
			return filepath.Join(devRootPath, port), nil
		}
	}

	return "", fmt.Errorf("Could not find virtio port %s", serialName)
}

func (p *pod) readCtl() (hyper.HyperCmd, []byte, error) {
	buf := make([]byte, ctlHeaderSize)

	n, err := p.ctl.Read(buf)
	if err != nil {
		return hyper.ErrorCmd, []byte{}, err
	}

	if n != ctlHeaderSize {
		return hyper.ErrorCmd, []byte{}, fmt.Errorf("Only %d bytes read out of %d expected", n, ctlHeaderSize)
	}

	cmd := hyper.HyperCmd(binary.BigEndian.Uint32(buf[:4]))
	length := int(binary.BigEndian.Uint32(buf[4:ctlHeaderSize]))
	length -= ctlHeaderSize
	if length == 0 {
		return cmd, nil, nil
	}

	data := make([]byte, length)

	n, err = p.ctl.Read(data)
	if err != nil {
		return hyper.ErrorCmd, []byte{}, err
	}

	if n != length {
		return hyper.ErrorCmd, []byte{}, fmt.Errorf("Only %d bytes read out of %d expected", n, length)
	}

	return cmd, data, nil
}

func (p *pod) readTty() (uint64, []byte, error) {
	buf := make([]byte, ttyHeaderSize)

	n, err := p.tty.Read(buf)
	if err != nil {
		return uint64(0), []byte{}, err
	}

	if n != ttyHeaderSize {
		return uint64(0), []byte{}, fmt.Errorf("Only %d bytes read out of %d expected", n, ttyHeaderSize)
	}

	seq := binary.BigEndian.Uint64(buf[:8])
	length := int(binary.BigEndian.Uint32(buf[8:ttyHeaderSize]))
	length -= ttyHeaderSize
	if length == 0 {
		return seq, nil, nil
	}

	data := make([]byte, length)

	n, err = p.tty.Read(data)
	if err != nil {
		return uint64(0), []byte{}, err
	}

	if n != length {
		return uint64(0), []byte{}, fmt.Errorf("Only %d bytes read out of %d expected", n, length)
	}

	return seq, data, nil
}

func (p *pod) sendCmd(cmd hyper.HyperCmd, data []byte) error {
	dataLen := len(data)
	length := ctlHeaderSize + dataLen
	buf := make([]byte, length)

	binary.BigEndian.PutUint32(buf[:], uint32(cmd))
	binary.BigEndian.PutUint32(buf[4:], uint32(length))

	if dataLen > 0 {
		bytesCopied := copy(buf[ctlHeaderSize:], data)
		if bytesCopied != dataLen {
			return fmt.Errorf("Only %d bytes copied out of %d expected", bytesCopied, dataLen)
		}
	}

	n, err := p.ctl.Write(buf)
	if err != nil {
		return err
	}

	if n != length {
		return fmt.Errorf("Only %d bytes written out of %d expected", n, length)
	}

	return nil
}

func (p *pod) sendSeq(seq uint64, data []byte) error {
	p.stdoutLock.Lock()
	defer p.stdoutLock.Unlock()

	dataLen := len(data)
	length := ttyHeaderSize + dataLen
	buf := make([]byte, length)

	binary.BigEndian.PutUint64(buf[:], seq)
	binary.BigEndian.PutUint32(buf[8:], uint32(length))

	if dataLen > 0 {
		bytesCopied := copy(buf[ttyHeaderSize:], data)
		if bytesCopied != dataLen {
			return fmt.Errorf("Only %d bytes copied out of %d expected", bytesCopied, dataLen)
		}
	}

	n, err := p.tty.Write(buf)
	if err != nil {
		return err
	}

	if n != length {
		return fmt.Errorf("Only %d bytes written out of %d expected", n, length)
	}

	return nil
}

func (p *pod) closeProcessStreams(cid, pid string) {
	if err := p.containers[cid].processes[pid].stderr.Close(); err != nil {
		fmt.Printf("Could not close stderr for container %s, process %s: %s\n", cid, pid, err)
	}

	if err := p.containers[cid].processes[pid].stdout.Close(); err != nil {
		fmt.Printf("Could not close stdout for container %s, process %s: %s\n", cid, pid, err)
	}

	if err := p.containers[cid].processes[pid].stdin.Close(); err != nil {
		fmt.Printf("Could not close stdin for container %s, process %s: %s\n", cid, pid, err)
	}

	p.unregisterStdin(p.containers[cid].processes[pid].seqStdio)
}

// Executed as a go routine to route stdout and stderr to the TTY channel.
func (p *pod) routeOutput(seq uint64, stream *os.File) {
	for {
		buf := make([]byte, 4096)
		if _, err := stream.Read(buf); err != nil {
			fmt.Printf("Stream %d closed: %s\n", seq, err)
			break
		}

		p.sendSeq(seq, buf)
	}
}

// Executed as go routine to run and wait for the process.
func (p *pod) runContainerProcess(cid, pid string) {
	go p.routeOutput(p.containers[cid].processes[pid].seqStdio, p.containers[cid].processes[pid].stdout)

	go p.routeOutput(p.containers[cid].processes[pid].seqStderr, p.containers[cid].processes[pid].stderr)

	if err := p.containers[cid].container.Run(&(p.containers[cid].processes[pid].process)); err != nil {
		fmt.Printf("Could not run process: %s\n", err)
		p.closeProcessStreams(cid, pid)
		delete(p.containers[cid].processes, pid)
		return
	}

	processState, err := p.containers[cid].processes[pid].process.Wait()
	if err != nil {
		fmt.Printf("Error while waiting for process to finish: %s\n", err)
		p.closeProcessStreams(cid, pid)
		delete(p.containers[cid].processes, pid)
		return
	}

	p.closeProcessStreams(cid, pid)

	// Send empty message on tty channel to close the IO stream
	p.sendSeq(p.containers[cid].processes[pid].seqStdio, []byte{})

	// Get exit code
	exitCode := uint8(255)
	if waitStatus, ok := processState.Sys().(syscall.WaitStatus); ok {
		exitCode = uint8(waitStatus.ExitStatus())
	}

	// Send exit code through tty channel
	p.sendSeq(p.containers[cid].processes[pid].seqStdio, []byte{exitCode})

	delete(p.containers[cid].processes, pid)
}

func (p *pod) buildProcess(hyperProcess hyper.Process) (*process, error) {
	rStdin, wStdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	rStderr, wStderr, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	if err := p.registerStdin(hyperProcess.Stdio, wStdin); err != nil {
		return nil, err
	}

	libContProcess := libcontainer.Process{
		Cwd:    hyperProcess.Workdir,
		Args:   hyperProcess.Args,
		Env:    hyperProcess.Envs,
		User:   hyperProcess.User,
		Stdin:  rStdin,
		Stdout: wStdout,
		Stderr: wStderr,
	}

	return &process{
		process:   libContProcess,
		stdin:     wStdin,
		stdout:    rStdout,
		stderr:    rStderr,
		seqStdio:  hyperProcess.Stdio,
		seqStderr: hyperProcess.Stderr,
	}, nil
}

func (p *pod) runCmd(cmd hyper.HyperCmd, data []byte) error {
	cb, exist := callbackList[cmd]
	if exist == false {
		return fmt.Errorf("No callback found for command '%s'", hyper.CmdToString(cmd))
	}

	return cb(p, data)
}

func startPodCb(pod *pod, data []byte) error {
	var payload hyper.StartPod

	if pod.running == true {
		return fmt.Errorf("Pod already started, impossible to start again")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if err := mountShareDir(payload.ShareDir); err != nil {
		return err
	}

	pod.id = payload.ID
	pod.running = true
	pod.network = payload.Network

	if err := pod.setupNetwork(); err != nil {
		return fmt.Errorf("Could not setup the network: %s", err)
	}

	return nil
}

func destroyPodCb(pod *pod, data []byte) error {
	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to destroy")
	}

	if len(pod.containers) > 0 {
		return fmt.Errorf("%d containers not removed, impossible to destroy the pod", len(pod.containers))
	}

	if err := unmountShareDir(); err != nil {
		return err
	}

	if err := pod.removeNetwork(); err != nil {
		return fmt.Errorf("Could not remove the network: %s", err)
	}

	pod.id = ""
	pod.containers = make(map[string]*container)
	pod.running = false
	pod.stdinList = make(map[uint64]*os.File)
	pod.network = hyper.Network{}

	return nil
}

func newContainerCb(pod *pod, data []byte) error {
	var payload hyper.NewContainer

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to start a new container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if _, exist := pod.containers[payload.ID]; exist == true {
		return fmt.Errorf("Container %s already existing, impossible to start", payload.ID)
	}

	absoluteRootFs, err := mountContainerRootFs(payload.ID, payload.RootFs)
	if err != nil {
		return err
	}

	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV

	config := configs.Config{
		Rootfs: absoluteRootFs,
		Capabilities: &configs.Capabilities{},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			{Type: configs.NEWUSER},
			{Type: configs.NEWNET},
		}),
		Cgroups: &configs.Cgroup{
			Name:   payload.ID,
			Parent: "system",
			Resources: &configs.Resources{
				MemorySwappiness: nil,
				AllowAllDevices:  nil,
				AllowedDevices:   configs.DefaultAllowedDevices,
			},
		},
		Devices: configs.DefaultAutoCreatedDevices,

		Hostname: pod.id,
		Mounts: []*configs.Mount{
			{
				Source:      "proc",
				Destination: "/proc",
				Device:      "proc",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "tmpfs",
				Destination: "/dev",
				Device:      "tmpfs",
				Flags:       syscall.MS_NOSUID | syscall.MS_STRICTATIME,
				Data:        "mode=755",
			},
			{
				Source:      "devpts",
				Destination: "/dev/pts",
				Device:      "devpts",
				Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
				Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			},
			{
				Device:      "tmpfs",
				Source:      "shm",
				Destination: "/dev/shm",
				Data:        "mode=1777,size=65536k",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "mqueue",
				Destination: "/dev/mqueue",
				Device:      "mqueue",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "sysfs",
				Destination: "/sys",
				Device:      "sysfs",
				Flags:       defaultMountFlags | syscall.MS_RDONLY,
			},
		},

		UidMappings: []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      0,
				Size:        65536,
			},
		},
		GidMappings: []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      0,
				Size:        65536,
			},
		},
	}

	containerPath := filepath.Join("/tmp/libcontainer", pod.id)
	factory, err := libcontainer.New(containerPath, libcontainer.Cgroupfs)
	if err != nil {
		return err
	}

	libContContainer, err := factory.Create(payload.ID, &config)
	if err != nil {
		return err
	}

	builtProcess, err := pod.buildProcess(payload.Process)
	if err != nil {
		return err
	}

	processes := make(map[string]*process)
	processes[payload.Process.ID] = builtProcess

	container := &container{
		container: libContContainer,
		config:    config,
		processes: processes,
	}

	pod.containers[payload.ID] = container

	go pod.runContainerProcess(payload.ID, payload.Process.ID)

	return nil
}

func killContainerCb(pod *pod, data []byte) error {
	var payload hyper.KillContainer

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to signal the container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if _, exist := pod.containers[payload.ID]; exist == false {
		return fmt.Errorf("Container %s not found, impossible to signal", payload.ID)
	}

	if err := pod.containers[payload.ID].container.Signal(payload.Signal, true); err != nil {
		return err
	}

	return nil
}

func removeContainerCb(pod *pod, data []byte) error {
	var payload hyper.RemoveContainer

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to remove the container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if _, exist := pod.containers[payload.ID]; exist == false {
		return fmt.Errorf("Container %s not found, impossible to remove", payload.ID)
	}

	status, err := pod.containers[payload.ID].container.Status()
	if err != nil {
		return err
	}

	if status == libcontainer.Running {
		return fmt.Errorf("Container %s running, impossible to remove", payload.ID)
	}

	if err := pod.containers[payload.ID].container.Destroy(); err != nil {
		return err
	}

	if err := unmountContainerRootFs(payload.ID, pod.containers[payload.ID].config.Rootfs); err != nil {
		return err
	}

	delete(pod.containers, payload.ID)

	return nil
}

func execCb(pod *pod, data []byte) error {
	var payload hyper.Exec

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to exec process on the container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if _, exist := pod.containers[payload.ContainerID]; exist == false {
		return fmt.Errorf("Container %s not found, impossible to execute process %s", payload.ContainerID, payload.Process.ID)
	}

	status, err := pod.containers[payload.ContainerID].container.Status()
	if err != nil {
		return err
	}

	if status != libcontainer.Running {
		return fmt.Errorf("Container %s not running, impossible to execute process %s", payload.ContainerID, payload.Process.ID)
	}

	if _, exist := pod.containers[payload.ContainerID].processes[payload.Process.ID]; exist == true {
		return fmt.Errorf("Process %s already exists", payload.Process.ID)
	}

	process, err := pod.buildProcess(payload.Process)
	if err != nil {
		return err
	}

	pod.containers[payload.ContainerID].processes[payload.Process.ID] = process

	go pod.runContainerProcess(payload.ContainerID, payload.Process.ID)

	return nil
}

func readyCb(pod *pod, data []byte) error {
	return nil
}

func pingCb(pod *pod, data []byte) error {
	return nil
}
