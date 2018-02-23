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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	hyper "github.com/clearcontainers/agent/api"
	goudev "github.com/jochenvg/go-udev"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	name               = "cc-agent"
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
	defaultPassword    = "/etc/passwd"
	statelessPassword  = "/usr/share/defaults/etc/passwd"
	defaultGroup       = "/etc/group"
	statelessGroup     = "/usr/share/defaults/etc/group"
	kernelCmdlineFile  = "/proc/cmdline"
	optionPrefix       = "agent."
	logLevelFlag       = optionPrefix + "log"
	defaultLogLevel    = logrus.InfoLevel
	cannotGetTimeMsg   = "Failed to get time for event %s:%v"
	pciBusRescanFile   = "/sys/bus/pci/rescan"
	pciBusMode         = 0220
	cpuMode            = 0600

	// If a process terminates because of signal "n"
	// The exit code is "128 + signal_number"
	// http://tldp.org/LDP/abs/html/exitcodes.html
	exitSignalOffset = 128

	// Timeouts
	defaultTimeout     = 15
	runProcessTimeout  = defaultTimeout
	killProcessTimeout = defaultTimeout

	// Udev subsystem
	blockSubsystem = "block"
	cpuSubsystem   = "cpu"
)

var defaultCapsList = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_RAW",
	"CAP_SYS_CHROOT",
	"CAP_MKNOD",
	"CAP_AUDIT_WRITE",
	"CAP_SETFCAP",
}

type agentConfig struct {
	logLevel logrus.Level
}

type process struct {
	process     libcontainer.Process
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	seqStdio    uint64
	seqStderr   uint64
	consoleSock *os.File
	termMaster  *os.File
}

type container struct {
	container        libcontainer.Container
	config           configs.Config
	processes        map[string]*process
	pod              *pod
	processesLock    sync.RWMutex
	wgProcesses      sync.WaitGroup
	deviceNodes      []string
	deviceNodesLock  sync.Mutex
	systemMountsInfo hyper.SystemMountsInfo
}

type pod struct {
	id             string
	running        bool
	containers     map[string]*container
	ctl            *os.File
	tty            *os.File
	stdinList      map[uint64]stdinInfo
	network        hyper.Network
	stdinLock      sync.Mutex
	ttyLock        sync.Mutex
	containersLock sync.RWMutex
	subreaper      *reaper
}

type stdinInfo struct {
	stdin *os.File
	term  bool
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
	hyper.WinsizeCmd:         winsizeCb,
}

type cmdCbWithReply func(*pod, []byte) ([]byte, error)

var callbackWithReplyList = map[hyper.HyperCmd]cmdCbWithReply{
	hyper.PsContainerCmd: processListCb,
}

var agentLog = logrus.WithFields(logrus.Fields{
	"name": name,
	"pid":  os.Getpid(),
})

// Add kernel subsystems that need to be blacklisted here.
// These devices will not be mounted within a container.
var blacklistedDeviceSubsystems = []string{}

func isBlacklistedSubsystem(subsystem string) bool {
	for _, s := range blacklistedDeviceSubsystems {
		if subsystem == s {
			return true
		}
	}

	return false
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			agentLog.Errorf("init went wrong: %v", err)
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

// Version is the agent version. This variable is populated at build time.
var Version = "unknown"

func main() {

	agentLog.Logger.Formatter = &logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano}
	config := newConfig(defaultLogLevel)
	if err := config.getConfig(kernelCmdlineFile); err != nil {
		agentLog.WithError(err).Warn("Failed to get config from kernel cmdline")
	}
	applyConfig(config)

	agentLog.WithField("version", Version).Info()

	if uptime, err := newEventTime(agentStartedEvent); err != nil {
		agentLog.WithError(err).Error("Failed to get uptime")
	} else {
		agentLog.Infof("%s", uptime)
	}

	// Initialiaze wait group waiting for loops to be terminated
	var wgLoops sync.WaitGroup
	wgLoops.Add(1)

	// Initialize unique pod structure
	pod := &pod{
		containers: make(map[string]*container),
		running:    false,
		stdinList:  make(map[uint64]stdinInfo),
	}

	// Open serial ports and write on both CTL and TTY channels
	if err := pod.openChannels(); err != nil {
		agentLog.WithError(err).Error("Could not open channels")
		return
	}
	defer pod.closeChannels()

	// Setup users and groups
	if err := pod.setupUsersAndGroups(); err != nil {
		agentLog.WithError(err).Error("Could not setup users and groups")
		return
	}

	if err := pod.setSubreaper(); err != nil {
		return
	}

	// Run CTL loop
	go pod.controlLoop(&wgLoops)

	// Run TTY loop
	go pod.streamsLoop(&wgLoops)

	// Create done signal channel for signalling udev epoll loop.
	done := make(chan struct{})

	// Run loop listening for udev events
	pod.listenToUdevEvents(done)

	wgLoops.Wait()
	close(done)
}

func (p *pod) getContainer(id string) (ctr *container) {
	p.containersLock.RLock()
	defer p.containersLock.RUnlock()

	ctr, exist := p.containers[id]
	if exist == false {
		return nil
	}

	return ctr
}

func (p *pod) setContainer(id string, ctr *container) {
	p.containersLock.Lock()
	p.containers[id] = ctr
	p.containersLock.Unlock()
}

func (p *pod) deleteContainer(id string) {
	p.containersLock.Lock()
	delete(p.containers, id)
	p.containersLock.Unlock()
}

// This loop is meant to be run inside a separate Go routine.
func (p *pod) reaperLoop(sigCh chan os.Signal) {
	for sig := range sigCh {
		switch sig {
		case unix.SIGCHLD:
			if err := p.subreaper.reap(); err != nil {
				agentLog.Error(err)
				return
			}
		default:
			agentLog.Infof("Unexpected signal %s, nothing to do...", sig.String())
		}
	}
}

func (p *pod) setSubreaper() error {
	p.subreaper = &reaper{
		exitCodeChans: make(map[int]chan int),
	}

	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(1), 0, 0, 0); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 512)
	signal.Notify(sigCh, unix.SIGCHLD)

	go p.reaperLoop(sigCh)

	return nil
}

func (p *pod) controlLoop(wg *sync.WaitGroup) {
	fieldLogger := agentLog.WithField("channel", "ctl")

	// Send READY right after it has connected.
	// This allows to block until the connection is up.
	if err := p.sendCmd(hyper.ReadyCmd, []byte{}); err != nil {
		fieldLogger.WithFields(
			logrus.Fields{
				"error":   err,
				"command": "ready",
			}).Error("Failed to send command")
		goto out
	}

	for {
		reply := hyper.AckCmd
		cmd, data, err := p.readCtl()
		if err != nil {
			if err == io.EOF {
				time.Sleep(time.Millisecond)
				continue
			}

			fieldLogger.WithError(err).Errorf("Read failed")
			break
		}

		fieldLogger = fieldLogger.WithField("command", hyper.CmdToString(cmd))

		fieldLogger.Info("Received command")

		response, err := p.runCmd(cmd, data)
		if err != nil {
			fieldLogger.WithError(err).Info("command failed")
			reply = hyper.ErrorCmd
		}

		if err != nil {
			response = []byte(err.Error())
		} else if response == nil {
			response = []byte{}
		}

		if err := p.sendCmd(reply, response); err != nil {
			fieldLogger.WithError(err).Info("reply send failed")
			break
		}
	}

out:
	wg.Done()
}

func (p *pod) streamsLoop(wg *sync.WaitGroup) {
	// Wait for reading something on TTY

	fieldLogger := agentLog.WithField("channel", "tty")

	for {
		seq, data, err := p.readTty()
		if err != nil {
			if err == io.EOF {
				time.Sleep(time.Millisecond)
				continue
			}

			fieldLogger.WithError(err).Info("Read failed")
			break
		}

		fieldLogger.Info("Read from channel")

		if seq == uint64(0) {
			continue
		}

		fieldLogger = fieldLogger.WithFields(logrus.Fields{
			"sequence": seq,
			"message":  string(data),
		})

		fieldLogger.Info("Read from channel")

		// message is now logged, so remove it to avoid bloating the
		// logs.
		delete(fieldLogger.Data, "message")

		// Lock the list before we access it.
		p.stdinLock.Lock()

		fieldLogger = fieldLogger.WithField("stream", "stdin")

		info, exist := p.stdinList[seq]
		if !exist {
			fieldLogger.Info("Sequence not found")
			p.stdinLock.Unlock()
			continue
		}

		p.stdinLock.Unlock()

		if len(data) == 0 && !info.term {
			fieldLogger.Info("EOF detected, closing stdin for a non terminal")
			p.unregisterStdin(seq)
			info.stdin.Close()
			continue
		}

		fieldLogger.Info("Sequence found, writing data")

		n, err := info.stdin.Write(data)
		if err != nil {
			fieldLogger.WithError(err).Error("Write to process failed")
		}

		fieldLogger.WithFields(logrus.Fields{
			"bytes_written": n,
			"bytes_total":   len(data),
		}).Info("bytes written")
	}

	wg.Done()
}

func (p *pod) registerStdin(seq uint64, stdin *os.File, term bool) error {
	p.stdinLock.Lock()
	defer p.stdinLock.Unlock()

	if _, exist := p.stdinList[seq]; exist {
		return fmt.Errorf("Sequence number %d already registered", seq)
	}

	p.stdinList[seq] = stdinInfo{
		stdin: stdin,
		term:  term,
	}

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

// listenToUdevEvents listens to udev events to detect device nodes added
// and binds the device nodes to the /dev of all the containers.
// This is required as a container has its /dev mounted with tmpfs with an initial
// list of devices.
func (p *pod) listenToUdevEvents(done chan struct{}) {
	u := goudev.Udev{}

	// Create a monitor listening on a NetLink socket.
	monitor := u.NewMonitorFromNetlink("udev")

	// Start monitor goroutine.
	ch, _ := monitor.DeviceChan(done)

	go func() {
		fieldLogger := agentLog.WithField("subsystem", "udevlistener")

		fieldLogger.Info("Started listening for all udev events")

		for d := range ch {
			fieldLogger.WithFields(logrus.Fields{
				"udev-path":  d.Syspath(),
				"udev-event": d.Action(),
			}).Info("Received udev event")

			// Ignore udev events for block devices, these are handled by another go-routine in waitForBlockDevice
			// that mounts block devices at the expected location provided on the command line.
			if d.Subsystem() == blockSubsystem {
				continue
			}

			if d.Subsystem() == cpuSubsystem {
				p.onlineVCPU(d.Syspath())
				continue
			}

			if isBlacklistedSubsystem(d.Subsystem()) {
				fieldLogger.WithFields(logrus.Fields{
					"udev-subsystem":  d.Subsystem(),
					"udev-devicenode": d.Devnode(),
				}).Info("Device has been blacklisted")

				continue
			}

			if d.Action() == "add" {
				// Bind device to /dev within all containers
				p.bindDeviceNode(d.Devnode())
			}
		}
	}()
}

func (p *pod) onlineVCPU(syspath string) {
	onlinePath := filepath.Join(syspath, "online")
	if _, err := os.Stat(onlinePath); os.IsNotExist(err) {
		agentLog.WithFields(logrus.Fields{
			"subsystem":      "udevlistener",
			"udev-subsystem": "cpu",
		}).Errorf("online file of vCPU %s not exist", syspath)
		return
	}

	if err := ioutil.WriteFile(onlinePath, []byte("1"), cpuMode); err != nil {
		agentLog.WithFields(logrus.Fields{
			"subsystem":      "udevlistener",
			"udev-subsystem": "cpu",
		}).Errorf("failed to online vCPU %s: %s", syspath, err)
	}
}

func (p *pod) bindDeviceNode(devNode string) {
	fieldLogger := agentLog.WithField("subsystem", "udevlistener")
	for _, ctr := range p.containers {
		fieldLogger.WithFields(logrus.Fields{
			"devNode": devNode,
			"ctr":     ctr.container.ID(),
		}).Info("Bind mounting device to /dev")

		if ctr.systemMountsInfo.BindMountDev {
			if err := ctr.bindDeviceNode(devNode); err != nil {
				fieldLogger.WithError(err).Info("Could not bind device")
			}
		}
	}
}

func (c *container) bindDeviceNode(devNode string) error {
	dest := filepath.Join(c.config.Rootfs, devNode)

	if err := bindMount(devNode, dest, true); err != nil {
		return err
	}

	c.deviceNodesLock.Lock()
	c.deviceNodes = append(c.deviceNodes, dest)
	c.deviceNodesLock.Unlock()

	return nil
}

func (p *pod) setupUsersAndGroups() error {

	// Check /etc/passwd for users
	if _, err := os.Stat(defaultPassword); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		if _, err := os.Stat(statelessPassword); err != nil {
			return err
		}

		if err := fileCopy(statelessPassword, defaultPassword); err != nil {
			return err
		}
	}

	// Check /etc/group for groups
	if _, err := os.Stat(defaultGroup); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		if _, err := os.Stat(statelessGroup); err != nil {
			return err
		}

		if err := fileCopy(statelessGroup, defaultGroup); err != nil {
			return err
		}
	}

	return nil
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
			if os.IsNotExist(err) {
				agentLog.WithField("file", path).Debug("Skip parsing of non-existent file")
				continue
			}
			return "", err
		}

		if strings.Contains(string(content), serialName) == true {
			return filepath.Join(devRootPath, port), nil
		}
	}

	return "", fmt.Errorf("Could not find virtio port %s", serialName)
}

// read l bytes from r
func readAll(r io.Reader, l int) ([]byte, int, error) {
	data := make([]byte, l)
	var t int
	for {
		n, err := r.Read(data[t:])
		if err != nil {
			return nil, -1, err
		}

		t += n
		if t == l {
			return data, t, nil
		}
	}
}

func (p *pod) readCtl() (hyper.HyperCmd, []byte, error) {
	buf := make([]byte, ctlHeaderSize)

	n, err := p.ctl.Read(buf)
	if err != nil {
		return hyper.ErrorCmd, []byte{}, err
	}

	if n != ctlHeaderSize {
		return hyper.ErrorCmd, []byte{},
			fmt.Errorf("Only %d bytes read out of %d expected (ctl channel)", n, ctlHeaderSize)
	}

	cmd := hyper.HyperCmd(binary.BigEndian.Uint32(buf[:4]))
	length := int(binary.BigEndian.Uint32(buf[4:ctlHeaderSize]))
	length -= ctlHeaderSize
	if length == 0 {
		return cmd, nil, nil
	}

	var data []byte
	data, n, err = readAll(p.ctl, length)
	if err != nil {
		return hyper.ErrorCmd, []byte{}, err
	}

	if n != length {
		return hyper.ErrorCmd, []byte{},
			fmt.Errorf("Only %d bytes read out of %d expected (ctl channel)", n, length)
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
		return uint64(0), []byte{},
			fmt.Errorf("Only %d bytes read out of %d expected (tty channel)", n, ttyHeaderSize)
	}

	seq := binary.BigEndian.Uint64(buf[:8])
	length := int(binary.BigEndian.Uint32(buf[8:ttyHeaderSize]))
	length -= ttyHeaderSize
	if length == 0 {
		return seq, []byte{}, nil
	}

	var data []byte
	data, n, err = readAll(p.tty, length)
	if err != nil {
		return uint64(0), []byte{}, err
	}

	if n != length {
		return uint64(0), []byte{},
			fmt.Errorf("Only %d bytes read out of %d expected (tty channel)", n, length)
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
			return fmt.Errorf("Only %d bytes copied out of %d expected (ctl channel)", bytesCopied, dataLen)
		}
	}

	n, err := p.ctl.Write(buf)
	if err != nil {
		return err
	}

	if n != length {
		return fmt.Errorf("Only %d bytes written out of %d expected (ctl channel)", n, length)
	}

	return nil
}

func (p *pod) sendSeq(seq uint64, data []byte) error {
	p.ttyLock.Lock()
	defer p.ttyLock.Unlock()

	dataLen := len(data)
	length := ttyHeaderSize + dataLen
	buf := make([]byte, length)

	binary.BigEndian.PutUint64(buf[:], seq)
	binary.BigEndian.PutUint32(buf[8:], uint32(length))

	if dataLen > 0 {
		bytesCopied := copy(buf[ttyHeaderSize:], data)
		if bytesCopied != dataLen {
			return fmt.Errorf("Only %d bytes copied out of %d expected (tty channel)", bytesCopied, dataLen)
		}
	}

	n, err := p.tty.Write(buf)
	if err != nil {
		return err
	}

	if n != length {
		return fmt.Errorf("Only %d bytes written out of %d expected (tty channel)", n, length)
	}

	return nil
}

func (c *container) getProcess(pid string) *process {
	c.processesLock.RLock()
	defer c.processesLock.RUnlock()

	proc, exist := c.processes[pid]
	if exist == false {
		return nil
	}

	return proc
}

func (c *container) setProcess(pid string, process *process) {
	c.processesLock.Lock()
	c.processes[pid] = process
	c.processesLock.Unlock()
}

func (c *container) deleteProcess(pid string) {
	c.processesLock.Lock()
	delete(c.processes, pid)
	c.processesLock.Unlock()
}

func (c *container) closeProcessStreams(pid string) {
	cid := c.container.ID()
	proc := c.getProcess(pid)

	fieldLogger := agentLog.WithFields(logrus.Fields{
		"container-pid": pid,
		"container":     cid,
	})

	if proc == nil {
		fieldLogger.Warn("Container process no longer exists")
		return
	}

	if proc.termMaster != nil {
		if err := proc.termMaster.Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"stream": "master-terminal",
				"error":  err,
			}).Warn("Could not close container stream")
		}

		proc.termMaster = nil
	}

	if proc.stdout != nil {
		if err := proc.stdout.Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"stream": "stdout",
				"error":  err,
			}).Warn("Could not close container stream")
		}

		proc.stdout = nil
	}

	if proc.stderr != nil {
		if err := proc.stderr.Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"stream": "stderr",
				"error":  err,
			}).Warn("Could not close container stream")
		}

		proc.stderr = nil
	}

	c.pod.unregisterStdin(c.processes[pid].seqStdio)

	if proc.stdin != nil {
		if err := proc.stdin.Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"stream": "stdin",
				"error":  err,
			}).Warn("Could not close container stream")
		}

		proc.stdin = nil
	}
}

func (c *container) closeProcessPipes(pid string) {
	cid := c.container.ID()
	proc := c.getProcess(pid)

	fieldLogger := agentLog.WithFields(logrus.Fields{
		"container-pid": pid,
		"container":     cid,
	})

	if proc == nil {
		fieldLogger.Warnf("Container process no longer exists")
		return
	}

	if proc.process.Stdout != nil {
		if err := proc.process.Stdout.(*os.File).Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"error":  err,
				"stream": "stdout",
			}).Warn("Could not close process stream")
		}

		proc.process.Stdout = nil
	}

	if proc.process.Stderr != nil {
		if err := proc.process.Stderr.(*os.File).Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"error":  err,
				"stream": "stderr",
			}).Warn("Could not close process stream")
		}

		proc.process.Stderr = nil
	}

	if proc.process.Stdin != nil {
		if err := proc.process.Stdin.(*os.File).Close(); err != nil {
			fieldLogger.WithFields(logrus.Fields{
				"error":  err,
				"stream": "stdin",
			}).Warn("Could not close process stream")
		}

		proc.process.Stdin = nil
	}
}

func (c *container) closeConsoleSocket(pid string) error {
	cid := c.container.ID()
	proc := c.getProcess(pid)

	errMsg := "Could not close process socket pair"

	if proc == nil {
		return fmt.Errorf("Container %s process %s no longer exists", cid, pid)
	}

	if proc.consoleSock != nil {
		if err := proc.consoleSock.Close(); err != nil {
			return fmt.Errorf("%s: %s", errMsg, err)
		}

		proc.consoleSock = nil
	}

	if proc.process.ConsoleSocket != nil {
		if err := proc.process.ConsoleSocket.Close(); err != nil {
			return fmt.Errorf("%s: %s", errMsg, err)
		}

		proc.process.ConsoleSocket = nil
	}

	return nil
}

// Executed as a go routine to route stdout and stderr to the TTY channel.
func (p *pod) routeOutput(seq uint64, stream *os.File, wg *sync.WaitGroup) {
	fieldLogger := agentLog.WithField("sequence", seq)

	for {
		buf := make([]byte, 1024)

		n, err := stream.Read(buf)
		if err != nil {
			fieldLogger.WithError(err).Info("Sequence has been closed")
			break
		}

		fieldLogger.WithField("data", string(buf[:n])).Info("Read from sequence")
		p.sendSeq(seq, buf[:n])
	}

	wg.Done()
}

func setConsoleCarriageReturn(fd uintptr) error {
	var termios syscall.Termios

	if err := ioctl(fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios))); err != nil {
		return err
	}

	termios.Oflag |= syscall.ONLCR

	return ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&termios)))
}

// Executed as go routine to run and wait for the process.
func (p *pod) runContainerProcess(cid, pid string, terminal bool, started chan error) error {
	ctr := p.getContainer(cid)

	defer func() {
		ctr.closeProcessPipes(pid)
		ctr.closeConsoleSocket(pid)
		ctr.closeProcessStreams(pid)
		ctr.deleteProcess(pid)
		ctr.wgProcesses.Done()
	}()

	var wgRouteOutput sync.WaitGroup

	proc := ctr.getProcess(pid)

	fieldLogger := agentLog.WithField("container-pid", pid)

	// This lock is very important to avoid any race with reaper.reap().
	// Indeed, if we don't lock this here, we could potentially get the
	// SIGCHLD signal before the exit code channel has been created,
	// meaning we will miss the opportunity to get the exit code, leading
	// this function to wait forever on the newly created exit code
	// channel.
	// Also, this lock has to be taken before we run the new process since
	// container.Run() expects to reap the first process itself.
	p.subreaper.RLock()

	if err := ctr.container.Run(&(proc.process)); err != nil {
		fieldLogger.WithError(err).Error("Could not run process")
		p.subreaper.RUnlock()
		started <- err
		return err
	}

	// Get process PID
	processID, err := proc.process.Pid()
	if err != nil {
		p.subreaper.RUnlock()
		started <- err
		return err
	}

	// Close parent pipes since we don't need to keep them opened after
	// they have been duplicated by libcontainer when starting the
	// container process.
	// Not closing those pipes means we're going to have some file
	// descriptor maintaining the file opened even after the process
	// returned, which would prevent this function from returning.
	fieldLogger.Debug("Closing parent pipes")
	ctr.closeProcessPipes(pid)

	// Create process channel to allow this function to wait for it.
	// This channel is buffered so that reaper.reap() will not block
	// until this function listen onto this channel.
	p.subreaper.setExitCodeCh(processID, make(chan int, 1))

	p.subreaper.RUnlock()

	if terminal {
		termMaster, err := utils.RecvFd(proc.consoleSock)
		if err != nil {
			return err
		}

		// No need to maintain this socket opened after we retrieved
		// the master end of the terminal.
		if err := ctr.closeConsoleSocket(pid); err != nil {
			return err
		}

		if err := setConsoleCarriageReturn(termMaster.Fd()); err != nil {
			return err
		}

		proc.termMaster = termMaster

		if err := p.registerStdin(proc.seqStdio, termMaster, true); err != nil {
			return err
		}

		wgRouteOutput.Add(1)
		go p.routeOutput(proc.seqStdio, termMaster, &wgRouteOutput)
	} else {
		if proc.stdout != nil {
			wgRouteOutput.Add(1)
			go p.routeOutput(proc.seqStdio,
				proc.stdout, &wgRouteOutput)
		}

		if proc.stderr != nil {
			wgRouteOutput.Add(1)
			go p.routeOutput(proc.seqStderr,
				proc.stderr, &wgRouteOutput)
		}
	}

	started <- nil

	// Using helper function wait() to deal with the subreaper.
	libContProcess := (*reaperLibcontainerProcess)(&(proc.process))
	exitCode, err := p.subreaper.wait(processID, libContProcess)
	if err != nil {
		return err
	}

	// Make sure all output has been routed before to go further and
	// return the exit code.
	wgRouteOutput.Wait()

	agentLog.WithField("exit-code", exitCode).Info("got wait exit code")

	// Send empty message on tty channel to close the IO stream
	p.sendSeq(proc.seqStdio, []byte{})

	// Send exit code through tty channel
	p.sendSeq(proc.seqStdio, []byte{uint8(exitCode)})

	return nil
}

func (p *pod) buildProcessWithoutTerminal(proc *process) (*process, error) {
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

	if err := p.registerStdin(proc.seqStdio, wStdin, false); err != nil {
		return nil, err
	}

	proc.process.Stdin = rStdin
	proc.process.Stdout = wStdout
	proc.process.Stderr = wStderr

	proc.stdin = wStdin
	proc.stdout = rStdout
	proc.stderr = rStderr

	return proc, nil
}

func (p *pod) buildProcessWithTerminal(proc *process) (*process, error) {
	parentSock, childSock, err := utils.NewSockPair("console")
	if err != nil {
		return nil, err
	}

	proc.process.ConsoleSocket = childSock

	proc.consoleSock = parentSock

	return proc, nil
}

func (p *pod) buildProcess(hyperProcess hyper.Process) (*process, error) {
	var envList []string
	for _, env := range hyperProcess.Envs {
		envList = append(envList, fmt.Sprintf("%s=%s", env.Env, env.Value))
	}

	// we can specify the user and the group separated by :
	user := fmt.Sprintf("%s:%s", hyperProcess.User, hyperProcess.Group)

	libContProcess := libcontainer.Process{
		Cwd:              hyperProcess.Workdir,
		Args:             hyperProcess.Args,
		Env:              envList,
		User:             user,
		AdditionalGroups: hyperProcess.AdditionalGroups,
	}

	proc := &process{
		process:   libContProcess,
		seqStdio:  hyperProcess.Stdio,
		seqStderr: hyperProcess.Stderr,
	}

	if hyperProcess.Terminal {
		return p.buildProcessWithTerminal(proc)
	}

	return p.buildProcessWithoutTerminal(proc)
}

func (p *pod) runCmd(cmd hyper.HyperCmd, data []byte) ([]byte, error) {
	var cbWithReply cmdCbWithReply
	cb, exist := callbackList[cmd]
	if exist == false {
		cbWithReply, exist = callbackWithReplyList[cmd]
		if exist == false {
			return nil, fmt.Errorf("No callback found for command %q", hyper.CmdToString(cmd))
		}
	}

	// XXX: Do not change the format of these two log calls: they are used by the
	// XXX: tests!
	agentLog.Infof("%s", hyper.CmdToString(cmd)+"_start")

	var cbErr error
	var response []byte

	if cb != nil {
		cbErr = cb(p, data)
	} else if cbWithReply != nil {
		response, cbErr = cbWithReply(p, data)
	}

	agentLog.Infof("%s", hyper.CmdToString(cmd)+"_end")
	return response, cbErr
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
	pod.network = hyper.Network{
		Interfaces: payload.Interfaces,
		DNS:        payload.DNS,
		Routes:     payload.Routes,
	}

	if err := pod.setupNetwork(); err != nil {
		return fmt.Errorf("Could not setup the network: %v", err)
	}

	return nil
}

func destroyPodCb(pod *pod, data []byte) error {
	if pod.running == false {
		agentLog.WithField("pod", pod.id).Info("Pod not started, this is a no-op")
		return nil
	}

	pod.containersLock.Lock()
	for key, c := range pod.containers {
		if err := c.removeContainer(key); err != nil {
			return err
		}

		delete(pod.containers, key)
	}
	pod.containersLock.Unlock()

	if err := pod.removeNetwork(); err != nil {
		return fmt.Errorf("Could not remove the network: %v", err)
	}

	if err := unmountShareDir(); err != nil {
		return err
	}

	pod.id = ""
	pod.containers = make(map[string]*container)
	pod.running = false
	pod.stdinList = make(map[uint64]stdinInfo)
	pod.network = hyper.Network{}

	// Synchronize the caches on the system. This is needed to ensure
	// there is no pending transactions left before the VM is shut down.
	syscall.Sync()

	return nil
}

func addMounts(config *configs.Config, fsmaps []hyper.Fsmap) error {
	for _, fsmap := range fsmaps {

		source := fsmap.Source
		var err error

		if fsmap.SCSIAddr != "" {
			source, err = getSCSIDisk(fsmap.SCSIAddr)
			if err != nil {
				return err
			}
		}

		if !fsmap.AbsolutePath {
			source = filepath.Join(mountShareDirDest, fsmap.Source)
		}

		newMount := &configs.Mount{
			Source:      source,
			Destination: fsmap.Path,
			Device:      "bind",
			Flags:       syscall.MS_BIND | syscall.MS_REC,
		}

		if fsmap.ReadOnly {
			newMount.Flags |= syscall.MS_RDONLY
		}

		config.Mounts = append(config.Mounts, newMount)
	}

	return nil
}

func mountDevToRootfs(absoluteRootFs string) error {
	dest := filepath.Join(absoluteRootFs, "/dev")
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		if err := os.Mkdir(dest, 755); err != nil {
			return err
		}
	}

	if err := syscall.Mount("tmpfs", dest, "tmpfs", syscall.MS_NOSUID|syscall.MS_STRICTATIME, ""); err != nil {
		return fmt.Errorf("Could not mount tmpfs to %v: %v", dest, err)
	}

	return nil
}

func updateCapabilities(config *configs.Config, payload hyper.NewContainer) {
	if len(payload.Process.Capabilities.Bounding) > 0 {
		config.Capabilities = &configs.Capabilities{
			Bounding:    payload.Process.Capabilities.Bounding,
			Effective:   payload.Process.Capabilities.Effective,
			Inheritable: payload.Process.Capabilities.Inheritable,
			Permitted:   payload.Process.Capabilities.Permitted,
			Ambient:     payload.Process.Capabilities.Ambient,
		}
	} else {
		config.Capabilities = &configs.Capabilities{
			Bounding:    defaultCapsList,
			Effective:   defaultCapsList,
			Inheritable: defaultCapsList,
			Permitted:   defaultCapsList,
			Ambient:     defaultCapsList,
		}
	}
}

func newContainerCb(pod *pod, data []byte) error {
	var payload hyper.NewContainer

	// re-scan PCI bus
	// looking for hidden devices
	if err := ioutil.WriteFile(pciBusRescanFile, []byte("1"), pciBusMode); err != nil {
		agentLog.WithError(err).Warnf("Could not rescan PCI bus")
	}

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to run a new container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if payload.Process.ID == "" {
		payload.Process.ID = fmt.Sprintf("%d", payload.Process.Stdio)
	}

	if ctr := pod.getContainer(payload.ID); ctr != nil {
		return fmt.Errorf("Container %s already exists, impossible to create", payload.ID)
	}

	absoluteRootFs, err := mountContainerRootFs(payload)
	if err != nil {
		return err
	}

	if err := mountDevToRootfs(absoluteRootFs); err != nil {
		return err
	}

	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV

	config := configs.Config{
		Rootfs: absoluteRootFs,
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
		}),
		Cgroups: &configs.Cgroup{
			Name:   payload.ID,
			Parent: "system",
			Resources: &configs.Resources{
				MemorySwappiness: nil,
				AllowAllDevices:  nil,
				AllowedDevices:   configs.DefaultAllowedDevices,
				CpuQuota:         payload.Constraints.CPUQuota,
				CpuPeriod:        payload.Constraints.CPUPeriod,
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
				Flags:       defaultMountFlags,
			},
		},

		NoNewKeyring:    true,
		NoNewPrivileges: payload.Process.NoNewPrivileges,
	}

	updateCapabilities(&config, payload)

	// Populate config.Mounts with additional mounts provided through
	// fsmap.
	if err := addMounts(&config, payload.Fsmap); err != nil {
		return err
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
		pod:              pod,
		container:        libContContainer,
		config:           config,
		processes:        processes,
		systemMountsInfo: payload.SystemMountsInfo,
	}

	pod.setContainer(payload.ID, container)

	container.wgProcesses.Add(1)

	started := make(chan error)
	go pod.runContainerProcess(payload.ID, payload.Process.ID, payload.Process.Terminal, started)

	select {
	case err := <-started:
		if err != nil {
			return fmt.Errorf("Process could not be started: %v", err)
		}
	case <-time.After(time.Duration(runProcessTimeout) * time.Second):
		return fmt.Errorf("Process could not be started: timeout error")
	}

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

	ctr := pod.getContainer(payload.ID)
	if ctr == nil {
		return fmt.Errorf("Container %s not found, impossible to signal", payload.ID)
	}

	status, err := ctr.container.Status()
	if err != nil {
		return err
	}
	if status == libcontainer.Stopped {
		agentLog.Info("Container %s is Stopped on pod %s, discard signal %s", payload.ID, pod.id, payload.Signal.String())
		return nil
	}

	signalled := make(chan error)
	go func() {
		// Use AllProcesses to make sure we carry forward the flag passed by the runtime.
		signalled <- ctr.container.Signal(payload.Signal, payload.AllProcesses)
	}()

	select {
	case err := <-signalled:
		if err != nil {
			return fmt.Errorf("Process could not be signalled: %v", err)
		}
	case <-time.After(time.Duration(killProcessTimeout) * time.Second):
		return fmt.Errorf("Process could not be signalled: timeout error")
	}

	return nil
}

func (c *container) removeContainer(id string) error {
	c.wgProcesses.Wait()

	if err := c.container.Destroy(); err != nil {
		return err
	}

	// Unmount all devices that have been bind-mounted to /dev
	c.deviceNodesLock.Lock()
	for _, devNode := range c.deviceNodes {
		// Ignore error here since the device may already by unmounted
		// interactively
		syscall.Unmount(devNode, 0)
	}
	c.deviceNodesLock.Unlock()

	// Unmount /dev
	devPath := filepath.Join(c.config.Rootfs, "/dev")
	if err := syscall.Unmount(devPath, 0); err != nil {
		return err
	}

	return unmountContainerRootFs(id, c.config.Rootfs)
}

func (c *container) processList(id string, format string, args []string) ([]byte, error) {
	pids, err := c.container.Processes()
	if err != nil {
		return nil, err
	}

	switch format {
	case "table":
	case "json":
		return json.Marshal(pids)
	default:
		return nil, fmt.Errorf("invalid format option")
	}

	psArgs := args
	if len(psArgs) == 0 {
		psArgs = []string{"-ef"}
	}

	cmd := exec.Command("ps", psArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err, output)
	}

	lines := strings.Split(string(output), "\n")

	pidIndex := getPIDIndex(lines[0])

	// PID field not found
	if pidIndex == -1 {
		return nil, fmt.Errorf("failed to find PID field in ps output")
	}

	// append title
	var result bytes.Buffer

	result.WriteString(lines[0] + "\n")

	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if pidIndex >= len(fields) {
			return nil, fmt.Errorf("missing PID field: %s", line)
		}

		p, err := strconv.Atoi(fields[pidIndex])
		if err != nil {
			return nil, fmt.Errorf("failed to convert pid to int: %s", fields[pidIndex])
		}

		// appends pid line
		for _, pid := range pids {
			if pid == p {
				result.WriteString(line + "\n")
				break
			}
		}
	}

	return result.Bytes(), nil
}

func getPIDIndex(title string) int {
	// looking for PID field in ps title
	fields := strings.Fields(title)
	for i, f := range fields {
		if f == "PID" {
			return i
		}
	}
	return -1
}

func removeContainerCb(pod *pod, data []byte) error {
	var payload hyper.RemoveContainer

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to remove the container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	ctr := pod.getContainer(payload.ID)

	if ctr == nil {
		return fmt.Errorf("Container %s not found, impossible to remove", payload.ID)
	}

	status, err := ctr.container.Status()
	if err != nil {
		return err
	}

	if status == libcontainer.Running {
		return fmt.Errorf("Container %s running, impossible to remove", payload.ID)
	}

	if err := ctr.removeContainer(payload.ID); err != nil {
		return err
	}

	pod.deleteContainer(payload.ID)

	return nil
}

func processListCb(pod *pod, data []byte) ([]byte, error) {
	var payload hyper.PsContainer

	if pod.running == false {
		return nil, fmt.Errorf("Pod not started, impossible to list processes")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if _, exist := pod.containers[payload.ID]; exist == false {
		return nil, fmt.Errorf("Container %s not found, impossible to list processes", payload.ID)
	}

	status, err := pod.containers[payload.ID].container.Status()
	if err != nil {
		return nil, err
	}

	if status != libcontainer.Running {
		return nil, fmt.Errorf("Container %s is not running, impossible to list processes", payload.ID)
	}

	response, err := pod.containers[payload.ID].processList(payload.ID, payload.Format, payload.Args)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func execCb(pod *pod, data []byte) error {
	var payload hyper.Exec

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to exec process on the container")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if payload.Process.ID == "" {
		payload.Process.ID = fmt.Sprintf("%d", payload.Process.Stdio)
	}

	ctr := pod.getContainer(payload.ContainerID)

	if ctr == nil {
		return fmt.Errorf("Container %s not found, impossible to execute process %s", payload.ContainerID, payload.Process.ID)
	}

	status, err := ctr.container.Status()
	if err != nil {
		return err
	}

	if status != libcontainer.Running {
		return fmt.Errorf("Container %s not running, impossible to execute process %s", payload.ContainerID, payload.Process.ID)
	}

	process := ctr.getProcess(payload.Process.ID)

	if process != nil {
		return fmt.Errorf("Process %s already exists", payload.Process.ID)
	}

	process, err = pod.buildProcess(payload.Process)
	if err != nil {
		return err
	}

	ctr.setProcess(payload.Process.ID, process)

	ctr.wgProcesses.Add(1)

	started := make(chan error)
	go pod.runContainerProcess(payload.ContainerID, payload.Process.ID, payload.Process.Terminal, started)

	select {
	case err := <-started:
		if err != nil {
			return fmt.Errorf("Process could not be started: %v", err)
		}
	case <-time.After(time.Duration(runProcessTimeout) * time.Second):
		return fmt.Errorf("Process could not be started: timeout error")
	}

	return nil
}

func readyCb(pod *pod, data []byte) error {
	return nil
}

func pingCb(pod *pod, data []byte) error {
	return nil
}

func (p *pod) findTermFromSeqID(seqID uint64) (*os.File, string) {
	p.containersLock.RLock()
	defer p.containersLock.RUnlock()

	for cid, container := range p.containers {
		container.processesLock.RLock()

		for _, process := range container.processes {
			if process.seqStdio == seqID {
				container.processesLock.RUnlock()
				return process.termMaster, cid
			}
		}
		container.processesLock.RUnlock()
	}

	return nil, ""
}

func winsizeCb(pod *pod, data []byte) error {
	var payload hyper.Winsize

	if pod.running == false {
		return fmt.Errorf("Pod not started, impossible to resize the window")
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	term, cid := pod.findTermFromSeqID(payload.Sequence)
	if cid == "" {
		// The sequence ID could be not found in case the process returned
		// and the process has been removed from the container map.
		// We should not error in that case, and discard the received signal.
		agentLog.Warnf("Could not find sequence ID %d on pod %s, discard SIGWINCH", payload.Sequence, pod.id)
		return nil
	}

	ctr := pod.getContainer(cid)
	status, err := ctr.container.Status()
	if err != nil {
		return err
	}

	if status == libcontainer.Stopped {
		agentLog.Info("Container %s is Stopped on pod %s, discard SIGWINCH", cid, pod.id)
		return nil
	} else if status != libcontainer.Running {
		return fmt.Errorf("Container %s %s, impossible to resize window", cid, status.String())
	}

	window := new(struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	})

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		term.Fd(),
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(window))); errno != 0 {
		return fmt.Errorf("Could not get window size: %v", errno.Error())
	}

	window.Row = payload.Row
	window.Col = payload.Column

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		term.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(window))); errno != 0 {
		return fmt.Errorf("Could not set window size: %v", errno.Error())
	}

	return nil
}

func newConfig(level logrus.Level) agentConfig {
	config := agentConfig{}
	config.logLevel = level
	return config
}

//Get the agent configuration from kernel cmdline
func (c *agentConfig) getConfig(cmdLineFile string) error {

	if cmdLineFile == "" {
		return fmt.Errorf("Kernel cmdline file cannot be empty")
	}

	kernelCmdline, err := ioutil.ReadFile(cmdLineFile)
	if err != nil {
		return err
	}

	words := strings.Fields(string(kernelCmdline))
	for _, w := range words {
		word := string(w)
		if err := c.parseCmdlineOption(word); err != nil {
			agentLog.WithFields(logrus.Fields{
				"error":  err,
				"option": word,
			}).Warn("Failed to parse kernel option")
		}
	}
	return nil
}

func applyConfig(config agentConfig) {
	agentLog.Logger.SetLevel(config.logLevel)
}

//Parse a string that represents a kernel cmdline option
func (c *agentConfig) parseCmdlineOption(option string) error {

	const (
		optionPosition = iota
		valuePosition
		optionSeparator = "="
	)

	split := strings.Split(option, optionSeparator)

	if len(split) < valuePosition+1 {
		return nil
	}

	switch split[optionPosition] {
	case logLevelFlag:
		level, err := logrus.ParseLevel(split[valuePosition])
		if err != nil {
			return err
		}
		c.logLevel = level
	default:
		if strings.HasPrefix(split[optionPosition], optionPrefix) {
			return fmt.Errorf("Unknown option %s", split[optionPosition])
		}
	}
	return nil

}
