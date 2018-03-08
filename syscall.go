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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	hyper "github.com/clearcontainers/agent/api"
	goudev "github.com/jochenvg/go-udev"
	"github.com/sirupsen/logrus"
)

const mountPerm = os.FileMode(0755)
const devPath = "/dev"
const mntOptions9p = "trans=virtio,version=9p2000.L"

// bindMount bind mounts a source in to a destination, with the recursive
// flag if needed.
func bindMount(source, destination string, recursive bool) error {
	flags := syscall.MS_BIND

	if recursive == true {
		flags |= syscall.MS_REC
	}

	return mount(source, destination, "bind", flags)
}

// mount mounts a source in to a destination. This will do some bookkeeping:
// * evaluate all symlinks
// * ensure the source exists
func mount(source, destination, fsType string, flags int) error {
	var options string
	if fsType == "xfs" {
		options = "nouuid"
	}

	absSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("Could not resolve symlink for source %v", source)
	}

	if err := ensureDestinationExists(absSource, destination, fsType); err != nil {
		return fmt.Errorf("Could not create destination mount point: %v: %v", destination, err)
	}

	if err := syscall.Mount(absSource, destination, fsType, uintptr(flags), options); err != nil {
		return fmt.Errorf("Could not bind mount %v to %v: %v", absSource, destination, err)
	}

	return nil
}

// ensureDestinationExists will recursively create a given mountpoint. If directories
// are created, their permissions are initialized to mountPerm
func ensureDestinationExists(source, destination string, fsType string) error {
	fileInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("could not stat source location: %v", source)
	}

	targetPathParent, _ := filepath.Split(destination)
	if err := os.MkdirAll(targetPathParent, mountPerm); err != nil {
		return fmt.Errorf("could not create parent directory: %v", targetPathParent)
	}

	if fsType != "bind" || fileInfo.IsDir() {
		if err := os.Mkdir(destination, mountPerm); !os.IsExist(err) {
			return err
		}
	} else {
		file, err := os.OpenFile(destination, os.O_CREATE, mountPerm)
		if err != nil {
			return err
		}

		file.Close()
	}
	return nil
}

func mountShareDir(tag string) error {
	if tag == "" {
		return fmt.Errorf("Invalid mount tag, should not be empty")
	}

	if err := os.MkdirAll(mountShareDirDest, os.FileMode(0755)); err != nil {
		return err
	}

	return syscall.Mount(tag, mountShareDirDest, type9pFs, syscall.MS_MGC_VAL|syscall.MS_NODEV, mntOptions9p)
}

func unmountShareDir() error {
	if err := syscall.Unmount(mountShareDirDest, 0); err != nil {
		return err
	}

	return os.RemoveAll(containerMountDest)
}

var (
	// Here in "0:0", the first number is the SCSI host number, while the second number is always 0.
	scsiHostChannel = "/0:0:"

	scsiDiskPrefix = "/sys/class/scsi_disk" + scsiHostChannel

	scsiDiskSuffix = "/device/block"
)

func waitForBlockDevice(deviceName string, isSCSIAddr bool) error {
	var path string

	if isSCSIAddr {
		path = filepath.Join(scsiDiskPrefix+deviceName, scsiDiskSuffix)
	} else {
		path = filepath.Join(devPath, deviceName)
	}

	if _, err := os.Stat(path); err == nil {
		return nil
	}

	u := goudev.Udev{}

	// Create a monitor listening on a NetLink socket.
	monitor := u.NewMonitorFromNetlink("udev")

	// Add filter to watch for just block devices.
	if err := monitor.FilterAddMatchSubsystemDevtype("block", "disk"); err != nil {
		return err
	}

	// Create done signal channel for signalling epoll loop on the monitor socket.
	done := make(chan struct{})

	// Create channel to signal when desired udev event has been received.
	doneListening := make(chan bool)

	// Start monitor goroutine.
	ch, _ := monitor.DeviceChan(done)

	go func() {
		fieldLogger := agentLog.WithField("device", deviceName)

		fieldLogger.Info("Started listening for udev events for block device hotplug")

		// Check if the device already exists.
		if _, err := os.Stat(path); err == nil {
			fieldLogger.Info("Device already hotplugged, quit listening")
		} else {

			for d := range ch {
				fieldLogger = fieldLogger.WithFields(logrus.Fields{
					"udev-path":  d.Syspath(),
					"dev-path":   d.Devpath(),
					"udev-event": d.Action(),
				})

				fieldLogger.Info("got udev event")

				if isSCSIAddr && d.Action() == "add" && strings.Contains(d.Devpath(), scsiHostChannel+deviceName+"/block") {
					fieldLogger.Info("SCSI hotplug event received")
					break
				} else if d.Action() == "add" && filepath.Base(d.Devpath()) == deviceName {
					fieldLogger.Info("Block hotplug event received")
					break
				}
			}
		}
		close(doneListening)
	}()

	select {
	case <-doneListening:
		close(done)
	case <-time.After(time.Duration(1) * time.Second):
		close(done)
		return fmt.Errorf("Timed out waiting for device %s", deviceName)
	}

	return nil
}

var scsiHostPath = "/sys/class/scsi_host"

// scanSCSIBus scans SCSI bus for the given SCSI address(SCSI-Id and LUN)
func scanSCSIBus(scsiAddr string) error {
	files, err := ioutil.ReadDir(scsiHostPath)
	if err != nil {
		return err
	}

	tokens := strings.Split(scsiAddr, ":")
	if len(tokens) != 2 {
		return fmt.Errorf("Unexpected format for SCSI Address : %s, expect SCSIID:LUN", scsiAddr)
	}

	// Scan scsi host passing in the channel, SCSI id and LUN, channel is always 0
	scanData := []byte(fmt.Sprintf("0 %s %s", tokens[0], tokens[1]))

	for _, file := range files {
		host := file.Name()
		scanPath := filepath.Join(scsiHostPath, host, "scan")
		if err := ioutil.WriteFile(scanPath, scanData, 0200); err != nil {
			return err
		}
	}

	return nil
}

// findSCSIDisk finds the SCSI disk name associated with the given SCSI address.
// This approach eliminates the need to predict the disk name on the host side,
// but we do need to rescan SCSI bus for this.
func findSCSIDisk(scsiAddr string) (string, error) {
	scsiPath := filepath.Join(scsiDiskPrefix+scsiAddr, scsiDiskSuffix)

	files, err := ioutil.ReadDir(scsiPath)
	if err != nil {
		return "", err
	}

	l := len(files)

	if l == 0 || l > 1 {
		return "", fmt.Errorf("Expecting a single SCSI device, found %v", files)
	}

	return files[0].Name(), nil
}

// getSCSIDisk scans the SCSI bus for the SCSI address provided, waits for the SCSI disk
// to become available and returns the device name associated with the disk.
func getSCSIDisk(scsiAddr string) (string, error) {
	if err := scanSCSIBus(scsiAddr); err != nil {
		return "", err
	}

	// Check if disk is available, and find the disk name for the SCSI address
	scsiDiskName, err := findSCSIDisk(scsiAddr)

	if err == nil {
		if err = waitForBlockDevice(scsiDiskName, false); err != nil {
			return "", err
		}
	} else {
		// If device node is not found, wait for udev event for the scsi disk,
		// with the format "0:SCSIId:LUN/block"

		if err := waitForBlockDevice(scsiAddr, true); err != nil {
			return "", err
		}

		scsiDiskName, err = findSCSIDisk(scsiAddr)
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(devPath, scsiDiskName), nil
}

func mountContainerRootFs(payload hyper.NewContainer) (string, error) {
	dest := filepath.Join(containerMountDest, payload.ID, "root")
	if err := os.MkdirAll(dest, os.FileMode(0755)); err != nil {
		return "", err
	}

	var source string
	var err error

	if payload.FsType != "" {
		// If SCSI adddress is provided, use that to find SCSI disk
		if payload.SCSIAddr != "" {
			source, err = getSCSIDisk(payload.SCSIAddr)
			if err != nil {
				return "", err
			}
		} else {
			source = filepath.Join(devPath, payload.Image)
			if err := waitForBlockDevice(payload.Image, false); err != nil {
				return "", err
			}
		}

		if err := mount(source, dest, payload.FsType, 0); err != nil {
			return "", fmt.Errorf("Mount rootfs command failed: %s", err)
		}
	} else {
		source = filepath.Join(mountShareDirDest, payload.Image)
		if err := bindMount(source, dest, false); err != nil {
			return "", err
		}
	}

	mountingPath := filepath.Join(dest, payload.RootFs)
	if err := bindMount(mountingPath, mountingPath, true); err != nil {
		return "", err
	}

	return mountingPath, nil
}

func unmountContainerRootFs(containerID, mountingPath string) error {
	if err := syscall.Unmount(mountingPath, 0); err != nil {
		return err
	}

	containerPath := filepath.Join(containerMountDest, containerID, "root")
	if err := syscall.Unmount(containerPath, 0); err != nil {
		return err
	}

	return os.RemoveAll(containerPath)
}

func ioctl(fd uintptr, flag, data uintptr) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, flag, data); err != 0 {
		return err
	}

	return nil
}
