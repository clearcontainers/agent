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
	"os"
	"path/filepath"
	"syscall"
	"time"

	goudev "github.com/jochenvg/go-udev"
)

const mountPerm = os.FileMode(0755)
const devPath = "/dev"

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

	return syscall.Mount(tag, mountShareDirDest, type9pFs, syscall.MS_MGC_VAL|syscall.MS_NODEV, "trans=virtio,version=9p2000.L,posixacl,cache=mmap")

}

func unmountShareDir() error {
	if err := syscall.Unmount(mountShareDirDest, 0); err != nil {
		return err
	}

	return os.RemoveAll(containerMountDest)
}

func waitForBlockDevice(deviceName string) error {
	devicePath := filepath.Join(devPath, deviceName)

	if _, err := os.Stat(devicePath); err == nil {
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
		agentLog.Infof("Started listening for udev events for block device hotplug")

		// Check if the device already exists.
		if _, err := os.Stat(devicePath); err == nil {
			agentLog.Infof("Device %s already hotplugged, quit listening", deviceName)
		} else {

			for d := range ch {
				agentLog.Infof("Event:", d.Syspath(), d.Action())
				if d.Action() == "add" && filepath.Base(d.Devpath()) == deviceName {
					agentLog.Infof("Hotplug event received for device %s", deviceName)
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

func mountContainerRootFs(containerID, image, rootFs, fsType string) (string, error) {
	dest := filepath.Join(containerMountDest, containerID, "root")
	if err := os.MkdirAll(dest, os.FileMode(0755)); err != nil {
		return "", err
	}

	var source string
	if fsType != "" {
		source = filepath.Join(devPath, image)
		if err := waitForBlockDevice(image); err != nil {
			return "", err
		}

		if err := mount(source, dest, fsType, 0); err != nil {
			return "", err
		}
	} else {
		source = filepath.Join(mountShareDirDest, image)
		if err := bindMount(source, dest, false); err != nil {
			return "", err
		}
	}

	mountingPath := filepath.Join(dest, rootFs)
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

	if err := os.RemoveAll(containerPath); err != nil {
		return err
	}

	return nil
}

func ioctl(fd uintptr, flag, data uintptr) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, flag, data); err != 0 {
		return err
	}

	return nil
}
