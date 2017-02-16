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
)

const mountPerm = os.FileMode(0755)

// bindMount bind mounts a source in to a destination. This will
// do some bookkeeping:
// * evaluate all symlinks
// * ensure the source exists
// * recursively create the destination
func bindMount(source, destination string, recursive bool) error {
	mountFlag := syscall.MS_BIND

	absSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("Could not resolve symlink for source %v", source)
	}

	if recursive == true {
		mountFlag |= syscall.MS_REC
	}

	if err := ensureDestinationExists(absSource, destination); err != nil {
		return fmt.Errorf("Could not create destination mount point: %v", destination)
	} else if err := syscall.Mount(absSource, destination, "bind", uintptr(mountFlag), ""); err != nil {
		return fmt.Errorf("Could not bind mount %v to %v", absSource, destination)
	}

	return nil
}

// ensureDestinationExists will recursively create a given mountpoint. If directories
// are created, their permissions are initialized to mountPerm
func ensureDestinationExists(source, destination string) error {
	fileInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("could not stat source location: %v", source)
	}

	targetPathParent, _ := filepath.Split(destination)
	if err := os.MkdirAll(targetPathParent, mountPerm); err != nil {
		return fmt.Errorf("could not create parent directory: %v", targetPathParent)
	}

	if fileInfo.IsDir() {
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

	return syscall.Mount(tag, mountShareDirDest, type9pFs, syscall.MS_MGC_VAL|syscall.MS_NODEV, "trans=virtio")
}

func unmountShareDir() error {
	if err := syscall.Unmount(mountShareDirDest, 0); err != nil {
		return err
	}

	return os.RemoveAll(containerMountDest)
}

func mountContainerRootFs(containerID, rootFs string) (string, error) {
	dest := filepath.Join(containerMountDest, containerID, "root")
	if err := os.MkdirAll(dest, os.FileMode(0755)); err != nil {
		return "", err
	}

	source := filepath.Join(mountShareDirDest, containerID)
	if err := bindMount(source, dest, false); err != nil {
		return "", err
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
