//
// Copyright 2015 The rkt Authors
// Copyright (c) 2016 Intel Corporation
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
	"testing"
)

func TestBindMountInvalidSourceSymlink(t *testing.T) {
	source := filepath.Join(testDir, "fooFile")
	os.Remove(source)

	err := bindMount(source, "", true)
	if err == nil {
		t.Fatal()
	}
}

func TestBindMountFailingMount(t *testing.T) {
	source := filepath.Join(testDir, "fooLink")
	fakeSource := filepath.Join(testDir, "fooFile")
	os.Remove(source)
	os.Remove(fakeSource)

	_, err := os.OpenFile(fakeSource, os.O_CREATE, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(fakeSource, source)
	if err != nil {
		t.Fatal(err)
	}

	err = bindMount(source, "", true)
	if err == nil {
		t.Fatal()
	}
}

func TestBindMountSuccessful(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip(testDisabledAsNonRoot)
	}

	source := filepath.Join(testDir, "fooDirSrc")
	dest := filepath.Join(testDir, "fooDirDest")
	syscall.Unmount(dest, 0)
	os.Remove(source)
	os.Remove(dest)

	err := os.MkdirAll(source, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = os.MkdirAll(dest, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = bindMount(source, dest, true)
	if err != nil {
		t.Fatal(err)
	}

	syscall.Unmount(dest, 0)
}

func TestEnsureDestinationExistsNonExistingSource(t *testing.T) {
	err := ensureDestinationExists("", "", "")
	if err == nil {
		t.Fatal()
	}
}

func TestEnsureDestinationExistsWrongParentDir(t *testing.T) {
	source := filepath.Join(testDir, "fooFile")
	dest := filepath.Join(source, "fooDest")
	os.Remove(source)
	os.Remove(dest)

	_, err := os.OpenFile(source, os.O_CREATE, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = ensureDestinationExists(source, dest, "")
	if err == nil {
		t.Fatal()
	}
}

func TestEnsureDestinationExistsSuccessfulSrcDir(t *testing.T) {
	source := filepath.Join(testDir, "fooDirSrc")
	dest := filepath.Join(testDir, "fooDirDest")
	os.Remove(source)
	os.Remove(dest)

	err := os.MkdirAll(source, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = ensureDestinationExists(source, dest, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDestinationExistsSuccessfulSrcFile(t *testing.T) {
	source := filepath.Join(testDir, "fooDirSrc")
	dest := filepath.Join(testDir, "fooDirDest")
	os.Remove(source)
	os.Remove(dest)

	_, err := os.OpenFile(source, os.O_CREATE, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	err = ensureDestinationExists(source, dest, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindSCSIDisk(t *testing.T) {
	scsiTestDir := filepath.Join(testDir, "testSCSIDir")
	os.RemoveAll(scsiTestDir)

	defer os.RemoveAll(scsiTestDir)

	scsiDiskPrefix = scsiTestDir + "/0:0:"
	scsiAddr := "1:1"

	_, err := findSCSIDisk(scsiAddr)
	if err == nil {
		t.Fatal()
	}

	path := fmt.Sprintf("%s%s/device/block", scsiDiskPrefix, scsiAddr)
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := findSCSIDisk(scsiAddr); err == nil {
		t.Fatal()
	}

	devFile := filepath.Join(path, "sda")

	f, err := os.OpenFile(devFile, os.O_CREATE, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	diskName, err := findSCSIDisk(scsiAddr)
	if err != nil {
		t.Fatal(err)
	}

	if diskName != "sda" {
		t.Fatal()
	}

	devFile = filepath.Join(path, "sdb")

	f, err = os.OpenFile(devFile, os.O_CREATE, mountPerm)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := findSCSIDisk(scsiAddr); err == nil {
		t.Fatal()
	}
}

func TestScanSCSIBus(t *testing.T) {
	scsiHostPath = filepath.Join(testDir, "scsi_host")
	os.RemoveAll(scsiHostPath)

	defer os.RemoveAll(scsiHostPath)

	scsiAddr := "1"

	if err := scanSCSIBus(scsiAddr); err == nil {
		t.Fatal()
	}

	if err := os.MkdirAll(scsiHostPath, mountPerm); err != nil {
		t.Fatal(err)
	}

	scsiAddr = "1:1"
	if err := scanSCSIBus(scsiAddr); err != nil {
		t.Fatal(err)
	}

	host := filepath.Join(scsiHostPath, "host0")
	if err := os.MkdirAll(host, mountPerm); err != nil {
		t.Fatal(err)
	}

	if err := scanSCSIBus(scsiAddr); err != nil {
		t.Fatal()
	}

	scanPath := filepath.Join(host, "scan")
	if _, err := os.Stat(scanPath); err != nil {
		t.Fatal(err)
	}
}
