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
	"io/ioutil"
	"os"
	"testing"
)

func TestFileCopy(t *testing.T) {

	//Create Tempfile to tests
	tmpfile, err := ioutil.TempFile("", "agent-unit-test")
	if err != nil {
		t.Fatal("expected an error: Failed to create TempFile")
	}
	defer os.Remove(tmpfile.Name())

	type args struct {
		srcPath string
		dstPath string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Source/destination paths are empty",
			args{srcPath: "", dstPath: ""}, true},
		{"Source path is empty",
			args{srcPath: "", dstPath: "./file"}, true},
		{"Destination path is empty",
			args{srcPath: "./file", dstPath: ""}, true},
		{"Source file does not exist",
			args{srcPath: "./f/f/false", dstPath: "./d"}, true},
		{"Destination path does not exist",
			args{srcPath: tmpfile.Name(), dstPath: tmpfile.Name() + "/non-existing/dest"}, true},
		{"Successful File Copy",
			args{srcPath: tmpfile.Name(), dstPath: tmpfile.Name() + "-dest"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := fileCopy(tt.args.srcPath, tt.args.dstPath); (err != nil) != tt.wantErr {
				t.Errorf("fileCopy() error = %v, wantErr %v", err, tt.wantErr)
			}
			os.RemoveAll(tt.args.dstPath)
		})
	}
}
