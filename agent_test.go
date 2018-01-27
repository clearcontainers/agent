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
	"io/ioutil"
	"os"
	"testing"

	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/sirupsen/logrus"
)

const testDisabledAsNonRoot = "Test disabled as requires root privileges"

// package variables set in TestMain
var testDir = ""

func TestMain(m *testing.M) {
	var err error
	testDir, err = ioutil.TempDir("", "cc-agent-tmp-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(testDir)

	ret := m.Run()
	os.Exit(ret)

}

func TestParseCmdlineOption(t *testing.T) {
	type args struct {
		option string
	}

	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantLevel logrus.Level
	}{
		{"Empty cmdline",
			args{""}, false, defaultLogLevel},
		{"Log config info",
			args{"agent.log=info"}, false, logrus.InfoLevel},
		{"Log config debug",
			args{"agent.log=debug"}, false, logrus.DebugLevel},
		{"Log config warn",
			args{"agent.log=warn"}, false, logrus.WarnLevel},
		{"Log config empty",
			args{"agent.log="}, true, defaultLogLevel},
		{"Invalid log config",
			args{"agent.log=ino"}, true, defaultLogLevel},
		{"Unknown option",
			args{"agent.logx=ino"}, true, defaultLogLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config agentConfig
			config.logLevel = defaultLogLevel

			if err := config.parseCmdlineOption(tt.args.option); (err != nil) != tt.wantErr {
				t.Errorf("parseCmdlineOption(%s) error = %v, wantErr %v",
					tt.args.option, err, tt.wantErr)
			}
			if config.logLevel != tt.wantLevel {
				t.Errorf("parseCmdlineOption(%s) config.logLevel = %s, wanted %s",
					tt.args.option, config.logLevel, tt.wantLevel)

			}
		})
	}
}

func createTmpfile(prefix string, content string) (string, error) {

	tmpfile, err := ioutil.TempFile(testDir, prefix)
	if err != nil {
		return "", err
	}

	if _, err := tmpfile.WriteString(content); err != nil {
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		return "", err
	}

	tmpfile.Sync()
	return tmpfile.Name(), nil
}

func TestAgentConfigGetConfig(t *testing.T) {

	nonExitingConfig := "/tmp/non-existhing-config-file"
	os.RemoveAll(nonExitingConfig)

	debugConfigFile, err := createTmpfile("debug-config", "init=systemd agent.log=debug")
	if err != nil {
		t.Fatalf("Failed to create debugConfigFile %v", err)
	}
	defer os.Remove(debugConfigFile)

	type fields struct {
		logLevel logrus.Level
	}
	type args struct {
		cmdLineFile string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantErr   bool
		wantLevel logrus.Level
	}{
		{"Empty cmdLineFile",
			fields{logrus.InfoLevel}, args{""}, true, logrus.InfoLevel},
		{"Non-existing cmdLineFile",
			fields{logrus.InfoLevel}, args{nonExitingConfig}, true, logrus.InfoLevel},
		{"Debug config",
			fields{logrus.InfoLevel}, args{debugConfigFile}, false, logrus.DebugLevel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &agentConfig{
				logLevel: tt.fields.logLevel,
			}
			err := c.getConfig(tt.args.cmdLineFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("agentConfig.getConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if c.logLevel != tt.wantLevel {
				t.Errorf("agentConfig.Level = %s, wantLevel %s", c.logLevel, tt.wantLevel)
			}
		})
	}
}

func TestReadCtl(t *testing.T) {
	f, err := ioutil.TempFile("", "ctl")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	hCmd := uint32(5)
	p := &pod{ctl: f}

	// file is empty, read should fail
	_, _, err = p.readCtl()
	if err == nil {
		t.Error(err)
	}

	// no enough bytes, read should fail
	buff := make([]byte, ctlHeaderSize-1)
	f.Write(buff)
	f.Seek(0, 0)
	_, _, err = p.readCtl()
	if err == nil {
		t.Error(err)
	}

	// there is no data, read should fail
	buff = make([]byte, ctlHeaderSize)
	f.Seek(0, 0)
	binary.BigEndian.PutUint32(buff[4:ctlHeaderSize], ctlHeaderSize+1)
	f.Write(buff)
	f.Seek(0, 0)
	_, _, err = p.readCtl()
	if err == nil {
		t.Error(err)
	}

	bufferSizes := []uint32{0, 2, 55, 278, 698, 1056, 3598, 6527, 10830, 56386, 894305, 9652381}
	for _, s := range bufferSizes {
		f.Seek(0, 0)

		// write command and length
		buff = make([]byte, ctlHeaderSize)
		binary.BigEndian.PutUint32(buff[:4], hCmd)
		binary.BigEndian.PutUint32(buff[4:ctlHeaderSize], s+ctlHeaderSize)
		n, err := f.Write(buff)
		if err != nil {
			t.Error(err)
		}
		if uint32(n) != uint32(ctlHeaderSize) {
			t.Errorf("expected: %d, actual: %d", n, ctlHeaderSize)
		}

		// write data
		data := make([]byte, s)
		n, err = f.Write(data)
		if err != nil {
			t.Error(err)
		}
		if uint32(n) != uint32(s) {
			t.Errorf("expected: %d, actual: %d", n, s)
		}

		f.Seek(0, 0)

		c, d, err := p.readCtl()
		if err != nil {
			t.Error(err)
		}
		if uint32(hCmd) != uint32(c) {
			t.Errorf("expected: %d, actual: %d", hCmd, c)
		}
		if s == 0 && len(d) != 0 {
			t.Errorf("expected: 0, actual: %d", len(d))
		} else if len(data) != len(d) {
			t.Errorf("expected: %d, actual: %d", len(data), len(d))
		}
	}
}

func TestReadTty(t *testing.T) {
	f, err := ioutil.TempFile("", "tty")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	seq := uint64(5)
	p := &pod{tty: f}

	// file is empty, read should fail
	_, _, err = p.readTty()
	if err == nil {
		t.Error(err)
	}

	// no enough bytes, read should fail
	buff := make([]byte, ttyHeaderSize-1)
	f.Write(buff)
	f.Seek(0, 0)
	_, _, err = p.readTty()
	if err == nil {
		t.Error(err)
	}

	// there is no data, read should fail
	buff = make([]byte, ttyHeaderSize)
	f.Seek(0, 0)
	binary.BigEndian.PutUint32(buff[8:ttyHeaderSize], ttyHeaderSize+1)
	f.Write(buff)
	f.Seek(0, 0)
	_, _, err = p.readTty()
	if err == nil {
		t.Error(err)
	}

	bufferSizes := []uint32{0, 2, 55, 278, 698, 1056, 3598, 6527, 10830, 56386, 894305, 9652381}
	for _, s := range bufferSizes {
		f.Seek(0, 0)

		// write command and length
		buff = make([]byte, ttyHeaderSize)
		binary.BigEndian.PutUint64(buff[:8], seq)
		binary.BigEndian.PutUint32(buff[8:ttyHeaderSize], s+ttyHeaderSize)
		n, err := f.Write(buff)
		if err != nil {
			t.Error(err)
		}
		if uint32(n) != uint32(ttyHeaderSize) {
			t.Errorf("expected: %d, actual: %d", n, ttyHeaderSize)
		}

		// write data
		data := make([]byte, s)
		n, err = f.Write(data)
		if err != nil {
			t.Error(err)
		}
		if uint32(n) != uint32(s) {
			t.Errorf("expected: %d, actual: %d", n, s)
		}

		f.Seek(0, 0)

		c, d, err := p.readTty()
		if err != nil {
			t.Error(err)
		}
		if seq != uint64(c) {
			t.Errorf("expected: %d, actual: %d", seq, c)
		}
		if len(data) != len(d) {
			t.Errorf("expected: %d, actual: %d", len(data), len(d))
		}
	}
}
