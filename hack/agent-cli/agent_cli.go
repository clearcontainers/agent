//
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
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/golang/glog"
	"github.com/urfave/cli"

	agentApi "github.com/clearcontainers/agent/api"
	"github.com/containers/virtcontainers/pkg/hyperstart"
)

const unixSocketType = "unix"

const (
	commandInputMsg  = "Command: "
	sequenceInputMsg = "Sequence: "
	payloadInputMsg  = "Payload: "
)

const (
	sendTty = "tty"
	exit    = "exit"
)

var cmdList = map[int]string{
	1:   agentApi.CmdToString(agentApi.StartPodCmd),
	2:   agentApi.CmdToString(agentApi.DestroyPodCmd),
	3:   agentApi.CmdToString(agentApi.ExecCmd),
	4:   agentApi.CmdToString(agentApi.ReadyCmd),
	5:   agentApi.CmdToString(agentApi.AckCmd),
	6:   agentApi.CmdToString(agentApi.ErrorCmd),
	7:   agentApi.CmdToString(agentApi.WinsizeCmd),
	8:   agentApi.CmdToString(agentApi.PingCmd),
	9:   agentApi.CmdToString(agentApi.NewContainerCmd),
	10:  agentApi.CmdToString(agentApi.KillContainerCmd),
	11:  agentApi.CmdToString(agentApi.RemoveContainerCmd),
	50:  sendTty,
	100: exit,
}

var waitingInput = false
var waitingInputText = ""

func magicLog(format string, args ...interface{}) {
	waitInput, waitInputText := getWaitingInputs()

	if waitInput == true {
		fmt.Println("")
	}

	fmt.Printf(format, args...)

	if waitInput == true {
		fmt.Println("")
		fmt.Printf(waitInputText)
	}
}

func setWaitingInputs(input bool, inputText string) {
	waitingInput = input
	waitingInputText = inputText
}

func getWaitingInputs() (bool, string) {
	return waitingInput, waitingInputText
}

func dumpSupportedCommands() {
	magicLog("== Supported commands ==\n")
	magicLog("  1 - STARTPOD\n")
	magicLog("  2 - DESTROYPOD\n")
	magicLog("  3 - EXECCMD\n")
	magicLog("  4 - READY\n")
	magicLog("  5 - ACK\n")
	magicLog("  6 - ERROR\n")
	magicLog("  7 - WINSIZE\n")
	magicLog("  8 - PING\n")
	magicLog("  9 - NEWCONTAINER\n")
	magicLog(" 10 - KILLCONTAINER\n")
	magicLog(" 11 - REMOVECONTAINER\n")
	magicLog(" 50 - TTY SEQUENCE\n")
	magicLog("100 - EXIT\n\n")
}

func dumpFrame(msg interface{}) {
	switch m := msg.(type) {
	case hyperstart.DecodedMessage:
		magicLog("DecodedMessage {\n\tCode: %x\n\tMessage: %s\n}\n", m.Code, m.Message)
	case hyperstart.TtyMessage:
		magicLog("TtyMessage {\n\tSession: %x\n\tMessage: %s\n}\n", m.Session, m.Message)
	}
}

func readStringNoDelimiter(reader *bufio.Reader, delim byte) (string, error) {
	input, err := reader.ReadBytes('\n')
	if err != nil {
		return "", err
	}

	strInput := string(input[:len(input)-1])

	return strInput, nil
}

func convertInputToCmd(input string) (string, error) {
	intInput, err := strconv.Atoi(input)
	if err != nil {
		return "", err
	}

	_, ok := cmdList[intInput]
	if ok == false {
		return "", fmt.Errorf("%d is not a valid command", intInput)
	}

	return cmdList[intInput], nil
}

func sendMessage(h *hyperstart.Hyperstart, ctlType bool, cmd string, payload string) error {
	payloadSlice, err := hyperstart.FormatMessage(payload)
	if err != nil {
		return err
	}

	if ctlType == true {
		msg, err := h.SendCtlMessage(cmd, payloadSlice)
		if err != nil {
			return err
		}

		if msg != nil {
			dumpFrame(*msg)
		}
	} else {
		seq, err := strconv.ParseUint(cmd, 10, 64)
		if err != nil {
			return err
		}

		ttyMsg := &hyperstart.TtyMessage{
			Session: seq,
			Message: payloadSlice,
		}

		err = h.SendIoMessage(ttyMsg)
		if err != nil {
			return err
		}
	}

	return nil
}

func monitorStdInLoop(h *hyperstart.Hyperstart, done chan<- bool) error {
	dumpSupportedCommands()
	reader := bufio.NewReader(os.Stdin)

	for {
		magicLog(commandInputMsg)
		setWaitingInputs(true, commandInputMsg)
		input, err := readStringNoDelimiter(reader, '\n')
		if err != nil {
			setWaitingInputs(false, "")
			magicLog("%s\n", err)
			break
		}
		setWaitingInputs(false, "")

		if input == "" {
			continue
		}

		cmd, err := convertInputToCmd(input)
		if err != nil {
			magicLog("%s\n", err)
			continue
		}

		if cmd == exit {
			break
		}

		ctlType := true

		if cmd == sendTty {
			ctlType = false
			magicLog(sequenceInputMsg)
			setWaitingInputs(true, sequenceInputMsg)
			cmd, err = readStringNoDelimiter(reader, '\n')
			if err != nil {
				setWaitingInputs(false, "")
				magicLog("%s\n", err)
				break
			}
			setWaitingInputs(false, "")
		}

		magicLog(payloadInputMsg)
		setWaitingInputs(true, payloadInputMsg)
		payload, err := readStringNoDelimiter(reader, '\n')
		if err != nil {
			setWaitingInputs(false, "")
			magicLog("%s\n", err)
			break
		}
		setWaitingInputs(false, "")

		err = sendMessage(h, ctlType, cmd, payload)
		if err != nil {
			magicLog("%s\n", err)
			continue
		}
	}

	close(done)

	return nil
}

func monitorTtyOutLoop(h *hyperstart.Hyperstart, done chan<- bool) error {
	for {
		msgCh := make(chan *hyperstart.TtyMessage)
		errorCh := make(chan bool)

		go func() {
			msg, err := h.ReadIoMessage()
			if err != nil {
				magicLog("%s\n", err)
				close(errorCh)
				return
			}

			msgCh <- msg
		}()

		select {
		case msg := <-msgCh:
			dumpFrame(*msg)
		case <-errorCh:
			close(done)
			break
		}
	}
}

func mainLoop(c *cli.Context) error {
	ctlSockPath := c.String("ctl")
	ttySockPath := c.String("tty")

	if ctlSockPath == "" || ttySockPath == "" {
		return fmt.Errorf("Missing socket path: please provide CTL and TTY socket paths")
	}

	h := hyperstart.NewHyperstart(ctlSockPath, ttySockPath, unixSocketType)

	if err := h.OpenSockets(); err != nil {
		return err
	}
	defer h.CloseSockets()

	if err := h.WaitForReady(); err != nil {
		return err
	}

	done := make(chan bool)

	go monitorStdInLoop(h, done)
	go monitorTtyOutLoop(h, done)

	<-done

	return nil
}

func main() {
	flag.Parse()

	agentCli := cli.NewApp()
	agentCli.Name = "Agent CLI"
	agentCli.Version = "1.0.0"
	agentCli.Commands = []cli.Command{
		{
			Name:  "run",
			Usage: "send/receive on hyperstart sockets",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ctl",
					Value: "",
					Usage: "the CTL socket path",
				},
				cli.StringFlag{
					Name:  "tty",
					Value: "",
					Usage: "the TTY socket path",
				},
			},
			Action: func(context *cli.Context) error {
				return mainLoop(context)
			},
		},
	}

	err := agentCli.Run(os.Args)
	if err != nil {
		glog.Fatal(err)
	}
}
