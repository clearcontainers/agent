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

	"golang.org/x/sys/unix"
)

const agentStartedEvent = "agent_started"

//Event that will be reported for time tracing
type eventTime struct {
	Event string
	Time  unix.Timespec
}

// Get eventTime based CLOCK_MONOTONIC_RAW clock
func newEventTime(event string) (eventTime, error) {
	var ts unix.Timespec

	if event == "" {
		return eventTime{Event: "error", Time: ts}, fmt.Errorf("event cannot be empty")
	}

	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		return eventTime{}, err
	}
	return eventTime{Event: event, Time: ts}, nil
}

func (e eventTime) String() string {
	return fmt.Sprintf("%s %d.%d", e.Event, e.Time.Sec, e.Time.Nsec)
}
