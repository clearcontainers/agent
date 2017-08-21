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

package main

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewEventTime(t *testing.T) {
	type args struct {
		event string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Empty event name", args{""}, true},
		{"Non-empty event name", args{"event"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newEventTime(tt.args.event)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newEventTime() = %s, error = %v, wantErr %v", got, err, tt.wantErr)
			}
		})
	}
}

func TestEventTimeString(t *testing.T) {
	type fields struct {
		event string
		time  unix.Timespec
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{"Check event name", fields{"event", unix.Timespec{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := eventTime{
				Event: tt.fields.event,
				Time:  tt.fields.time,
			}
			if got := e.String(); !strings.Contains(got, tt.fields.event) {
				t.Errorf("eventTime.String() = \"%s\",  want it Contains = \"%s\"", got, tt.fields.event)
			}
			fmt.Println(e)
		})
	}
}
