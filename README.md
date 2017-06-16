# container-vm-agent
Virtual Machine agent for hardware virtualized containers

## Role
This project holds the code related to a virtual machine agent relying on the communication protocol defined by hyperstart. That way, it allows to spawn some processes on behalf of pod/container(s) running inside the virtual machine.
The code relies heavily on [libcontainer](https://github.com/opencontainers/runc/tree/master/libcontainer) so that we can reuse as much as possible the code used by `runc` (standard to run containers on bare metal).

## Requirements
We need the guest kernel to enable CONFIG_KEYS, otherwise we get the following error from libcontainer:
```
Could not run process 1: container_linux.go:259: starting container process caused "process_linux.go:345: container init caused "could not create session key: function not implemented"
```
