# Agent CLI

## Usage

### Start your VM

```
sudo /usr/bin/qemu-lite-system-x86_64 -name "4933b48bb99bfa8c" -machine pc-lite,accel=kvm,kernel_irqchip,nvdimm -device nvdimm,memdev=mem0,id=nv0 -object "memory-backend-file,id=mem0,mem-path=/usr/share/clear-containers/clear-containers.img,size=235929600" -m "2G,slots=2,maxmem=3G" -smp 2,sockets=2,cores=1,threads=1 -cpu host -no-user-config -nodefaults -no-hpet -global kvm-pit.lost_tick_policy=discard -chardev stdio,signal=off,id=charconsole0 -device virtio-serial-pci,id=virtio-serial0 -device virtconsole,bus=virtio-serial0.0,chardev=charconsole0,id=console0,name=console0 -uuid a877689d-284e-4544-90a7-ed390a76ef57 -chardev socket,id=charch0,path=/tmp/hyper.sock,server,nowait -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charch0,id=channel0,name=sh.hyper.channel.0 -chardev socket,id=charch1,path=/tmp/tty.sock,server,nowait -device virtserialport,bus=virtio-serial0.0,nr=2,chardev=charch1,id=channel1,name=sh.hyper.channel.1 -chardev socket,path=/tmp/monitor_4933b48bb99bfa8c.sock,server,nowait,id=charmonitor -mon chardev=charmonitor -nographic -vga none  -kernel "/usr/share/clear-containers/vmlinux.container" -append " root=/dev/pmem0p1 rootflags=dax,data=ordered,errors=remount-ro rw rootfstype=ext4 tsc=reliable no_timer_check rcupdate.rcu_expedited=1 cryptomgr.notests i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k panic=1 console=hvc0 initcall_debug init=/usr/lib/systemd/systemd iommu=off" -device virtio-9p-pci,fsdev=shared,mount_tag=shared -fsdev local,id=shared,path=<your_rootfs>,security_model=none
```
Make sure you replace "your rootfs" with the rootfs of your choice. And make sure your clear-containers.img includes `agent` binary.

Enter `root` as login, and choose a password.

### Run the agent

From the VM shell:

```
hyperstart
```

### Run agent-cli

From a different shell on the host:
```
./agent-cli run --ctl=/tmp/hyper.sock --tty=/tmp/tty.sock
```

### Basic usage

To exit the tool, choose command "100"

To send to TTY, choose command "50".

To send to CTL, choose any other command.

### Complete example

__Start a pod__

```
Command: 1 
Payload: {"hostname":"30028dfd-4904-4818-a2cf-9419bdc7e2d4","shareDir":"shared"}
```

Output

```
DecodedMessage {
        Code: 9
        Message: 
}
```

__Start a new container__

```
Command: 9
Payload: {"id":"1","rootfs":"rootfs","image":"","process":{"terminal":false,"stdio":3,"stderr":4,"args":["/bin/ifconfig"],"workdir":"/"}}
```
Output

```
TtyMessage {
        Session: 3
        Message: lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:288 errors:0 dropped:0 overruns:0 frame:0
          TX packets:288 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:23904 (23.3 KiB)  TX bytes:23904 (23.3 KiB)


}
DecodedMessage {
        Code: 9
        Message: 
}
Command: 
TtyMessage {
        Session: 3
        Message: 
}

Command: 
TtyMessage {
        Session: 3
        Message: 
}
```

__Execute an additional command on a running container__

```
Command: 3
Payload: {"container":"1","process":{"terminal":false,"stdio":5,"stderr":6,"args":["/bin/ifconfig"],"envs":[{"env":"PATH","value":"/bin:/usr/bin:/sbin:/usr/sbin"}],"workdir":"/"}}
```
Output

```
DecodedMessage {
        Code: 9
        Message: 
}
Command: 
TtyMessage {
        Session: a
        Message: lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:160 errors:0 dropped:0 overruns:0 frame:0
          TX packets:160 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:13024 (12.7 KiB)  TX bytes:13024 (12.7 KiB)


}

Command: 
TtyMessage {
        Session: a
        Message: 
}

Command: 
TtyMessage {
        Session: a
        Message: 
}
```

Make sure the container that you have previously started has not returned yet, otherwise you will get similar error from the agent inside the VM:
```
ERRO[0372] Run "exec" command failed: Container 1 not running, impossible to execute process 10
```
