# Instructions for testing Multipass environment (A0)
1. Clone This repository
2. Install Multipass on your system. Follow the instructions in this link to install Multipass: [https://multipass.run/install](https://multipass.run/install).
Multipass is a Ubuntu VM orchastrator. It quickly and easily installs VMs using you system's default hypervisor.
3. Launch an Ubuntu VM that you can use to develop and test your code. Run: 
```bash
cd assignments-spring24/Assignment0
multipass launch focal -n cn-a0 --cloud-init config.yaml
```
After the VM launches, use the following command to open as many shells as you need:
```bash
multipass shell cn-a0
```

## Developing on the virtual machine using VSCode
Multipass automatically assigns an IP address to the VM which is accible from your host machine. If you enable the remote-SSH extention in VSCode, you can develop your code remotely.
To find the IP address of your Ubuntu VM, run:

```bash
multipass list
```

The only pre-requisite is to set a password to your default (ubuntu) user in the VM. To do so, run `sudo passwd ubuntu` on the VM shell. Feel free to enable password-less authentication to your VM!

See this guide for more information: https://code.visualstudio.com/docs/remote/ssh

## Transferring your code from/to the virtual machine
You can use the following commands to transfer files to and from the VM if you prefer to develop your code locally on your machine.

```bash
# transfer from your machine to VM
multipass transfer /path/to/source cn-0:/path/to/destination
# transfer from the VM to your machine
multipass transfer cn-0:/path/to/source /path/to/destination
```

## Using git to move your code from/to the virtual machine
Your VM should have internet access if installed correctly. You can use your own private git repository to move code from/to the virtual machine.

### FAQ
Q: Can I run my code on my own system instead of the virtual machine?

A: Depends on the assignment and your operating system! We have ensured that all the assignments can be run in this VM. Please refer to the individual assignment README files to see what environments are supported. As a summary:

Linux users: Except for Assignment 2, you can use your own system to develop and test!

MAC users: Except for Assignments 2 and 3, you can use your own system to develop and test!

Windows users: You can use WSL for all assignments except Assignment 2.

Q: Do I need to install any software dependencies to use Multipass?

Linux users can install multipass using **snap** which will automatically take care of dependencies. Mac users, similarly, will use brew. Some Windows users might see this warning during Multipass installation: "Oracle Virtualbox is required on Windows Home Edition". If HyperV is unavailable in your system, please follow [this](https://www.virtualbox.org/wiki/Downloads) link to install Virtualbox after installing Multipass. 