# iptables Extension: Filter HTTP Traffic by User-Agent Header

## Overview
This extension allows you to filter HTTP traffic based on the contents of the **User-Agent** header. It is implemented as a custom `iptables` module and consists of both kernel space and userspace components. The kernel space module will handle the filtering of HTTP traffic, while the userspace module allows interaction with `iptables` through the User-Agent header.

## Prerequisites
Before starting, make sure you have the following tools installed:
- `iptables`
- `gcc`
- Kernel headers for your current kernel version
- `xtables` (for building the shared library)

## Kernel Space Module

### Step 1: Copy the Header File
Copy the header file to the appropriate location in your kernel headers directory:

```bash
cp xt_http.h /usr/src/linux-headers-5.10.0-28-common/include/linux/netfilter
```

### Step 2: Compile the Kernel Module
Navigate to the directory containing `xt_http.c` and compile:
```bash
make
```

### Step 3: Install the Kernel Module
Copy the compiled `.ko` file to the appropriate kernel directory:
```bash
cp xt_http.ko /usr/lib/modules/5.10.0-22-amd64/kernel/net/netfilter
```

### Step 4: Load the Kernel Module
Load the module into the system:
```bash
sudo insmod xt_http.ko
```

### Userspace Module

#### Step 1: Compile the Shared Library
Compile the userspace shared library `libxt_http.so`:
```bash
gcc -shared -fPIC -o libxt_http.so libxt_http.c $(pkg-config --cflags --libs xtables)
```

#### Step 2: Install the Userspace Module
Copy the compiled shared library to the xtables directory:
```bash
cp libxt_http.so /usr/lib/x86_64-linux-gnu/xtables
```

### Example Usage

To drop incoming HTTP traffic with a User-Agent header that matches "Chrome":

```bash
sudo iptables -A INPUT -m http --user-agent "Chrome" -j DROP
```
