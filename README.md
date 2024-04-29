cp xt_http.h /usr/src/linux-headers-5.10.0-28-common/include/linux/netfilter


make


//kernel space module

cp xt_http.ko /usr/lib/modules/5.10.0-22-amd64/kernel/net/netfilter


//compile and create the shared library object file

gcc -shared -fPIC -o libxt_http.so libxt_http.c $(pkg-config --cflags --libs xtables)


//put the userspace module in a directory where iptables can find it

cp libxt_http.so /usr/lib/x86_64-linux-gnu/xtables


//load the kernel module

sudo insmod xt_http.ko


sudo iptables -A INPUT -m http --user-agent "Chrome" -j DROP
