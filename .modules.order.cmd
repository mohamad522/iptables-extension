cmd_/home/joe/demo_module/modules.order := {   echo /home/joe/demo_module/xt_http.ko; :; } | awk '!x[$$0]++' - > /home/joe/demo_module/modules.order
