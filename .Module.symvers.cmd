cmd_/home/joe/demo_module/Module.symvers := sed 's/ko$$/o/' /home/joe/demo_module/modules.order | scripts/mod/modpost -m    -o /home/joe/demo_module/Module.symvers -e -i Module.symvers   -T -
