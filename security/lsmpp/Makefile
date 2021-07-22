UBSAN_SANITIZE := y 
CONFIG_UBSAN:=y

obj-$(CONFIG_SECURITY_LSMPP) := helpers.o lsmpp_ns.o lsmpp_fs.o lsm_handlers.o  lsmpp.o

ccflags-y := -I$(srctree)/security/lsmpp -I$(srctree)/security/lsmpp/include -DDEBUG -ggdb3 -O1

