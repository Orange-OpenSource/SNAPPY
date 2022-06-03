UBSAN_SANITIZE := y 
CONFIG_UBSAN:=y

obj-$(CONFIG_SECURITY_SNAPPY) := helpers.o snappy_ns.o snappy_fs.o lsm_handlers.o  snappy.o

ccflags-y := -I$(srctree)/security/snappy -I$(srctree)/security/snappy/include -DDEBUG -ggdb3 -O1

