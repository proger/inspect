SUBDIR		:= common libelf libdwarf
RTARGETS	:= all clean obj

$(RTARGETS):
	for dir in $(SUBDIR); do $(MAKE) -C $$dir $@; done
