INCS=	elfdefinitions.h
INCSDIR?=	/usr/include

_NATIVE_ELF_FORMAT = native-elf-format

${_NATIVE_ELF_FORMAT}.h:
	${CURDIR}/${_NATIVE_ELF_FORMAT} > $@

obj depend:

clean:
	rm -f ${CLEANFILES}

.PHONY: clean

