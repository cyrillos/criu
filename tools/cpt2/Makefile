MAKEFLAGS 	:= -r -R --no-print-directory

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

FIND		:= find
CSCOPE		:= cscope
TAGS		:= ctags
RM		:= rm -f
LD		:= ld
CC		:= gcc
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= bash
MAKE		:= make
OBJCOPY		:= objcopy

#
# Fetch ARCH from the uname if not yet set
#
ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/arm.*/arm/		\
		-e s/sa110/arm/		\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/ppc.*/powerpc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

ifeq ($(ARCH),i386)
	ARCH         := x86-32
	DEFINES      := -DCONFIG_X86_32
endif

ifeq ($(ARCH),x86_64)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_64
	LDARCH       := i386:x86-64
endif

ifeq ($(ARCH),arm)
	ARCH         := arm
	ARCH_DEFINES := -DCONFIG_ARM
	LDARCH       := arm
	CFLAGS       += -march=armv7-a
endif

ifneq ($(ARCH),x86)
$(error "The architecture $(ARCH) isn't supported"))
endif

cflags-y	+= -iquote src/include -iquote ../../include -iquote ../../arch/$(ARCH)/include
cflags-y	+= -fno-strict-aliasing
export cflags-y

LIBS		:= -lrt -lpthread -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export SH RM OBJCOPY LDARCH LD

include ../../scripts/Makefile.rules

build := -I ../../ -r -R --no-print-directory -f ../../scripts/Makefile.build makefile=Makefile obj

PROGRAM		:= cpt2

.PHONY: all clean tags protobuf

../../protobuf/built-in.o:
	$(Q) $(MAKE) -C ../../ protobuf/built-in.o

protobuf: ../../protobuf/built-in.o

src/res/%:
	$(Q) $(MAKE) $(build)=src/res $@
src/res/built-in.o:
	$(Q) $(MAKE) $(build)=src/res $@

src/%: protobuf src/res/built-in.o
	$(Q) $(MAKE) $(build)=src $@
src/built-in.o: src protobuf src/res/built-in.o
	$(Q) $(MAKE) $(build)=src all

$(PROGRAM): src/built-in.o src/res/built-in.o ../../protobuf/built-in.o
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) -o $@

all: $(PROGRAM)

tags:
	$(E) "  GEN" $@
	$(Q) $(RM) tags
	$(Q) $(FIND) -L . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a

clean:
	$(E) "  CLEAN"
	$(Q) $(MAKE) $(build)=src clean
	$(Q) $(MAKE) $(build)=src/res clean
	$(Q) $(RM) $(PROGRAM)

.DEFAULT_GOAL := all
