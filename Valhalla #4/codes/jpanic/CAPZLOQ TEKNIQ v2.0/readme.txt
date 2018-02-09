[CAPZLOQ TEKNIQ v2.0] - another multiplatform virus by JPanic (c) 2013.

<Contents>
~~~~~~~~~~
	- <Description>
	- <File List>
	- <'make' usage>

<Description>
~~~~~~~~~~~~~
	CLT20 is a 2.8k infector of Win32 PE, Linux ELF, and OSX MACHO/FAT
	files. When viewing source, a TAB size of '8' is recommended.
	
	The virus runs under 3 different platforms: Win32,Linux,OSX (i386).
	
	The virus has some improvements of CLT10. Handling more error 
	conditions, more virulent, more checks. Handling attributes/
	permissions and datestamps too.

	On execution under either Operating System the virus attempts to
	infect all PE,ELF,MACHO and FAT files in the current directory. 
	If user is 'root' or administrator, it also infects all files in 
	Windows+System32 dirs, or '/bin'+'/usr/bin' dirs depending on
	operating system.
	
	Under Win32y he virus calls Kernel32.dll and also uses SFC.DLL.
	Under Linux the virus calls INT 0x80.
	Under OSX the virus calls INT 0x80, 32-bit BSD calls.

	Infection of Win32 PE files is achieved by adding the virus to the
	last section. This is a fairly standard method. Checks are made for
	SFX's, drivers, digital certificates and so on.	
	
	When infecting Linux ELF files, the virus creates a cave after the PHdrs
	and before ".text". This causes the load address to be lowered by 0x1000
	(1 page).
	
	When infecting OSX MACHO files, the virus modifies __PAGEZERO and
	'i386_NEW_THREAD_STATE' struct, appending itself to the end of the
	file.
	
	When infecting FAT (OSX Universal Binaries), if the last MACHO module is
	i386, The MACHO is infected in the above manner.

	The virus is written in TASM and assembles and links to a Win32 PE
	host. This host can be used to infect other PE/ELF/MACHO/FAT files.
	When building the makefile outputs the address of 'VHost' which tells
	you the zize of the virus.
	
	There are 2 builds: 'test' (default) and 'deadly'. 
	- 'test' only infects '*.clt20' under windows, and '/testa/' and
	  '/testb/' under linux/OSX.
	- 'test' infects all files under windows, and '/bin/' and '/usr/bin/' 
	   under linux/OSX.

	The virus is built with Borland 'make' - see <'make' commands>.
	The tools are so old, they need an OS running NTVDM or similar.
	I used a Win2k pro VM as a build environment.

<File List>
~~~~~~~~~~~
readme.txt		- This file.

./test/			- Output directory for 'test' build.
./deadly/		- Output directory for 'deadly' build.

./inc/			- Folder including many .INC Files. Filenames are self
			  explanatory.

./bin/			- Tools used to build virus, TASM/TLINK, MAKE, 7ZIP CLI.
			  See 'make usage' section below.

./tools/		- Some very basic 'tools' used to test development of virus.

samples			- Some sample files (2 of each format) for you to test virus.

clt20-deadly.def	- Defintion files for TLINK linker.
clt20.def

makefile		- Project makefile. See 'make usage' section below.
make.bat		- Chain to ./bin/make.exe
zip.bat			- BAT file using 7zipcli in ./bin/ to create virus archive.
			- 'make clean' before running, edit BAT to change destination.
			
vheap.ash		- Assembler header to define virus 'heap' structure on stack,
			  and dynamically allocated memory structures.

vmain.ash		- Main virus procedure, entry point.
vmain.asm

vhost.asm		- 1st geneneration dropper, host code.

codeseg.ash		- Assembler header to force byte aligned linking.

osprocs.ash		- Routines to manager different operating system modules.
osprocs.asm

linux-procs.asm		- Routines used under Linux.
osx-procs.asm		- Routines used under OSX.
win32-procs.asm		- Routines used under Win32.
win32imps.ash		- Assembler header to manage kernel32.dll imports.

inf-elf.ash		- Routines to infect 'ELF' files.
inf-elf.asm
inf-macho.ash		- Routines to infect 'MACHO' and 'FAT' files.
inf-macho.asm
inf-pe.ash		- Routines to infect 'PE' files.
inf-pe.asm

rand.ash		- Simple RNG, 32-Bit Linear Shift Feedback Register (lsfr)
rand.asm
strhash32.ash		- Simple 32-bit string hash algorithm.
strhash32.asm



~~~~~~~~~~~
	
<'make' Usage>
~~~~~~~~~~~~~~
[Note: I used borland turbo 'make'.]

	Command:				Result:
	--------				-------
	'make [-B] [-DDEBUG]'			Compile and link 'clt20.exe' (test build).

	'make [-B] -DDEADLY [-DDEBUG]'		Compile and link 'clt20-deadly.ex_' (deadly build).	

	'make tools'				Compile binaries in './tools/' directory. Uses gcc.
	
	'make clean'				Delete temporary lst,obj,map,ex? files and infected
						samples.	
	
	zip.bat					Create ZIP archive. Run 'make clean' first.
						Modify zip.bat to define target archive.

- Best wishes: JPanic (aka Sepultura, aka The Soul Manager)!.