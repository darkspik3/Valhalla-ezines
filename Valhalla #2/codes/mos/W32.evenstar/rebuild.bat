cls

del calc.exe

copy calc_orig.exe calc.exe

C:\masm32\bin\ml.exe /c /coff /Cp es.asm
C:\masm32\bin\link.exe /SUBSYSTEM:WINDOWS /lIBPATH:C:\masm32\lib es.obj

es.exe