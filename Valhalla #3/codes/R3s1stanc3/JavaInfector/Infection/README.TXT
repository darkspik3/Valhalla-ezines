------------------------------------------------------------------------
This is the project README file. Here, you should describe your project.
Tell the reader (someone who does not know anything about this project)
all he/she needs to know. The comments should usually include at least:
------------------------------------------------------------------------

PROJECT TITLE: Java Infector
PURPOSE OF PROJECT: PoC Code of a Java Infection using the Java Compiler Class
VERSION or DATE: 1.0; 09 Dec 2012
AUTHORS: R3s1stanc3

The code unzips every jar file in the current directory, copys its own classes and a class that is compiled 
in runtime in the archive, modifies the MANIFEST.MF and packs the code again
If the archive contains a file called "kjlfaojdfaljgsdfaKdlkAUSfdld" the file won't be infected
The payload is a simple message box, saying that the file is infected
