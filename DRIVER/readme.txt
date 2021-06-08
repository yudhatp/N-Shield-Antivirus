========================================================================
       Windows Driver : Nshield
========================================================================


QuickSYS has created this Nshield SYS for you.  

This file contains a summary of what you will find in each of the files that
make up your application.

Nshield.dsp (VC6)
Nshield.vcproj (VC2005/VC2008)
    This file (the project file) contains information at the project level and
    is used to build a single project or subproject. Other users can share the
    project (.dsp or .vcproj) file, but they should export the makefiles locally.

Nshield.c
    This is the main SYS source file.

Nshield.h
    This file contains your SYS definition.

ntddkinc.h
	This file contains some useful macros.

/////////////////////////////////////////////////////////////////////////////
Other notes:

AppWizard uses "TODO:" to indicate parts of the source code you
should add to or customize.

To support 64bit Windows:
The easy way is check "Use VC2008 and WDK".

Or you can
Change _X86_=1 to _AMD64_=1
Change include directory to ddk\wnet
Change lib directory to lib\wnet\amd64

/////////////////////////////////////////////////////////////////////////////
