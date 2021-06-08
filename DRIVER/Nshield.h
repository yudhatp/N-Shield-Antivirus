/*++

Copyright (c) 

Module Name:

    Nshield.h

Abstract:

    This framework is generated by QuickSYS 0.4

Author:

	<your name>

Environment:

	User or kernel mode.

Revision History:

--*/

#ifndef _NSHIELD_H
#define _NSHIELD_H 1

//
// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-0x7FFF(32767), and 0x8000(32768)-0xFFFF(65535)
// are reserved for use by customers.
//

#define FILE_DEVICE_NSHIELD	0x8000

//
// Macro definition for defining IOCTL and FSCTL function control codes. Note
// that function codes 0-0x7FF(2047) are reserved for Microsoft Corporation,
// and 0x800(2048)-0xFFF(4095) are reserved for customers.
//

#define NSHIELD_IOCTL_BASE	0x800

//
// The device driver IOCTLs
//

#define CTL_CODE_NSHIELD(i)	\
	CTL_CODE(FILE_DEVICE_NSHIELD, NSHIELD_IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NSHIELD_HELLO	CTL_CODE_NSHIELD(0)
#define IOCTL_NSHIELD_TEST	CTL_CODE_NSHIELD(1)

//
// Name that Win32 front end will use to open the Nshield device
//

#define NSHIELD_WIN32_DEVICE_NAME_A	"\\\\.\\Nshield"
#define NSHIELD_WIN32_DEVICE_NAME_W	L"\\\\.\\Nshield"
#define NSHIELD_DEVICE_NAME_A			"\\Device\\Nshield"
#define NSHIELD_DEVICE_NAME_W			L"\\Device\\Nshield"
#define NSHIELD_DOS_DEVICE_NAME_A		"\\DosDevices\\Nshield"
#define NSHIELD_DOS_DEVICE_NAME_W		L"\\DosDevices\\Nshield"

#ifdef _UNICODE
#define NSHIELD_WIN32_DEVICE_NAME	NSHIELD_WIN32_DEVICE_NAME_W
#define NSHIELD_DEVICE_NAME		NSHIELD_DEVICE_NAME_W
#define NSHIELD_DOS_DEVICE_NAME	NSHIELD_DOS_DEVICE_NAME_W
#else
#define NSHIELD_WIN32_DEVICE_NAME	NSHIELD_WIN32_DEVICE_NAME_A
#define NSHIELD_DEVICE_NAME		NSHIELD_DEVICE_NAME_A
#define NSHIELD_DOS_DEVICE_NAME	NSHIELD_DOS_DEVICE_NAME_A
#endif

#endif