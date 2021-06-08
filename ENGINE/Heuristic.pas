{steve10120@ic0de.org}

unit Heuristic;

interface

uses Windows;

function Assigned(pInput:Pointer):Boolean;
function ValidHandle(dwValue:DWORD):Boolean;
function ValidSize(dwValue:DWORD):Boolean;
function AllocMemory(var pOutput:Pointer; pBase:Pointer; dwSize:DWORD; dwProtect:DWORD):Boolean;
function FreeMemory(pInput:Pointer):Boolean;
function ReallocMemory(var pOutput:Pointer; pInput:Pointer; dwOldSize:DWORD; dwNewSize:DWORD):Boolean;
procedure FillChar(pInput:Pointer; cFill:Char; dwSize:DWORD);
function FileToStr(szFilePath:string; var szOutput:string):Boolean;
function FileToPtr(szFilePath:string; var pOutput:Pointer; var dwSize:DWORD):Boolean;
function StrToFile(szFilePath:string; dwPosition:DWORD; szInput:string):Boolean;
function PtrToFile(szFilePath:string; dwPosition:DWORD; pInput:Pointer; dwSize:DWORD; bFreeWhenDone:Boolean):Boolean;
function StrToPtr(szInput:string):Pointer;
function PtrToStr(pInput:Pointer; dwSize:DWORD):string;
function SwapBytes(dwValue:DWORD):DWORD;
function ASCIIToUNICODE(szInput:string):WideString;
function UNICODEToASCII(szInput:WideString):string;
function LowerCaseA(szInput:string):string;
function LowerCaseW(szInput:WideString):WideString;
function UpperCaseA(szInput:string):string;
function UpperCaseW(szInput:WideString):WideString;
function ReverseStringA(szInput:string):string;
function ReverseStringW(szInput:WideString):WideString;
function IntToStr(dwValue:DWORD):string;
function StrToInt(szInput:string):DWORD;
function UserNameA():string;
function UserNameW():WideString;
function ComputerNameA():string;
function ComputerNameW():WideString;
function WindowsPathA():string;
function WindowsPathW():WideString;
function SystemPathA():string;
function SystemPathW():WideString;
function TempPathA():string;
function TempPathW():WideString;
function WindowsVersion():string;
function Is64BitOS():Boolean;
function CopyA(szInput:PChar; dwIndex:DWORD; dwSize:DWORD):PChar;
function CopyW(szInput:PWideChar; dwIndex:DWORD; dwSize:DWORD):PWideChar;
function LeftStr(szInput:string; dwSize:DWORD):string;
function RightStr(szInput:string; dwSize:DWORD):string;
function MidStr(szInput:string; dwIndex:DWORD; dwSize:DWORD):string;
function KeyToStr(hRoot:HKEY; szSubKey:string; szValue:string; var szOutput:string):Boolean;
function StrToKey(hRoot:HKEY; szSubKey:string; szValue:string; szInput:string):Boolean;
procedure CopyMemory(Destination:Pointer; Source:Pointer; dwSize:DWORD);
function IsValidPE(szFilePath:string):Boolean;
function LongPath(szInput:string):string;
function ShortPath(szInput:string):string;
function UpdateResources(szFilePath:string; szType:PChar; szName:PChar; wLang:WORD; bDeleteExisting:Boolean; szInput:Pointer; dwSize:DWORD):Boolean;
function GetResource(hModule:DWORD; szType:PChar; szName:PChar; var pOutput:Pointer; var dwSize:DWORD):Boolean;
function FileExists(szFilePath:string):Boolean;
procedure ShowMessageA(szMessage:string);
procedure ShowMessageW(szMessage:WideString);
procedure ShowErrorA(szMessage:string);
procedure ShowErrorW(szMessage:WideString);
function FileTypeA(szFilePath:string):string;
function FileTypeW(szFilePath:WideString):WideString;
function DefaultBrowser():string;
function PosChar(Delimiter:Char; szInput:string):DWORD;
procedure lstrcpyA(szOutput:PChar; szInput:PChar);
procedure lstrcpyW(szOutput:PWideChar; szInput:PWideChar);
function MyGetProcAddress(hModule:DWORD; szFuncName:PChar):Pointer;
function MapFile(szFilePath:string; szMapName:string; var pMapped:Pointer; var dwSize:DWORD):Boolean;
function UnMapFile(pMapped:Pointer):Boolean;
function GetMyHandle():DWORD;

const
  cSlashA:            string = '\';
  cSlashW:            WideString = '\';
  SM_SERVERR2:        DWORD = 89;
  VER_NT_WORKSTATION: DWORD = 1;
  SHGFI_TYPENAME:     DWORD = $400;
  szInfoA:            PChar = 'Information';
  szInfoW:            PWideChar = 'Information';
  szErrorA:           PChar = 'Error';
  szErrorW:           PWideChar = 'Error';
  szNull:             string = '';
  szEXE:              string = '.exe';

type
  OSVERSIONINFOEX = packed record
    dwOSVersionInfoSize: DWORD;
    dwMajorVersion: DWORD;
    dwMinorVersion: DWORD;
    dwBuildNumber: DWORD;
    dwPlatformId: DWORD;
    szCSDVersion: array[0..127] of Char;
    wServicePackMajor: WORD;
    wServicePackMinor: WORD;
    wSuiteMask: WORD;
    wProductType: BYTE;
    wReserved: BYTE;
  end;
  TOSVersionInfoEx = OSVERSIONINFOEX;
  POSVersionInfoEx = ^TOSVersionInfoEx;

type
  PSHFileInfoA = ^TSHFileInfoA;
  PSHFileInfoW = ^TSHFileInfoW;
  PSHFileInfo = PSHFileInfoA;
  {$EXTERNALSYM _SHFILEINFOA}
  _SHFILEINFOA = record
    hIcon: HICON;                      { out: icon }
    iIcon: Integer;                    { out: icon index }
    dwAttributes: DWORD;               { out: SFGAO_ flags }
    szDisplayName: array [0..MAX_PATH-1] of  AnsiChar; { out: display name (or path) }
    szTypeName: array [0..79] of AnsiChar;             { out: type name }
  end;

  _SHFILEINFOW = record
    hIcon: HICON;                      { out: icon }
    iIcon: Integer;                    { out: icon index }
    dwAttributes: DWORD;               { out: SFGAO_ flags }
    szDisplayName: array [0..MAX_PATH-1] of  WideChar; { out: display name (or path) }
    szTypeName: array [0..79] of WideChar;             { out: type name }
  end;

  _SHFILEINFO = _SHFILEINFOA;
  TSHFileInfoA = _SHFILEINFOA;
  TSHFileInfoW = _SHFILEINFOW;
  TSHFileInfo = TSHFileInfoA;
  SHFILEINFOA = _SHFILEINFOA;
  SHFILEINFOW = _SHFILEINFOW;
  SHFILEINFO = SHFILEINFOA;

const
  szkernel32 = 'kernel32.dll';
  shell32    = 'shell32.dll';
  ntdll      = 'ntdll.dll';

function GetVersionExA(var lpVersionInformation: TOSVersionInfoEx): BOOL; stdcall; external szkernel32;
function IsWow64Process(hProcess:DWORD; var bIsWow64:Boolean):Boolean; stdcall; external szkernel32;
function GetLongPathNameA(lpszShortPath:PChar; lpszLongPath:PChar; dwSize:DWORD):DWORD; stdcall; external kernel32
function SHGetFileInfoA(pszPath: PAnsiChar; dwFileAttributes: DWORD; var psfi: TSHFileInfoA; cbFileInfo, uFlags: UINT): DWORD; stdcall; external shell32
function SHGetFileInfoW(pszPath: PWideChar; dwFileAttributes: DWORD; var psfi: TSHFileInfoW; cbFileInfo, uFlags: UINT): DWORD; stdcall; external shell32
procedure RtlFillMemory(pInput:Pointer; dwSize:DWORD; bFill:Byte); stdcall; external ntdll;

implementation

function Assigned(pInput:Pointer):Boolean;
begin
  Result := FALSE;
  if pInput <> nil then
    Result := TRUE;
end;

function ValidHandle(dwValue:DWORD):Boolean;
begin
  Result := FALSE;
  if dwValue <> INVALID_HANDLE_VALUE then
    Result := TRUE;
end;

function ValidSize(dwValue:DWORD):Boolean;
begin
  Result := FALSE;
  if dwValue > 0 then
    Result := TRUE;
end;

function AllocMemory(var pOutput:Pointer; pBase:Pointer; dwSize:DWORD; dwProtect:DWORD):Boolean;
begin
  Result := FALSE;
  pOutput := VirtualAlloc(pBase, dwSize, MEM_COMMIT, dwProtect);
  if Assigned(pOutput) then
    Result := TRUE;
end;

function FreeMemory(pInput:Pointer):Boolean;
begin
  Result := FALSE;
  if VirtualFree(pInput, 0, MEM_RELEASE) then
    Result := TRUE;
end;

function ReallocMemory(var pOutput:Pointer; pInput:Pointer; dwOldSize:DWORD; dwNewSize:DWORD):Boolean;
begin
  Result := FALSE;
  if AllocMemory(pOutput, nil, dwNewSize, PAGE_READWRITE) then
  begin
    CopyMemory(pOutput, pInput, dwOldSize);
    FreeMemory(pInput);
    Result := TRUE;
  end;
end;

procedure FillChar(pInput:Pointer; cFill:Char; dwSize:DWORD);
begin
  RtlFillMemory(pInput, dwSize, Byte(cFill));
end;

function FileToStr(szFilePath:string; var szOutput:string):Boolean;
var
  hFile:  DWORD;
  dwSize: DWORD;
  dwRead: DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if ValidHandle(hFile) then
  begin
    dwSize := GetFileSize(hFile, nil);
    if ValidSize(dwSize) then
    begin
      SetLength(szOutput, dwSize);
      SetFilePointer(hFile, 0, nil, FILE_BEGIN);
      ReadFile(hFile, szOutput[1], dwSize, dwRead, nil);
      if dwSize = dwRead then
        Result := TRUE;
    end;
    CloseHandle(hFile);
  end;
end;

function FileToPtr(szFilePath:string; var pOutput:Pointer; var dwSize:DWORD):Boolean;
var
  hFile:  DWORD;
  dwRead: DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if ValidHandle(hFile) then
  begin
    dwSize := GetFileSize(hFile, nil);
    if ValidSize(dwSize) then
    begin
      if AllocMemory(pOutput, nil, dwSize, PAGE_READWRITE) then
      begin
        SetFilePointer(hFile, 0, nil, FILE_BEGIN);
        ReadFile(hFile, pOutput^, dwSize, dwRead, nil);
        if dwSize = dwRead then
          Result := TRUE;
      end;
    end;
    CloseHandle(hFile);
  end;
end;

function StrToFile(szFilePath:string; dwPosition:DWORD; szInput:string):Boolean;
var
  hFile:      DWORD;
  dwSize:     DWORD;
  dwWritten:  DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_WRITE, FILE_SHARE_WRITE, nil, CREATE_NEW, 0, 0);
  if ValidHandle(hFile) then
  begin
    dwSize := Length(szInput);
    if ValidSize(dwSize) then
    begin
      SetFilePointer(hFile, dwPosition, nil, FILE_BEGIN);
      WriteFile(hFile, szInput[1], dwSize, dwWritten, nil);
      if dwWritten = dwSize then
        Result := TRUE;
    end;
    CloseHandle(hFile);
  end;
end;

function PtrToFile(szFilePath:string; dwPosition:DWORD; pInput:Pointer; dwSize:DWORD; bFreeWhenDone:Boolean):Boolean;
var
  hFile:      DWORD;
  dwWritten:  DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_WRITE, FILE_SHARE_WRITE, nil, CREATE_NEW, 0, 0);
  if ValidHandle(hFile) then
  begin
    if ValidSize(dwSize) then
    begin
      SetFilePointer(hFile, dwPosition, nil, FILE_BEGIN);
      WriteFile(hFile, pInput^, dwSize, dwWritten, nil);
      if dwWritten = dwSize then
        Result := TRUE;
      if bFreeWhenDone then
        FreeMemory(pInput);
    end;
    CloseHandle(hFile);
  end;
end;

function StrToPtr(szInput:string):Pointer;
var
  dwSize: DWORD;
begin
  Result := nil;
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    if AllocMemory(Result, nil, dwSize, PAGE_READWRITE) then
      CopyMemory(Result, @szInput[1], Length(szInput));
  end;
end;

function PtrToStr(pInput:Pointer; dwSize:DWORD):string;
begin
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    CopyMemory(@Result[1], pInput, dwSize);
  end;
end;

function SwapBytes(dwValue:DWORD):DWORD;
asm
  BSWAP EAX
end;

function ASCIIToUNICODE(szInput:string):WideString;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    for i := 1 to dwSize do
      Result := Result + szInput[i];
  end;
end;

function UNICODEToASCII(szInput:WideString):string;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    for i := 1 to dwSize do
      Result := Result + szInput[i]
  end;
end;

function LowerCaseA(szInput:string):string;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    for i := 1 to dwSize do
      Result[i] := Char(CharLowerA(PChar(szInput[i])));
  end;
end;

function LowerCaseW(szInput:WideString):WideString;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    for i := 1 to dwSize do
      Result[i] := WideChar(CharLowerW(PWideChar(szInput[i])));
  end;
end;

function UpperCaseA(szInput:string):string;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    for i := 1 to dwSize do
      Result[i] := Char(CharUpperA(PChar(szInput[i])));
  end;
end;

function UpperCaseW(szInput:WideString):WideString;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    for i := 1 to dwSize do
      Result[i] := WideChar(CharUpperW(PWideChar(szInput[i])));
  end;
end;

function ReverseStringA(szInput:string):string;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    for i := 1 to dwSize do
      Result := Result + szInput[dwSize - i + 1]
  end;
end;

function ReverseStringW(szInput:WideString):WideString;
var
  i:      DWORD;
  dwSize: DWORD;
begin
  dwSize := Length(szInput);
  if ValidSize(dwSize) then
  begin
    for i := 1 to dwSize do
      Result := Result + szInput[dwSize - i + 1]
  end;
end;

function IntToStr(dwValue:DWORD):string;
begin
  Str(dwValue, Result);
end;

function StrToInt(szInput:string):DWORD;
begin
  Val(szInput, Result, Result);
end;

function UserNameA():string;
var
  dwSize: DWORD;
begin
  dwSize := 16;
  SetLength(Result, dwSize);
  GetUserNameA(PChar(Result), dwSize);
end;

function UserNameW():WideString;
var
  dwSize: DWORD;
begin
  dwSize := 16;
  SetLength(Result, dwSize);
  GetUserNameW(PWideChar(Result), dwSize);
end;

function ComputerNameA():string;
var
  dwSize:  DWORD;
begin
  dwSize := 16;
  SetLength(Result, dwSize);
  GetComputerNameA(PChar(Result), dwSize);
end;

function ComputerNameW():WideString;
var
  dwSize:  DWORD;
begin
  dwSize := 16;
  SetLength(Result, dwSize);
  GetComputerNameW(PWideChar(Result), dwSize);
end;

function WindowsPathA():string;
var
  dwSize: DWORD;
begin
  dwSize := GetWindowsDirectoryA(nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetWindowsDirectoryA(PChar(Result), dwSize);
    if CopyA(PChar(Result), dwSize - 1, 1) <> cSlashA then
      lstrcatA(PChar(Result), PChar(cSlashA));
  end;
end;

function WindowsPathW():WideString;
var
  dwSize: DWORD;
begin
  dwSize := GetWindowsDirectoryW(nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetWindowsDirectoryW(PWideChar(Result), dwSize);
    if CopyW(PWideChar(Result), dwSize - 1, 1) <> cSlashW then
      lstrcatW(PWideChar(Result), PWideChar(cSlashW));
  end;
end;

function SystemPathA():string;
var
  dwSize: DWORD;
begin
  dwSize := GetSystemDirectoryA(nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetSystemDirectoryA(PChar(Result), dwSize);
    if CopyA(PChar(Result), dwSize - 1, 1) <> cSlashA then
      lstrcatA(PChar(Result), PChar(cSlashA));
  end;
end;

function SystemPathW():WideString;
var
  dwSize: DWORD;
begin
  dwSize := GetSystemDirectoryW(nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetSystemDirectoryW(PWideChar(Result), dwSize);
    if CopyW(PWideChar(Result), dwSize - 1, 1) <> cSlashW then
      lstrcatW(PWideChar(Result), PWideChar(cSlashW));
  end;
end;

function TempPathA():string;
var
  dwSize: DWORD;
begin
  dwSize := GetTempPathA(0, nil);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetTempPathA(dwSize, PChar(Result));
    Result := PChar(Result);
  end;
end;

function TempPathW():WideString;
var
  dwSize: DWORD;
begin
  dwSize := GetTempPathW(0, nil);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetTempPathW(dwSize, PWideChar(Result));
  end;
end;

function WindowsVersion():string;
var
  OSINFO: TOSVersionInfoEx;
begin
  OSINFO.dwOSVersionInfoSize := SizeOf(OSINFO);
  if GetVersionExA(OSINFO) then
  begin
    if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 0) then
      Result := 'Windows 2000'
    else if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 1) then
      Result := 'Windows XP'
    else if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 2) and (GetSystemMetrics(SM_SERVERR2) = 0) then
      Result := 'Windows Server 2003'
    else if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 2) and (GetSystemMetrics(SM_SERVERR2) <> 0) then
      Result := 'Windows Server 2003 R2'
    else if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 0) and (OSINFO.wProductType = VER_NT_WORKSTATION) then
      Result := 'Windows Vista'
    else if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 0) and (OSINFO.wProductType <> VER_NT_WORKSTATION) then
      Result := 'Windows Server 2008'
    else if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 1) and (OSINFO.wProductType <> VER_NT_WORKSTATION) then
      Result := 'Windows Server 2008 R2'
    else if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 1) and (OSINFO.wProductType = VER_NT_WORKSTATION) then
      Result := 'Windows 7'
    else
      Result := 'Unknown';
  end;
end;

function Is64BitOS():Boolean;
begin
  IsWow64Process(INVALID_HANDLE_VALUE, Result);
end;

function CopyA(szInput:PChar; dwIndex:DWORD; dwSize:DWORD):PChar;
asm
  PUSH EDI
  PUSH ESI
  PUSH ECX
  PUSH EAX
  MOV ESI, szInput
  ADD ESI, dwIndex
  DEC ESI
  PUSH ECX
  PUSH PAGE_READWRITE
  PUSH MEM_COMMIT
  PUSH dwSize
  PUSH 0
  CALL VirtualAlloc
  POP ECX
  MOV EDI, EAX
  PUSH ECX
  REP MOVSB
  POP ECX
  SUB EDI, ECX
  POP EAX
  MOV EAX, EDI
  POP ECX
  POP ESI
  POP EDI
end;

function CopyW(szInput:PWideChar; dwIndex:DWORD; dwSize:DWORD):PWideChar;
asm
  PUSH EDI
  PUSH ESI
  PUSH ECX
  PUSH EAX
  MOV ESI, szInput
  ADD ESI, dwIndex
  DEC ESI
  ADD ECX, 2
  PUSH ECX
  PUSH PAGE_READWRITE
  PUSH MEM_COMMIT
  PUSH dwSize
  PUSH 0
  CALL VirtualAlloc
  POP ECX
  MOV EDI, EAX
  PUSH ECX
  REP MOVSB
  POP ECX
  SUB EDI, ECX
  POP EAX
  MOV EAX, EDI
  POP ECX
  POP ESI
  POP EDI
end;

function LeftStr(szInput:string; dwSize:DWORD):string;
begin
  Result := CopyA(PChar(szInput), 1, dwSize);
end;

function RightStr(szInput:string; dwSize:DWORD):string;
var
  dwLen:  DWORD;
begin
  dwLen := Length(szInput);
  Result := CopyA(PChar(szInput), dwLen - dwSize + 1, dwSize);
end;

function MidStr(szInput:string; dwIndex:DWORD; dwSize:DWORD):string;
begin
  Result := CopyA(PChar(szInput), dwIndex, dwSize);
end;

function KeyToStr(hRoot:HKEY; szSubKey:string; szValue:string; var szOutput:string):Boolean;
var
  hOpen:  HKEY;
  wSize:  Integer;
begin
  Result := FALSE;
  if RegOpenKey(hRoot, nil, hOpen) = 0 then
  begin
    wSize := 1024;
    SetLength(szOutput, 1024);
    if RegQueryValue(hOpen, PChar(szSubKey), PChar(szOutput), wSize) = 0 then
    begin
      szOutput := PChar(szOutput);
      Result := TRUE;
    end;
    RegCloseKey(hOpen);
  end;
end;

function StrToKey(hRoot:HKEY; szSubKey:string; szValue:string; szInput:string):Boolean;
var
  hOpen: HKEY;
begin
  Result := FALSE;
  if RegCreateKeyEx(hRoot, PChar(szSubKey), 0, nil, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nil, hOpen, nil) = 0 then
  begin
    if RegSetValueEx(hOpen, PChar(szValue), 0, REG_SZ, PChar(szInput), Length(szInput)) = 0 then
      Result := TRUE;
    RegCloseKey(hOpen);
  end;
end;

procedure CopyMemory(Destination:Pointer; Source:Pointer; dwSize:DWORD);
asm
  PUSH EDI
  PUSH ESI
  PUSH ECX
  MOV EDI, Destination
  MOV ESI, Source
  REP MOVSB
  POP ECX
  POP ESI
  POP EDI
end;

function IsValidPE(szFilePath:string):Boolean;
var
  hFile:  DWORD;
  dwRead: DWORD;
  IDH:    TImageDosHeader;
  INH:    TImageNtHeaders;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if ValidHandle(hFile) then
  begin
    SetFilePointer(hFile, 0, nil, FILE_BEGIN);
    ReadFile(hFile, IDH, 64, dwRead, nil);
    if IDH.e_magic = IMAGE_DOS_SIGNATURE then
    begin
      SetFilePointer(hFile, IDH._lfanew, nil, FILE_BEGIN);
      ReadFile(hFile, INH, 248, dwRead, nil);
      if INH.Signature = IMAGE_NT_SIGNATURE then
        Result := TRUE;
    end;
    CloseHandle(hFile);
  end;
end;

function LongPath(szInput:string):string;
var
  dwSize: DWORD;
begin
  dwSize := GetLongPathNameA(PChar(szInput), nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetLongPathNameA(PChar(szInput), PChar(Result), dwSize);
  end;
end;

function ShortPath(szInput:string):string;
var
  dwSize: DWORD;
begin
  dwSize := GetShortPathName(PChar(szInput), nil, 0);
  if ValidSize(dwSize) then
  begin
    SetLength(Result, dwSize);
    GetShortPathName(PChar(szInput), PChar(Result), dwSize);
  end;
end;

function UpdateResources(szFilePath:string; szType:PChar; szName:PChar; wLang:WORD; bDeleteExisting:Boolean; szInput:Pointer; dwSize:DWORD):Boolean;
var
  hRes: DWORD;
begin
  Result := FALSE;
  hRes := BeginUpdateResource(PChar(szFilePath), bDeleteExisting);
  if hRes <> 0 then
  begin
    if UpdateResource(hRes, szType, szName, wLang, szInput, dwSize) then
    begin
      if EndUpdateResource(hRes, FALSE) then
        Result := TRUE;
    end
    else
      EndUpdateResource(hRes, TRUE);
  end;
end;

function GetResource(hModule:DWORD; szType:PChar; szName:PChar; var pOutput:Pointer; var dwSize:DWORD):Boolean;
var
  hFind:  DWORD;
  hLoad:  DWORD;
  pMem:   Pointer;
begin
  Result := FALSE;
  hFind := FindResource(hModule, szName, szType);
  if hFind <> 0 then
  begin
    dwSize := SizeofResource(hModule, hFind);
    if ValidSize(dwSize) then
    begin
      hLoad := LoadResource(hModule, hFind);
      if hLoad <> 0 then
      begin
        if AllocMemory(pOutput, nil, dwSize, PAGE_READWRITE) then
        begin
          pMem := LockResource(hLoad);
          if Assigned(pMem) then
          begin
            CopyMemory(pOutput, pMem, dwSize);
            Result := TRUE;
          end;
        end;
        FreeResource(hLoad);
      end;
    end;
    CloseHandle(hFind);
  end;
end;

function FileExists(szFilePath:string):Boolean;
var
  hFile:  DWORD;
  WIN32:  TWin32FindData;
begin
  Result := FALSE;
  hFile := FindFirstFile(PChar(szFilePath), WIN32);
  if ValidHandle(hFile) then
  begin
    FindClose(hFile);
    Result := TRUE;
  end;
end;

procedure ShowMessageA(szMessage:string);
begin
  MessageBox(0, PChar(szMessage), szInfoA, MB_ICONINFORMATION);
end;

procedure ShowMessageW(szMessage:WideString);
begin
  MessageBoxW(0, PWideChar(szMessage), szInfoW, MB_ICONINFORMATION);
end;

procedure ShowErrorA(szMessage:string);
begin
  MessageBox(0, PChar(szMessage), szErrorA, MB_ICONEXCLAMATION);
end;

procedure ShowErrorW(szMessage:WideString);
begin
  MessageBoxW(0, PWideChar(szMessage), szErrorW, MB_ICONEXCLAMATION);
end;

function FileTypeA(szFilePath:string):string;
var
  SHInfo: TSHFileInfo;
begin
  if SHGetFileInfoA(PChar(szFilePath), 0, SHInfo, SizeOf(SHInfo), SHGFI_TYPENAME) <> 0 then
    Result := SHInfo.szTypeName;
end;

function FileTypeW(szFilePath:WideString):WideString;
var
  SHInfo: TSHFileInfoW;
begin
  if SHGetFileInfoW(PWideChar(szFilePath), 0, SHInfo, SizeOf(SHInfo), SHGFI_TYPENAME) <> 0 then
    Result := SHInfo.szTypeName;
end;

function DefaultBrowser():string;
begin
  if KeyToStr(HKEY_CLASSES_ROOT, 'http\shell\open\command\', szNull, Result) then
  begin
    if Result[1] = '"' then
      Result := CopyA(PChar(Result), 2, Pos(szEXE, Result) + 2)
    else
      Result := CopyA(PChar(Result), 1, Pos(szEXE, Result) + 3);
  end;
end;

function PosChar(Delimiter:Char; szInput:string):DWORD;
var
  i:  DWORD;
begin
  Result := 0;
  for i := 1 to Length(szInput) do
  begin
    if szInput[i] = Delimiter then
    begin
      Result := i;
      Exit;
    end;
  end;
end;

procedure lstrcpyA(szOutput:PChar; szInput:PChar);
asm
  PUSH EAX
  PUSH ECX
  PUSH ESI
  PUSH EDI
  MOV ESI, EDX
  MOV EDI, EAX
  PUSH EDX
  CALL lstrlenA
  TEST EAX, EAX
  JE @End
  MOV ECX, EAX
  REP MOVSB
@End:
  POP EDI
  POP ESI
  POP ECX
  POP EAX
end;

procedure lstrcpyW(szOutput:PWideChar; szInput:PWideChar);
asm
  PUSH EAX
  PUSH EBX
  PUSH ECX
  PUSH ESI
  PUSH EDI
  MOV ESI, EDX
  MOV EDI, EAX
  PUSH EDX
  CALL lstrlenW
  TEST EAX, EAX
  MOV EBX, EAX
  MOV EAX, 2
  MUL EBX
  JE @End
  MOV ECX, EAX
  REP MOVSB
@End:
  POP EDI
  POP ESI
  POP ECX
  POP EBX
  POP EAX
end;

function MyGetProcAddress(hModule:DWORD; szFuncName:PChar):Pointer;
var
  IDH:        PImageDosHeader;
  INH:        PImageNtHeaders;
  IED:        PImageExportDirectory;
  i:          DWORD;
  dwNameAddr: DWORD;
  wOrdinal:   WORD;
begin
  Result := nil;
  IDH := Pointer(hModule);
  if IDH.e_magic = IMAGE_DOS_SIGNATURE then
  begin
    INH := Pointer(hModule + IDH._lfanew);
    if INH.Signature = IMAGE_NT_SIGNATURE then
    begin
      if INH.OptionalHeader.DataDirectory[0].VirtualAddress > 0 then
      begin
        IED := Pointer(hModule + INH.OptionalHeader.DataDirectory[0].VirtualAddress);
        for i := 0 to IED.NumberOfNames - 1 do
        begin
          dwNameAddr := DWORD(PDWORD(hModule + DWORD(IED.AddressOfNames) + i * 4)^);
          if lstrcmp(PChar(hModule + dwNameAddr), szFuncName) = 0 then
          begin
            wOrdinal := WORD(PWORD(hModule + DWORD(IED.AddressOfNameOrdinals) + i * 2)^);
            Result := Pointer(hModule + DWORD(PDWORD(hModule + DWORD(IED.AddressOfFunctions) + wOrdinal * 4)^));
          end;
        end;
      end;
    end;
  end;
end;

function MapFile(szFilePath:string; szMapName:string; var pMapped:Pointer; var dwSize:DWORD):Boolean;
var
  hFile:    DWORD;
  hMapping: DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(szFilePath), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
  if ValidHandle(hFile) then
  begin
    dwSize := GetFileSize(hFile, nil);
    if ValidSize(dwSize) then
    begin
      hMapping := CreateFileMapping(hFile, nil, PAGE_READWRITE, 0, 0, PChar(szMapName));
      if ValidSize(hMapping) then
      begin
        pMapped := MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
        if Assigned(pMapped) then
          Result := TRUE;
        CloseHandle(hMapping);
      end;
    end;
    CloseHandle(hFile);
  end;
end;

function UnMapFile(pMapped:Pointer):Boolean;
begin
  Result := FALSE;
  if UnMapViewOfFile(pMapped) then
    Result := TRUE;
end;

function GetMyHandle():DWORD;
asm
  MOV EAX, FS:[$30]
  MOV EAX, DWORD PTR[EAX+8]
end;

end.
