unit ProcessMonitor;

interface

uses
  Windows, messages, WinSvc, SysUtils, tlhelp32, Classes, Dialogs, PsAPI, Forms, Graphics, NShieldCore;
Const
  THREAD_ALL_ACCESS = ($000F0000 Or $00100000 Or $3FF);
function OpenThread(dwDesiredAccess : DWORD; bInheritHandle : BOOL; dwThreadId : DWORD) : THandle;

//type class untuk IPC menggunakan mailslot
//-----------------------------------------
Type
  TApiMsg = record
    Pid :Dword;
    //Apicall : array[0..89] of char;
  end;


const
  Slotname = 'nshieldIPC';
  Dllname:string='navhook.dll';  //engine untuk anti keylogger
  
implementation


uses Unit1;

Procedure SendInfo(Msg: TApiMsg);
var
MailSlot: THandle;
BytesWritten: DWord;
begin
  MailSlot := CreateFile(PChar('\\.\mailslot\' +Slotname),
    GENERIC_WRITE, FILE_SHARE_READ, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if (MailSlot <> INVALID_HANDLE_VALUE) then begin
    WriteFile(MailSlot, Msg, SizeOf(Msg), BytesWritten, nil);
    CloseHandle(MailSlot);
  end;
end;

function OpenThread; external 'kernel32.dll' name 'OpenThread'

var
  DriverDevice: THandle = 0;
  ProcessMonitorEvent: THandle;

type
  TVersionInfo = record
    CompanyName: WideString;
    FileDescription: WideString;
    FileVersion: WideString;
    InternalName: WideString;
    LegalCopyright: WideString;
    LegalTradeMarks: WideString;
    OriginalFilename: WideString;
    ProductName: WideString;
    ProductVersion: WideString;
    Comments: WideString;
    Language: WideString;
    Translation: WideString;

    FileVersionMajor: Word;
    FileVersionMinor: Word;
    FileVersionRelease: Word;
    FileVersionBuild: Word;
    ProductVersionMajor: Word;
    ProductVersionMinor: Word;
    ProductVersionRelease: Word;
    ProductVersionBuild: Word;

    Debug: Boolean;
    Patched: Boolean;
    PreRelease: Boolean;
    PrivateBuild: Boolean;
    SpecialBuild: Boolean;
  end;

type
  TProcessMonitorThread = class(TThread)
  private
    procedure GetProcessMonitorData;
  protected
    constructor Create(CreateSuspended: Boolean);
    procedure Execute; override;
  end;

function SetCurrentProcessPrivilege(Privilege: WideString): Boolean;
var
  TokenHandle: THandle;
  TokenPrivileges: TTokenPrivileges;
  ReturnLength: Cardinal;
begin
  Result := False;
  if Windows.OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, TokenHandle) then
  begin
    try
      LookupPrivilegeValueW(nil, PWideChar(Privilege), TokenPrivileges.Privileges[0].Luid);
      TokenPrivileges.PrivilegeCount := 1;
      TokenPrivileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      if AdjustTokenPrivileges(TokenHandle, False, TokenPrivileges, 0, nil, ReturnLength) then
        Result := True;
    finally
      CloseHandle(TokenHandle);
    end;
  end;
end;

function GetFileVersionInfo(FileName: WideString; var VersionInfo: TVersionInfo): Boolean;
var
  Handle, Len, Size: Cardinal;
  Translation: WideString;
  Data: PWideChar;
  Buffer: Pointer;
  FixedFileInfo: PVSFixedFileInfo;
begin
  Result := False;
  Finalize(VersionInfo);
  try
    Size := GetFileVersionInfoSizeW(PWideChar(FileName), Handle);
    if Size > 0 then
    begin
      try
        GetMem(Data, Size);
        if GetFileVersionInfoW(PWideChar(FileName), Handle, Size, Data) then
        begin
          if VerQueryValue(Data, '\', Pointer(FixedFileInfo), Len) then
          begin
            VersionInfo.Debug := False;
            VersionInfo.Patched := False;
            VersionInfo.PreRelease := False;
            VersionInfo.PrivateBuild := False;
            VersionInfo.SpecialBuild := False;

            VersionInfo.FileVersionMajor := HiWord(FixedFileInfo^.dwFileVersionMS);
            VersionInfo.FileVersionMinor := LoWord(FixedFileInfo^.dwFileVersionMS);
            VersionInfo.FileVersionRelease := HiWord(FixedFileInfo^.dwFileVersionLS);
            VersionInfo.FileVersionBuild := LoWord(FixedFileInfo^.dwFileVersionLS);
            VersionInfo.ProductVersionMajor := HiWord(FixedFileInfo^.dwProductVersionMS);
            VersionInfo.ProductVersionMinor := LoWord(FixedFileInfo^.dwProductVersionMS);
            VersionInfo.ProductVersionRelease := HiWord(FixedFileInfo^.dwProductVersionLS);
            VersionInfo.ProductVersionBuild := LoWord(FixedFileInfo^.dwProductVersionLS);

            VersionInfo.FileVersion := IntToStr(HiWord(FixedFileInfo^.dwFileVersionMS)) + '.' + IntToStr(LoWord(FixedFileInfo^.dwFileVersionMS)) + '.' + IntToStr(HiWord(FixedFileInfo^.dwFileVersionLS)) + '.' + IntToStr(LoWord(FixedFileInfo^.dwFileVersionLS))
          end;

          if VerQueryValueW(Data, '\VarFileInfo\Translation', Buffer, Len) then
          begin
            Translation := IntToHex(PDWORD(Buffer)^, 8);
            Translation := Copy(Translation, 5, 4) + Copy(Translation, 1, 4);
            VersionInfo.Translation := '$' + Copy(Translation, 1, 4);

            SetLength(VersionInfo.Language, 64);
            SetLength(VersionInfo.Language, VerLanguageNameW(StrToIntDef('$' + Copy(Translation, 1, 4), $0409), PWideChar(VersionInfo.Language), 64));
          end;

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\CompanyName'), Buffer, Len) then
            VersionInfo.CompanyName := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\FileDescription'), Buffer, Len) then
            VersionInfo.FileDescription := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\FileVersion'), Buffer, Len) then
            VersionInfo.FileVersion := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\InternalName'), Buffer, Len) then
            VersionInfo.InternalName := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\LegalCopyright'), Buffer, Len) then
            VersionInfo.LegalCopyright := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\LegalTradeMarks'), Buffer, Len) then
            VersionInfo.LegalTradeMarks := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\OriginalFilename'), Buffer, Len) then
            VersionInfo.OriginalFilename := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\ProductName'), Buffer, Len) then
            VersionInfo.ProductName := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\ProductVersion'), Buffer, Len) then
            VersionInfo.ProductVersion := PWideChar(Buffer);

          if VerQueryValueW(Data, PWideChar('\StringFileInfo\' + Translation + '\Comments'), Buffer, Len) then
            VersionInfo.Comments := PWideChar(Buffer);
          Result := True;
        end;
      finally
        FreeMem(Data);
      end;
    end;
  except
  end;
end;

function SuspendProcess(PID:DWORD):Boolean;
var
hSnap:  THandle;
THR32:  THREADENTRY32;
hOpen:  THandle;
begin
  Result := FALSE;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if hSnap <> INVALID_HANDLE_VALUE then
  begin
    THR32.dwSize := SizeOf(THR32);
    Thread32First(hSnap, THR32);
    repeat
      if THR32.th32OwnerProcessID = PID then
      begin
        hOpen := OpenThread($0002, FALSE, THR32.th32ThreadID);
        if hOpen <> INVALID_HANDLE_VALUE then
        begin
          Result := TRUE;
          SuspendThread(hOpen);
          CloseHandle(hOpen);
        end;
      end;
    until Thread32Next(hSnap, THR32) = FALSE;
    CloseHandle(hSnap);
  end;
end;

Function ResumeProcess(ProcessID: DWORD): Boolean;
var
  Snapshot,cThr: DWORD;
  ThrHandle: THandle;
  Thread:TThreadEntry32;
begin
  Result := False;
  cThr := GetCurrentThreadId;
  Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if Snapshot <> INVALID_HANDLE_VALUE then
   begin
    Thread.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(Snapshot, Thread) then
     repeat
      if (Thread.th32ThreadID <> cThr) and (Thread.th32OwnerProcessID = ProcessID) then
       begin
        ThrHandle := OpenThread(THREAD_ALL_ACCESS, false, Thread.th32ThreadID);
        if ThrHandle = 0 then Exit;
        ResumeThread(ThrHandle);
        CloseHandle(ThrHandle);
       end;
     until not Thread32Next(Snapshot, Thread);
     Result := CloseHandle(Snapshot);
    end;
end;

function InstallAndStartDriver(DriverPath: WideString): Boolean;
var
  hSCManager, hService: SC_HANDLE;
  lpServiceArgVectors: PWideChar;
begin
  Result := False;
  hSCManager := 0;
  hSCManager := OpenSCManagerW(nil, nil, SC_MANAGER_ALL_ACCESS);
  if hSCManager <> 0 then
  begin
    try
      hService := 0;
      hService := CreateServiceW(hSCManager, 'NShield', 'NShield Driver', SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, PWideChar(DriverPath), nil, nil, nil, nil, nil);
      hService := 0;
      lpServiceArgVectors := nil;
      hService := OpenServiceW(hSCManager, 'NShield', SERVICE_ALL_ACCESS);
      if hService <> 0 then
      begin
        try
          if StartServiceW(hService, 0, PWideChar(lpServiceArgVectors)) then
          begin
            Result := True;
          end;
        finally
          CloseServiceHandle(hService);
        end;
      end;
    finally
      CloseServiceHandle(hSCManager);
    end;
  end;
  if (DriverDevice <> 0) then
    CloseHandle(DriverDevice);
  DriverDevice := CreateFileW('\\.\' + 'NSHIELD', GENERIC_READ or GENERIC_WRITE, 0, PSECURITY_DESCRIPTOR(nil), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
end;

function UnInstallAndStopDriver: Boolean;
var
  hSCManager, hService: SC_HANDLE;
  lpServiceStatus: TServiceStatus;
begin
  Result := False;
  hSCManager := 0;
  hSCManager := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if (DriverDevice <> 0) then
    CloseHandle(DriverDevice);
  if hSCManager <> 0 then
  begin
    try
      hService := 0;
      hService := OpenService(hSCManager, 'NShield', SERVICE_ALL_ACCESS);
      if (hService <> 0) then
      begin
        try
          if ControlService(hService, SERVICE_CONTROL_STOP, lpServiceStatus) then
          begin
            Result := True;
            DeleteService(hService);
          end;
        finally
          CloseServiceHandle(hService);
        end;
      end;
    finally
      CloseServiceHandle(hSCManager);
    end;
  end;
end;

function CTL_CODE(DeviceType: Integer; Func: Integer; Meth: Integer; Access: Integer): DWORD;
begin
  Result := (DeviceType shl 16) or (Access shl 14) or (Func shl 2) or (Meth);
end;

{type
  TOpenProcessCallbackInfo = record
    ProcessHandle: THandle;
  end;

  POpenProcessCallbackInfo = ^TOpenProcessCallbackInfo;

type
  TOpenProcessInfo = record
    ProcessId: THandle;
    DesiredAccess: ACCESS_MASK;
  end;

  POpenProcessInfo = ^TOpenProcessInfo;

function KernelOpenProcess(DesiredAccess: Cardinal; ProcessId: DWORD; var ProcessHandle: THandle): Boolean;
var
  dwBytesReturned: DWORD;
  OpenProcessCallbackInfo: TOpenProcessCallbackInfo;
  OpenProcessInfo: TOpenProcessInfo;
begin
  Result := False;
  ProcessHandle := 0;

  OpenProcessInfo.ProcessId := THandle(ProcessId);
  OpenProcessInfo.DesiredAccess := DesiredAccess;

  if DeviceIoControl(DriverDevice, CTL_CODE($F100, $0903, 0, 0), @OpenProcessInfo, Sizeof(OpenProcessInfo), @OpenProcessCallbackInfo, Sizeof(OpenProcessCallbackInfo), dwBytesReturned, 0) then
  begin
    ProcessHandle := OpenProcessCallbackInfo.ProcessHandle;
    Result := True;
  end;
end;

//Пример открытия процесса в драйвере, хотя толку от этого мало, надо передавать все данные из драйвера или ждать пока процесс инициализируеться

var
  ProcessHandle: THandle;
begin
  if KernelOpenProcess(MAXIMUM_ALLOWED, ProcessId, ProcessHandle) then
  begin
    try
    
    finally
      CloseHandle(ProcessHandle);
    end;
  end;
end;
}

function NormalizePath(Path: PWideChar): WideString;
var
  lpDeviceName: array [0 .. MAX_PATH] of WideChar;
  lpDrive: WideString;
  Drive: WideChar;
begin
  Result := '';
  try
    for Drive := 'A' to 'Z' do
    begin
      lpDrive := WideString(Drive) + ':';
      if (QueryDosDeviceW(PWideChar(lpDrive), lpDeviceName, MAX_PATH) <> 0) then
      begin
        if (CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, lpDeviceName, lstrlenW(lpDeviceName), Path, lstrlenW(lpDeviceName)) = CSTR_EQUAL) then
        begin
          Result := WideString(Path);
          Delete(Result, 1, lstrlenW(lpDeviceName));
          Result := WideString(lpDrive) + Result;
          Break;
        end;
      end;
    end;
  except
  end;
end;

var
  ProcessMonitorActive: Boolean = False;

type
  TProcessMonitorInfo = record
    ProcessMonitorEvent: THandle;
    HostProcessId: THandle;
  end;

  PProcessMonitorInfo = ^TProcessMonitorInfo;

constructor TProcessMonitorThread.Create(CreateSuspended: Boolean);
var
  dwBytesReturned: DWORD;
  ProcessMonitorInfo: TProcessMonitorInfo;
begin
  inherited Create(CreateSuspended);
  FreeOnTerminate := True;
  Priority := tpHighest;
  try
    ProcessMonitorEvent := CreateEvent(nil, False, False, nil);
    if GetLastError = ERROR_ALREADY_EXISTS then
    begin
      if ProcessMonitorEvent <> 0 then
        CloseHandle(ProcessMonitorEvent);
    end;
  except
  end;
  ProcessMonitorInfo.ProcessMonitorEvent := ProcessMonitorEvent;
  ProcessMonitorInfo.HostProcessId := GetCurrentProcessId;
  if DeviceIoControl(DriverDevice, CTL_CODE($F100, $0901, 0, 0), @ProcessMonitorInfo, Sizeof(ProcessMonitorInfo), nil, 0, dwBytesReturned, 0) then
  begin
    ProcessMonitorActive := True;
  end;
end;

type
  TProcessMonitorData = record
    ParentId: THandle;
    ProcessId: THandle;
    Create: Boolean;
    ProcessPath: array[0..255] of WideChar;
  end;

  PProcessMonitorData = ^TProcessMonitorData;

procedure TProcessMonitorThread.GetProcessMonitorData;
var
  dwBytesReturned: DWORD;
  ProcessMonitorData: PProcessMonitorData;
  EventName, ProcessPath: WideString;
  VersionInfo: TVersionInfo;
  info :TApiMsg;
begin
  GetMem(ProcessMonitorData, Sizeof(TProcessMonitorData));
  try
    if DeviceIoControl(DriverDevice, CTL_CODE($F100, $0902, 0, 0), nil, 0, ProcessMonitorData, Sizeof(TProcessMonitorData), dwBytesReturned, 0) then
    begin
      ProcessPath:= NormalizePath(ProcessMonitorData.ProcessPath);

      GetFileVersionInfo(ProcessPath, VersionInfo);

      with Form1.ListView1.Items.Add do
      begin
        if ProcessMonitorData.Create then
        begin
                EventName := 'Created';
        end
        else
        begin
          EventName := 'Deleted';
          //Data:= Pointer(clRed)
        end;

        caption := EventName;
        SubItems.Add(IntToStr(ProcessMonitorData.ProcessId));
        SubItems.Add(PWideChar(ProcessPath));
        SubItems.Add(VersionInfo.FileDescription);
        SubItems.Add(VersionInfo.CompanyName);

        //inject dengan DLL kita =))
        InjectAllProc(GetPath(ParamStr(0))+DllName);
      end;
         //showmessage(processpath);
         //info.Pid := ProcessMonitorData.ProcessId;
         //SendInfo(info);
    end;
  finally
    FreeMem(ProcessMonitorData);
  end;
end;

procedure TProcessMonitorThread.Execute;
begin
  while ProcessMonitorActive do
  begin
    if WaitForSingleObject(ProcessMonitorEvent, INFINITE) <> WAIT_FAILED then
    begin
      Synchronize(GetProcessMonitorData);
    end
    else
    begin
      Break;
    end;
    Sleep(1);
  end;
end;

function _Initialize: Boolean;
begin
  SetCurrentProcessPrivilege('SeDebugPrivilege');
  SetCurrentProcessPrivilege('SeLoadDriverPrivilege');
  if InstallAndStartDriver(ExtractFilePath(ParamStr(0)) + 'NShield.sys') then
    TProcessMonitorThread.Create(False);
end;

function _DeInitialize: Boolean;
begin
  UnInstallAndStopDriver;
  ProcessMonitorActive := False;
  if ProcessMonitorEvent <> 0 then
  begin
    CloseHandle(ProcessMonitorEvent);
  end;
end;

initialization

_Initialize;

finalization

_DeInitialize;

end.
