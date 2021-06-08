library Registry;

uses Windows, NShieldCore;
{$R *.res}
var
 DllName: string='regshield.dll';
 DllPath: array[0..255] of Char;

 MainRegSetValueExA: function(hKey:HKEY; lpValueName:PAnsiChar; Reserved:DWORD; dwType:DWORD; lpData:Pointer; cbData:DWORD):Longint; stdcall;
 MainRegSetValueExW: function(hKey:HKEY; lpValueName:PWideChar; Reserved:DWORD; dwType:DWORD; lpData:Pointer; cbData:DWORD):Longint; stdcall;

function SetDebugPrivileges():Boolean;
var
  hToken:     DWORD;
  dwLuid:     Int64;
  TokenPrivs: TTokenPrivileges;
  dwRetnLen:  DWORD;
begin
  Result := FALSE;
  if (OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken)) then
  begin
    if (LookupPrivilegeValue(nil, 'SeDebugPrivilege', dwLuid)) then
    begin
      TokenPrivs.PrivilegeCount := 1;
      TokenPrivs.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      TokenPrivs.Privileges[0].Luid := dwLuid;
      if (AdjustTokenPrivileges(hToken, FALSE, TokenPrivs, SizeOf(TTokenPrivileges), nil, dwRetnLen)) then
        Result := TRUE;
    end;
    CloseHandle(hToken);
  end;
end;
(******************************************************************************)
function HookRegSetValueExA(hKey: HKEY; lpValueName: PAnsiChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
var S:string;
begin
 S:=string(lpValueName);
 if (StrCmp(S,'DisableTaskMgr') or StrCmp(S,'DisableRegistryTools') or  StrCmp(S,'NoClose') or StrCmp(S,'NoControlPanel') or
     StrCmp(S,'DisableCMD')) and (DWORD(lpData^)>=1) then DWORD(lpData^):=0;
 Result:=MainRegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
end;
(******************************************************************************)
function HookRegSetValueExW(hKey: HKEY; lpValueName: PWideChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
var S:string;
begin
 S:=WideToStr(lpValueName);
 if (StrCmp(S,'DisableTaskMgr') or StrCmp(S,'DisableRegistryTools') or  StrCmp(S,'NoClose') or StrCmp(S,'NoControlPanel') or
     StrCmp(S,'DisableCMD')) and (DWORD(lpData^)>=1) then DWORD(lpData^):=0;
 Result:=MainRegSetValueExW(hKey,lpValueName,Reserved,dwType,lpData,cbData);
end;
(******************************************************************************)
procedure DLLEntryPoint(dwReason:DWORD);
begin
 case dwReason of
   DLL_PROCESS_ATTACH: begin
   SetDebugPrivileges();
     ApiHook('advapi32.dll','RegSetValueExA',nil,@HookRegSetValueExA,@MainRegSetValueExA);
     ApiHook('advapi32.dll','RegSetValueExW',nil,@HookRegSetValueExW,@MainRegSetValueExW);
     GetModuleFileName(GetModuleHandle(Pchar(DllName)),DllPath,SizeOf(DllPath));
   end;
   DLL_PROCESS_DETACH: begin
     ApiUnHook('advapi32.dll','RegSetValueExA',nil,@HookRegSetValueExA,@MainRegSetValueExA);
     ApiUnHook('advapi32.dll','RegSetValueExW',nil,@HookRegSetValueExW,@MainRegSetValueExW);
   end;
 end;
end;
(******************************************************************************)
begin
 DllProc:=@DLLEntryPoint;
 DLLEntryPoint(DLL_PROCESS_ATTACH);
end.

