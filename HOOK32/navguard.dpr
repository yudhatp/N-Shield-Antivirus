library navguard;

uses
  SysUtils,
  Classes,
  Windows,
  //Dialogs,
  NShieldHook in 'NShieldHook.pas';

{$R *.res}

const
HOOK_MEM_FILENAME = 'tmp.hkt';
var
hhk: HHOOK;
Hook: array[0..2] of TNtHookClass;


MemFile: THandle;
startPid: PDWORD;
fhProcess: THandle; 



function NewOpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
type
TNewOpenProcess = function (dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
begin
if startPid^ = dwProcessId then begin
Hook[1].UnHook;
Result := TNewOpenProcess(Hook[1].BaseAddr)(dwDesiredAccess, bInheritHandle, dwProcessId);
fhProcess:=Result;
Hook[1].Hook;
exit;
end;
Hook[1].UnHook;
Result := TNewOpenProcess(Hook[1].BaseAddr)(dwDesiredAccess, bInheritHandle, dwProcessId);
Hook[1].Hook;

end;

function NewTerminateProcess(hProcess: THandle;uExitCode: UINT): BOOL; Stdcall;
type
TNewTerminateProcess = function (hProcess: THandle;uExitCode: UINT): BOOL; Stdcall;
begin
if fhProcess = hProcess then begin
MessageBox(0,PCHAR('Access Denied'),PCHAR('N-Shield AntiVirus'),MB_ICONERROR);
result := true;
exit;
end;
Hook[2].UnHook;
Result := TNewTerminateProcess(Hook[2].BaseAddr)(hProcess, uExitCode );
Hook[2].Hook;
end;

procedure InitHook; //Initialize Hook
begin
Hook[1] := TNtHookClass.Create('kernel32.dll', 'OpenProcess', @NewOpenProcess);
hook[2] := TNtHookClass.Create('kernel32.dll', 'TerminateProcess', @NewTerminateProcess);
end;

procedure UninitHook; //Un-Initialize Hook
var
I: Integer;
begin
for I := 0 to High(Hook) do
begin
FreeAndNil(Hook[I]);
end;
end;

procedure MemShared();
begin
MemFile:=OpenFileMapping(FILE_MAP_ALL_ACCESS,False , HOOK_MEM_FILENAME); //Open the memory mapped File
if MemFile = 0 then begin
MemFile := CreateFileMapping($FFFFFFFF, nil, PAGE_READWRITE, 0,
4, HOOK_MEM_FILENAME);
end;
if MemFile <> 0 then
//Map File to variables 
startPid := MapViewOfFile(MemFile,FILE_MAP_ALL_ACCESS,0,0,0);
end;

//Transfer 
function HookProc(nCode, wParam, lParam: Integer): Integer; stdcall;
begin
Result := CallNextHookEx(hhk, nCode, wParam, lParam);
end;

//Start HOOK
procedure StartGuard(pid: DWORD); stdcall;
begin
startPid^ := pid;
hhk := SetWindowsHookEx(WH_CALLWNDPROC, HookProc, hInstance, 0);
end;

//End HOOK
procedure EndGuard; stdcall;
begin
if hhk <> 0 then
UnhookWindowsHookEx(hhk);
end;


procedure DllEntry(dwResaon: DWORD);
begin
case dwResaon of
DLL_PROCESS_ATTACH: InitHook; 
DLL_PROCESS_DETACH: UninitHook; 
end;
end;

exports
StartGuard, EndGuard;

begin
MemShared;

{Distribution of DLL programs to DllProc variable}
DllProc:= @ DllEntry;
{Call the DLL load processing}
DllEntry (DLL_PROCESS_ATTACH);
end.