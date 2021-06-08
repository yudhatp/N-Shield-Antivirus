unit NShieldHook;

interface

uses
Windows, Messages, Classes, SysUtils;

type

//NtHook class related types
TNtJmpCode=packed record //8 Bytes
MovEax:Byte;
Addr:DWORD;
JmpCode:Word;
dwReserved:Byte;
end;

TNtHookClass=class(TObject)
private
hProcess:THandle;
NewAddr:TNtJmpCode;
OldAddr:array[0..7] of Byte;
ReadOK:Boolean;
public
BaseAddr:Pointer;
constructor Create(DllName,FuncName:string;NewFunc:Pointer);
destructor Destroy; override;
procedure Hook;
procedure UnHook;
end;




implementation





//==================================================
//NtHOOK Class Start
//==================================================
constructor TNtHookClass.Create(DllName: string; FuncName: string;NewFunc:Pointer);
var
DllModule:HMODULE;
dwReserved:DWORD;
begin
//Get Module Handle
DllModule:=GetModuleHandle(PChar(DllName));
//If DllModule is not loaded use LoadLibrary
if DllModule=0 then DllModule:=LoadLibrary(PChar(DllName));
//Get module entry address (base address)
BaseAddr:=Pointer(GetProcAddress(DllModule,PChar(FuncName)));
//Get the current process handle
hProcess:=GetCurrentProcess;
//Pointer to point to the new address
NewAddr.MovEax:=$B8;
NewAddr.Addr:=DWORD(NewFunc);
NewAddr.JmpCode:=$E0FF;
//Save the original address
ReadOK:=ReadProcessMemory(hProcess,BaseAddr,@OldAddr,8,dwReserved);
//Starting block
Hook;
end;

//Release object
destructor TNtHookClass.Destroy;
begin
UnHook;
CloseHandle(hProcess);

inherited;
end;

//Starting block
procedure TNtHookClass.Hook;
var
dwReserved:DWORD;
begin
if (ReadOK=False) then Exit;
//Write a new address
WriteProcessMemory(hProcess,BaseAddr,@NewAddr,8,dwReserved);
end;

//Recovery block
procedure TNtHookClass.UnHook;
var
dwReserved:DWORD;
begin
if (ReadOK=False) then Exit;
//Recovery Address
WriteProcessMemory(hProcess,BaseAddr,@OldAddr,8,dwReserved);
end;

end.