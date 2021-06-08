{
N-Shield AntiVirus
akcore.dll
untuk anti-keylogger
start coding    : 17 maret 2013
revisi terakhir : 3 Oktober 2013
using mailslot for IPC

problem :belum bisa menginjeksi proses baru yang dijalankan dengan hak akses administrator
         keybd_event(44)  for trigerring print screen window

--------------------------------------------------------------------------------------------
hook rules :
1. fungsi yang di hook harus dikembalikan ke fungsi awalnya
2. jika melakukan hook pada system atau service,pastikan tidak menggunakan fungsi UI seperti
   messagebox, findwindow dan sebagainya
--------------------------------------------------------------------------------------------
}


library navhook;

{$IMAGEBASE $57800000}

uses Windows, NShieldCore;
{$R *.res}

type
 PCLIENT_ID = ^CLIENT_ID;
 CLIENT_ID = packed record
 ProcessId: ULONG;
 ThreadId: ULONG;
end;


//type class untuk IPC menggunakan mailslot
//-----------------------------------------
Type
  TApiMsg = record
    Pid :Dword;
    Apicall : array[0..89] of char;
  end;
//-----------------------------------------

NTSTATUS = Integer;

const
  STATUS_SUCCESS: NTSTATUS = 0;
  WH_KEYBOARD_LL          =13;
  Slotname = 'nshieldIPC';

  //opsional,untuk setwindowshookex, mencegah hook pada mouse [?]
  //WH_MOUSE_LL            =14;



var

 //nama dll dideklarasikan dengan nama Engine.dll dan harus pada path yang sama dengan *.exe
 DllName: string='akcore.dll';
 DllPath: array[0..255] of Char;

 //F sebagai handle untuk file temporary, PID sebagai nilai dari PID n-shield dengan tipe DWORD
 F: THandle;
 PID,Cnt: DWORD;

 //Deklarasi fungsi-fungsi asli yang akan di hook oleh n-shield

 MainCreateProcessInternalW: function(P1:DWORD; lpApplicationName:PWideChar; lpCommandLine:PWideChar; lpProcessAttributes,lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PWideChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation; P2:DWORD):BOOL; stdcall;
 MainOpenProcess: function(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
 MainCreateProcessAsUserA: function(hToken:THandle; lpApplicationName:PAnsiChar; lpCommandLine:PAnsiChar; lpProcessAttributes:PSecurityAttributes; lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PAnsiChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation):BOOL; stdcall;
 MainCreateProcessAsUserW: function(hToken:THandle; lpApplicationName:PWideChar; lpCommandLine:PWideChar; lpProcessAttributes:PSecurityAttributes; lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PWideChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation):BOOL; stdcall;
 GetAsyncKeyStateNext: function(vKey: Integer): SHORT; stdcall;
 GetKeyStateNext: function(nVirtKey: Integer): SHORT; stdcall;
 SetWindowsHookExANext: function(idHook: Integer; lpfn: TFNHookProc; hmod: HINST; dwThreadId: DWORD): HHOOK; stdcall;
 SetWindowsHookExWNext: function(idHook: Integer; lpfn: TFNHookProc; hmod: HINST; dwThreadId: DWORD): HHOOK; stdcall;
 GetKeyboardState: function(var KeyState: TKeyboardState) : LongBool;  stdcall;
 MainBitBlt: Function(DestDC: HDC; X, Y, Width, Height: Integer; SrcDC: HDC; XSrc, YSrc: Integer; Rop: DWORD): BOOL; stdcall;
 MainRtlSetProcessIsCritical:function(unu :DWORD ; proc:POinter ; doi: DWORD): LongInt; stdcall;
 //CreateRemoteThreadNext: function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress,lpParameter, dwCreationFlags, lpThreadId); stdcall;
{
==================================================================================
fungsi untuk mendapatkan PID dari suatu proses yang sudah di-injeksi oleh N-Shield
membutuhkan privilege yang cukup atau hak akses administrator
karena menggunakan fungsi native --NtQueryInformationProcess--
==================================================================================
}

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

{
==========================================================
fungsi untuk mendapatkan nama atau info dari module/proses
==========================================================
}
function GetModule(S:string):string;
begin
 Result:=S;
 //Jika result NULL atau kosong maka langsung keluar
 if S='' then Exit;
 if S[1]='"' then begin
  Delete(S,1,1);
  if S='' then Exit;
  Result:=Copy(S,1,Pos('"',S)-1);
 end
 else if Pos(' ',S)<>0 then Result:=Copy(S,1,Pos(' ',S)-1);
end;

{function CreateRemoteThreadCallback(hProcess: THandle; lpThreadAttributes: Pointer;
  dwStackSize: DWORD; lpStartAddress: TFNThreadStartRoutine; lpParameter: Pointer;
  dwCreationFlags: DWORD; var lpThreadId: DWORD): THandle; stdcall;
var HandleStore: TProcessHandleStore;
begin
if (CREATE_REMOTE_THREAD = pmAllow) or (IsFullTrust) or (GetCallingModule = GetModuleHandle(kernel32)) then
begin 
Result := CreateRemoteThreadNext(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, 
lpParameter, dwCreationFlags, lpThreadId); 
Exit; 
end 
  else if CREATE_REMOTE_THREAD = pmDeny then
    begin
      SetLastError(ERROR_ACCESS_DENIED);
      Result := 0;
    end
  else if CREATE_REMOTE_THREAD = pmAsk then
    begin
      if IPCRequestApiCall(CREATE_REMOTE_THREAD_API_TYPE, [IntToStr(GetProcessPID(hProcess))]) <> pmAllow then
        begin
          SetLastError(ERROR_ACCESS_DENIED);
          Result := 0;
        end
      else
        Result := CreateRemoteThreadNext(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress,
          lpParameter, dwCreationFlags, lpThreadId);
    end;        }

{
============================================================================================================
Fungsi hook winAPI CreateProcessInternalW
semua proses aktif di memory yang mencoba menjalankan file (ex: explorer.exe) dengan winAPI tsb akan di hook
hook hanya berlaku untuk proses yang sedang didebug atau rilis debug [?]
GAGAL - karena meminta hak akses administrator
============================================================================================================
}
function HookCreateProcessInternalW(P1:DWORD; lpApplicationName:PWideChar; lpCommandLine:PWideChar; lpProcessAttributes,lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PWideChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation; P2:DWORD):BOOL; stdcall;
var
 CrSuspend,Debuged: Boolean;
 //S1,S2: string;
begin
 Debuged:=((dwCreationFlags and DEBUG_PROCESS)=DEBUG_PROCESS) or
          ((dwCreationFlags and DEBUG_ONLY_THIS_PROCESS)=DEBUG_ONLY_THIS_PROCESS);
 if (P1=0) and (P2=0) and (not Debuged) then begin
 //S1:=GetModule(WideToStr(lpApplicationName));
 //S2:=GetModule(WideToStr(lpCommandLine));
 // messagebox(0,'tidak terinject','warning', MB_ICONWARNING);


 //jika nama Company Name yaitu "anu" maka blok atau jangan di-izinkan untuk aktif [?]
 //if (S1='anu') and (Pos('',GetFileInfo(S1,'CompanyName'))=0) then begin
 //  Result:=False;
 //  SetLastError(ERROR_ACCESS_DENIED);
 //  exit;
 // end;

 // CrSuspend:=((dwCreationFlags and CREATE_SUSPENDED)=CREATE_SUSPENDED);
//  dwCreationFlags:=dwCreationFlags or CREATE_SUSPENDED;
  Result:=MainCreateProcessInternalW(P1,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation,P2);
  InjectDll(DllPath,lpProcessInformation.dwProcessId);
 // if not CrSuspend then ResumeThread(lpProcessInformation.hThread);
end
 else
 Result:=MainCreateProcessInternalW(P1,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation,P2);
 InjectDll(DllPath,lpProcessInformation.dwProcessId);
end;

{
=============================================
Fungsi untuk hook winAPI CreateProcessAsUserA
=============================================
}
function HookCreateProcessAsUserA(hToken:THandle; lpApplicationName:PAnsiChar; lpCommandLine:PAnsiChar; lpProcessAttributes:PSecurityAttributes; lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PAnsiChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation):BOOL; stdcall;
var
 CrSuspend: Boolean;
 S1,S2: string;
begin
 S1:=GetModule(string(lpApplicationName));
 S2:=GetModule(string(lpCommandLine));
 if (S1='anu') and (Pos('',GetFileInfo(S1,'CompanyName'))=0) then begin
 SetLastError(ERROR_ACCESS_DENIED);
 Exit;
 end;

 CrSuspend:=((dwCreationFlags and CREATE_SUSPENDED)=CREATE_SUSPENDED);
 dwCreationFlags:=dwCreationFlags or CREATE_SUSPENDED;
 Result:=MainCreateProcessAsUserA(hToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
 InjectDll(DllPath,lpProcessInformation.dwProcessId);
 if not CrSuspend then ResumeThread(lpProcessInformation.hThread);
end;

function HookCreateProcessAsUserW(hToken:THandle; lpApplicationName:PWideChar; lpCommandLine:PWideChar; lpProcessAttributes:PSecurityAttributes; lpThreadAttributes:PSecurityAttributes; bInheritHandles:BOOL; dwCreationFlags:DWORD; lpEnvironment:Pointer; lpCurrentDirectory:PWideChar; const lpStartupInfo:TStartupInfo; var lpProcessInformation:TProcessInformation):BOOL; stdcall;
var
 CrSuspend: Boolean;
 S1,S2: string;
begin
 S1:=GetModule(WideToStr(lpApplicationName));
 S2:=GetModule(WideToStr(lpCommandLine));
 if (S1='anu') and (Pos('',GetFileInfo(S1,'CompanyName'))=0) then begin

  Result:=False;
  SetLastError(ERROR_ACCESS_DENIED);
  exit;
  end;

  CrSuspend:=((dwCreationFlags and CREATE_SUSPENDED)=CREATE_SUSPENDED);
  dwCreationFlags:=dwCreationFlags or CREATE_SUSPENDED;
  Result:=MainCreateProcessAsUserW(hToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
  InjectDll(DllPath,lpProcessInformation.dwProcessId);
 if not CrSuspend then ResumeThread(lpProcessInformation.hThread);
end;



{
=====================================
mencegah proses lain membuat critical
code original =))
=====================================
}
Function RtlSetProcessIsCriticalCallBack(unu :DWORD ; proc:POinter ; doi: DWORD): LongInt; stdcall;
var

 //variabe; myresult dideklarasikan sebagia long integer [longint] ,agar sama dengan result fungsi aslinya
 myresult : longint;
 info :TApiMsg;
 //tanya dahulu apakah user mengizinkan atau tidak,jika tidak maka result dikembalikan ke fungsi sebenarnya
 begin
 if MessageBox(0, 'other process want to make critical process, block function?', 'Question', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
    begin

    //jika user ingin memblok fungsi maka variabel myresult diberikan nilai 0 atau false
    myresult := 0;
    result:= myresult;
    info.Pid := PHandleToPID(getcurrentprocess);
    info.Apicall := 'Make critical process';

    //kirim data ke n-shield.exe, diletakkan di listview
    SendInfo(info);
    end else
    result := MainRtlSetProcessIsCritical(unu,proc,doi);
end;


{
===========================================================================================================
fungsi anti screen-logger atau anti capture
proses lain juga menggunakan fungsi ini,contoh winlogon.exe , sehingga ketika turn off maka mengalami error
credits to : cracksman (ic0de.org)
============================================================================================================
}
function BitBltCallBack(DestDC: HDC; X, Y, Width, Height: Integer; SrcDC: HDC; XSrc, YSrc: Integer; Rop: DWORD): BOOL; stdcall;
Var
  Handle: THandle;
  HDCSrc: HDC;
  DSize : TRect;
  info :TApiMsg;
begin

  //jika benar fungsi digunakan untuk membuat screenshoot maka
  IF (Width >= GetSystemMetrics(SM_CXSCREEN)) AND (Height >= GetSystemMetrics(SM_CYSCREEN)) then
  Begin
    //if MessageBox(0, 'Detected Screen Logger, block this?', 'Question', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
    //begin

    //hanya info,tidak mem-blok [?]
  info.Pid := PHandleToPID(getcurrentprocess);
  info.Apicall := 'Screen logger - Level 1';

  //kirim data ke n-shield.exe, diletakkan di listview
  SendInfo(info);
  Result := MainBitBlt(DestDC, X, Y, Width, Height, SrcDC, XSrc, YSrc, Rop);
    //opsi satu, mengatur size menjadi 0, sehingga hasil capture menjadi blank
    //Width := 0;
    //Height:= 0;
    //end else
    //Result := true;
    End;

    //opsi dua, mengganti gambar capture dengan gambar lain
    //Handle  := LoadImage(nil, 'c:\trollface.bmp', IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
    //HDCSrc  := CreateCompatibleDC(GetDC(0));
    //SelectObject(HDCSrc, Handle);
    //SrcDC := HDCSrc;//replace

  //pada akhrinya, kembalikan fungsi aslinya
  Result := MainBitBlt(DestDC, X, Y, Width, Height, SrcDC, XSrc, YSrc, Rop);
end;

//=================================================================================
function GetKeyboardStateCallBack(var KeyState: TKeyboardState) : LongBool;stdcall;
var
  myresult: Longbool;
begin
  begin
    myresult:= false;
	end;
  result:=myresult;
end;

//===============================================================
function GetAsyncKeyStateCallback(vKey: Integer): SHORT; stdcall;
var
  myresult: SHORT;
begin
  begin
    myresult:= 0;
	end;
  result:=myresult;
end;

//==============================================================
function GetKeyStateCallback(nVirtKey: Integer): SHORT; stdcall;
var
  myresult: SHORT;
begin
  begin
		myresult:= 0;
	end;
  result:=myresult;
end;

//=====================================================================================================================
function SetWindowsHookExACallback(idHook: Integer; lpfn: TFNHookProc; hmod: HINST; dwThreadId: DWORD): HHOOK; stdcall;
var
  myresult: HHOOK;
  info :TApiMsg;
begin
	if (idHook=WH_KEYBOARD_LL)or (idHook=WH_JOURNALRECORD) then
  begin
				result:=random(10000)+1;
        info.Pid := PHandleToPID(getcurrentprocess);
        info.Apicall := 'Keylogger - Level 1';

    //kirim data ke n-shield.exe, diletakkan di listview
    SendInfo(info);
	end else
	 myresult := SetWindowsHookExANext(idHook, lpfn, hMod, dwThreadId);
		result:=myresult;
end;

//=====================================================================================================================
function SetWindowsHookExWCallback(idHook: Integer; lpfn: TFNHookProc; hmod: HINST; dwThreadId: DWORD): HHOOK; stdcall;
var
  myresult: HHOOK;
  info :TApiMsg;
begin
	if (idHook=WH_KEYBOARD_LL) or (idHook=WH_JOURNALRECORD) then
  begin
				result:=random(10000)+1;
        info.Pid := PHandleToPID(getcurrentprocess);
        info.Apicall := 'Keylogger - Level 2';

        //kirim data ke n-shield.exe, diletakkan di listview
        SendInfo(info);
	         end else

        //jika bukan ID Hook low level keyboard, maka kembalikan result ke aslinya
	      myresult := SetWindowsHookExWNext( idHook, lpfn, hMod, dwThreadId);
		    result:=myresult;
end;

{
====================================
fungsi utama pada DLL engine.dll =))
====================================
}
procedure DLLEntryPoint(dwReason:DWORD);
begin
 case dwReason of
   DLL_PROCESS_ATTACH: begin
     DebugPrivilege(True);
     //ApiHook('advapi32.dll','CreateProcessAsUserA',nil,@HookCreateProcessAsUserA,@MainCreateProcessAsUserA);
     //ApiHook('advapi32.dll','CreateProcessAsUserW',nil,@HookCreateProcessAsUserW,@MainCreateProcessAsUserW);
     ApiHook('USER32.DLL', 'GetAsyncKeyState',nil, @GetAsyncKeyStateCallback, @GetAsyncKeyStateNext);
     ApiHook('USER32.DLL', 'SetWindowsHookExA',nil, @SetWindowsHookExACallback, @SetWindowsHookExANext);
     ApiHook('USER32.DLL', 'SetWindowsHookExW',nil, @SetWindowsHookExWCallback, @SetWindowsHookExWNext);
     ApiHook('USER32.DLL', 'GetKeyboardState',nil, @GetKeyboardStateCallBack, @GetKeyboardState);
     //ApiHook('kernel32.dll', 'CreateRemoteThread',nil, @CreateRemoteThreadCallback, @CreateRemoteThreadNext);
     //ApiHook('kernel32.dll','CreateProcessInternalW',nil,@HookCreateProcessInternalW,@MainCreateProcessInternalW);
     //ApiHook('Gdi32.dll', 'BitBlt',nil, @BitBltCallBack, @MainBitBlt);
     //ApiHook('ntdll.dll', 'RtlSetProcessIsCritical',nil, @RtlSetProcessIsCriticalCallBack, @MainRtlSetProcessIsCritical);

     GetModuleFileName(GetModuleHandle(Pchar(DllName)),DllPath,SizeOf(DllPath));
   end;
   DLL_PROCESS_DETACH: begin
    //ApiUnHook('advapi32.dll','CreateProcessAsUserA',nil,@HookCreateProcessAsUserA,@MainCreateProcessAsUserA);
    //ApiUnHook('advapi32.dll','CreateProcessAsUserW',nil,@HookCreateProcessAsUserW,@MainCreateProcessAsUserW);
    ApiUnHook('USER32.DLL', 'GetAsyncKeyState',nil, @GetAsyncKeyStateCallback, @GetAsyncKeyStateNext);
    ApiUnHook('USER32.DLL', 'SetWindowsHookExA',nil, @SetWindowsHookExACallback, @SetWindowsHookExANext);
    ApiUnHook('USER32.DLL', 'SetWindowsHookExW',nil, @SetWindowsHookExWCallback, @SetWindowsHookExWNext);
    ApiUnHook('USER32.DLL', 'GetKeyboardState',nil, @GetKeyboardStateCallBack, @GetKeyboardState);
   // ApiUnHook('kernel32.dll', 'CreateRemoteThread',nil, @CreateRemoteThreadCallback, @CreateRemoteThreadNext);
    //ApiUnHook('Gdi32.dll', 'BitBlt',nil, @BitBltCallBack, @MainBitBlt);
    //ApiUnHook('ntdll.dll', 'RtlSetProcessIsCritical',nil, @RtlSetProcessIsCriticalCallBack, @MainRtlSetProcessIsCritical);
    //ApiUnHook('kernel32.dll','CreateProcessInternalW',nil,@HookCreateProcessInternalW,@MainCreateProcessInternalW);
   end;
 end;
end;

//entry point DLL ada disini
//entry point mengarah ke fungsi DLL_PROCESS_ATTACH untuk memulai proses injeksi
begin
 DllProc:=@DLLEntryPoint;
 DLLEntryPoint(DLL_PROCESS_ATTACH);
end.

