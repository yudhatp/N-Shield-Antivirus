unit ThreadUnit;

interface
uses
 Windows, MadKernel,PSAPI,sysutils, EngineDLLUnit,
 NativeAPI;

type
  TPCardinal         = ^cardinal;

  TNtThreadInfoClass = (ThreadBasicInformation,
                        ThreadTimes,
                        ThreadPriority,
                        ThreadBasePriority,
                        ThreadAffinityMask,
                        ThreadImpersonationToken,
                        ThreadDescriptorTableEntry,
                        ThreadEnableAlignmentFaultFixup,
                        ThreadEventPair,
                        ThreadQuerySetWin32StartAddress,
                        ThreadZeroTlsCell,
                        ThreadPerformanceCount,
                        ThreadAmILastThread,
                        MaxThreadInfoClass);

var
  //FOpenedFile : clsOpenedFiles;
  OpenThread : function (access : cardinal; inheritHandle  : bool; threadID : cardinal ) : cardinal stdcall = nil;
  NtQueryInformationThread : function (threadHandle  : cardinal;
                                       infoClass     : TNtThreadInfoClass;
                                       buffer        : pointer;
                                       bufSize       : cardinal;
                                       returnSize    : TPCardinal) : cardinal stdcall = nil;

function ScanThreadMemory: boolean;

implementation

uses MainUnit;

function GetThreadStartAddress(dwThreadId: DWORD): DWORD;
var
  hThread: THANDLE;
  retaddr, len, error: DWORD;
begin
  Result := 0;
  if @OpenThread = nil then
  begin
    OpenThread := GetProcAddress(GetModuleHandle(kernel32), 'OpenThread');
    if @OpenThread = nil then
    begin
      OpenThread := pointer(1);
      Exit;
    end;
  end;
  hThread := OpenThread(Thread_QUERY_INFORMATION, FALSE, dwThreadId);
  retaddr := 0;
  len := 0;
  if @NtQueryInformationThread = nil then
    NtQueryInformationThread := GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQueryInformationThread');
  if @NtQueryInformationThread = nil then exit;
  error := NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, @retaddr, sizeof(retaddr), @len);
  if error <> 0 then retaddr := 0;
  Result := retaddr;
  CloseHandle(hThread);
end;

function EnableDebugPrivilegeNT : integer;
CONST
  ENUM_NOERR = 0;
  ENUM_NOTSUPPORTED = -1;
  ENUM_ERR_OPENPROCESSTOKEN = -2;
  ENUM_ERR_LookupPrivilegeValue = -3;
  ENUM_ERR_AdjustTokenPrivileges = -4;
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  hToken : THANDLE;
  DebugValue : TLargeInteger;
  tkp : TTokenPrivileges ;
  ReturnLength : DWORD;
  PreviousState: TTokenPrivileges;
begin
  if (OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) = false) then
    result := ENUM_ERR_OPENPROCESSTOKEN
  else
  begin
    if (LookupPrivilegeValue(nil, SE_DEBUG_NAME, DebugValue) = false) then
      result := ENUM_ERR_LookupPrivilegeValue
    else
    begin
      ReturnLength := 0;
      tkp.PrivilegeCount := 1;
      tkp.Privileges[0].Luid := DebugValue;
      tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      AdjustTokenPrivileges(hToken, false, tkp, SizeOf(TTokenPrivileges),PreviousState , ReturnLength);
      if (GetLastError <> ERROR_SUCCESS) then
        result := ENUM_ERR_AdjustTokenPrivileges
      else
        result := ENUM_NOERR;
    end;
  end;
end;

function GetThreadModule(PID : Cardinal; TID : Cardinal) : string;
var
  hThread : Cardinal;
  hProc : THandle;
  mbi : TMemoryBasicInformation;
  hMod : Cardinal;
  acModule : array [0..MAX_PATH] of Char;
  Status : NTStatus;
  error,len : cardinal;
  retaddr : dword;
begin
  EnableDebugPrivilegeNT;
  OpenThread := GetProcAddress(GetModuleHandle(kernel32), 'OpenThread');
  if @OpenThread = nil then exit;
  hThread := OpenThread(THREAD_ALL_ACCESS, False, TID);       // opens the thread (TID 1464)  to get its address
  NtQueryInformationThread := GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQueryInformationThread');
  error := NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, @retaddr, sizeof(retaddr), @len);
  hProc := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, PID);     // opens winlogon.exe (PID 660)
  VirtualQueryEx(hProc, Ptr(retaddr), mbi, sizeof(TMemoryBasicInformation));
  hMod := HMODULE(mbi.AllocationBase);
  Status := GetModuleFileNameEx(hProc, hMod, @acModule, MAX_PATH);
  Result := acModule;
end;


function ScanThreadMemory: boolean;
const
  //ngrbot dump memory
  VRS1 = '2D20796F752073747570696420637261636B65720D0A2D20796F752073747570696420637261636B65722E2E2E0D0A2D20796F752073747570696420637261636B65723F210D0A0000006E6772426F74';
  // taken from:
  // - you stupid cracker
  // - you stupid cracker...
  // - you stupid cracker?!

  //zeus bot dump memory
  VRS2 = '64656c20222573220d0a6966206578697374202225732220676f746f20640d0a406563686f206f66660d0a64656c202f4620222573220d0a687474703a2f2f7777772e676f6f676c652e636f6d2f';
    //del "%s"
    //if exist "%s" goto d
    //@echo off
    //del /F "%s"
    //http://www.google.com/

var
  AllProcess         : IProcesses;
  CurrentProcess     : IProcess;
  AllThreads         : IThreads;
  CurrentThread      : IThread;
  ThreadStartAddress : Dword;
  ThreadModuleName   : string;
  ProcessName        : string;
  ProcIdx, i, x, z   : integer;
  PID, TID           : Cardinal;
  hIdx               : integer;
  Buf                : String;
  MI                 : MEMORY_BASIC_INFORMATION;
  Addr               : pointer;
  Rd                 : DWORD;
  TmpPage            : Pointer;
  AddrStart, AddrStop: Dword;
  InfectedBy         : string;
  vxPos              : integer;
  vxpos2             : integer;
  tmpStr             : string;
  sExplorer          : string;
  test               : string;
  vxName             : string;

begin

  vxName := '';
  Result := False;
  //FOpenedFile.Refresh; //Getting All Handles
  AllProcess := Processes;

  // cek semua process
  for i := 0 to AllProcess.ItemCount-1 do
  begin

    CurrentProcess := AllProcess[i];
    ProcessName := ExtractFileName(CurrentProcess.ExeFile);
    PID:= CurrentProcess.ID;

    AllThreads := CurrentProcess.Threads;
    //Status(Format('- Checking %s; PID: %d;', [ProcessName, PID]));

    // terminate process mencurigakan yang biasa digunakan NgrBot
    if (not CurrentProcess.ServiceProcess)
       //and
       //(LowerCase(ProcessName) <> 'explorer.exe') // bukan windows explorer
       and
       (LowerCase(ProcessName) <> '[system process]') // bukan system process
       and
       (LowerCase(ProcessName) <> 'vmwaretray.exe') // bukan VMWare
       and
       (LowerCase(ProcessName) <> 'vmwareuser.exe') // bukan VMWare
       and
       (LowerCase(ProcessName) <> 'nav.exe') // bukan process sendiri
       //(LowerCase(ProcessName) <> LowerCase( ExtractFileName( application.exeName ) ) ) // bukan diri sendiri

       //and
       //(
       // (LowerCase(ProcessName) = 'svchost.exe') or
       // (LowerCase(ProcessName) = 'cmd.exe')
       //)
    then
    begin
       CurrentProcess.Terminate;
       MainForm.MemoScanReport.Lines.Add(Format('- Process %s terminated.', [ProcessName]));
    end;


    for x := 0 to AllThreads.ItemCount-1 do
    begin

      //Application.ProcessMessages;
      CurrentThread := AllThreads.Items[x];
      TID := CurrentThread.ID;

      ThreadStartAddress := GetThreadStartAddress(TID);
      ThreadModuleName := GetThreadModule(PID, TID);

      if (ThreadModuleName = '') or (not FileExists(ThreadModuleName)) then //Suspicous! ModuleName gak ketemu! no valid!
      begin

        //----------------------------------------------------------------
        Addr := nil;
        ZeroMemory(@MI, sizeof(MI));
        // dapatkan range untuk current process
        while VirtualQueryEx(CurrentProcess.Handle.Handle, Addr, MI, SizeOf(MI)) > 0 do
        begin

           if ((MI.AllocationProtect or {>>> PAGE_EXECUTE_READWRITE} PAGE_READWRITE or PAGE_EXECUTE) <> 0) and (MI.State = MEM_COMMIT) Then
           begin
             AddrStart := Cardinal(mi.BaseAddress);
             AddrStop  := Cardinal(mi.BaseAddress) + mi.RegionSize;

             if (AddrStart <= ThreadStartAddress) and (AddrStop >= ThreadStartAddress) then
             begin
               TmpPage := VirtualAlloc(nil, MI.RegionSize, MEM_COMMIT, PAGE_READWRITE);
               if TmpPage <> nil Then
               begin
                 SetLength(Buf, MI.RegionSize);
                 if ReadProcessMemory(CurrentProcess.Handle.Handle, MI.BaseAddress, Pointer(Buf), MI.RegionSize, rd) and (rd = MI.RegionSize) then
                 begin

                  //if FParamDumpMemory then //Jika parameter /DUMP maka... dumping ke file
                   //  StringToFile(Buf, ProcessName + '_detected_' + IntToHex(Cardinal(MI.BaseAddress), 8));

                   tmpStr := 'VRS1';

                   vxPos := NShield_BM_SearchString(NShield_HexStrToStr(VRS1), Buf, 1);
                   vxpos2 :=  NShield_BM_SearchString(NShield_HexStrToStr(VRS2), Buf, 1);

                   if (vxPos > 0) or (vxpos2 > 0) then

                   begin


                     //MainForm.MemoScanReport.Lines.Add(Format('- Process: %s; Thread infected: ID = %d; Start Address: $%x;', [ProcessName, TID, ThreadStartAddress]));
                     MainForm.MemoScanReport.Lines.Add(Format('- Infected Process terminated - %s ', [ProcessName]));


                     //Terminating thread virus!!!

                     if CurrentThread.IsStillRunning then  Result := CurrentThread.Terminate;

                     //if not Result then Result := True;

                     if Result then
                       MainForm.MemoScanReport.Lines.Add(Format('- Infected Thread %d terminated.', [TID]))
                     else
                       MainForm.MemoScanReport.Lines.Add(Format('- Infected Thread %d invalid. Error when terminating.', [TID]));

                   end;
                 end; //else Status('UNREADABLE PAGE: '+ IntToHex(AddrStart, 8)); //UNREADABLE PAGE
                 VirtualFree(TmpPage, 0, MEM_RELEASE);
               end;
             end;
           end;
           Addr := pointer(DWORD(MI.BaseAddress) + MI.RegionSize);
        end;
        //----------------------------------------------------------------
      end;

    end;

                //if ScanFile(ObjectName, InfectedBy) then
                //begin
                  //Status('- Module infected: '+ ObjectName);
                  {
                  SetFileAttributes(PChar(ObjectName), FILE_ATTRIBUTE_NORMAL);
                  if DeleteFile(ObjectName) then
                    Status('- Module deleted: ' + ObjectName)
                  else
                    Status('- Module cannot be deleted: ' + ObjectName);
                  }
                  //FFileFound.Add(ObjectName);
                //end;
                //else
                  //Status('File not infected: ' + ObjectName);
                //------------------------------------------------------------
              //end;
          //end;
        //end;
      //end;


  end;

end;

end.
