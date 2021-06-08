unit HiddenProcess;


interface

uses
  Windows, Psapi, sysutils, TlHelp32;

type
  THiddenProcessManager = class(TObject)
  private
  public
    Count: integer;
    ExePathList: array of string;
    PIDList: array of string;
    PriorityList: array of string;
    ThreadList: array of string;

    HiddenCount : integer;
    HiddenExePathList : array of string;
    HiddenPIDList : array of string;
    
    constructor Create;
    Function ReturnExe (szPID : String):string;
    procedure ListHiddenProcesses;
    procedure ListProcesses;
    procedure KillProcessByPID(PID: string);
    procedure KillProcessByExePath(ExePath: string);
  end;

implementation

function IntToStr(X: integer): string;
var
  S: string;
begin
 Str(X, S);
 Result := S;
end;

function StrToInt(S: string): integer;
var
  V, X: integer;
begin
 Val(S, V, X);
 Result := V;
end;

procedure SetTokenPrivileges;
var 
  hToken1, hToken2, hToken3: THandle;
  TokenPrivileges: TTokenPrivileges;
  Version: OSVERSIONINFO;
begin
  Version.dwOSVersionInfoSize := SizeOf(OSVERSIONINFO);
  GetVersionEx(Version);
  if Version.dwPlatformId <> VER_PLATFORM_WIN32_WINDOWS then
  begin
    try
      OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES, hToken1);
      hToken2 := hToken1;
      LookupPrivilegeValue(nil, 'SeDebugPrivilege', TokenPrivileges.Privileges[0].luid);
      TokenPrivileges.PrivilegeCount := 1;
      TokenPrivileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      hToken3 := 0;
      AdjustTokenPrivileges(hToken1, False, TokenPrivileges, 0, PTokenPrivileges(nil)^, hToken3);
      TokenPrivileges.PrivilegeCount := 1;
      TokenPrivileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      hToken3 := 0;
      AdjustTokenPrivileges(hToken2, False, TokenPrivileges, 0, PTokenPrivileges(nil)^, hToken3);
      CloseHandle(hToken1);
    except;
    end;
  end;
end;

function Split(Input: string; Deliminator: string; Index: integer): string;
var
  StringLoop, StringCount: integer;
  Buffer: string;
begin
  StringCount := 0;
  for StringLoop := 1 to Length(Input) do
  begin
    if (Copy(Input, StringLoop, 1) = Deliminator) then
    begin
      Inc(StringCount);
      if StringCount = Index then
      begin
        Result := Buffer;
        Exit;
      end
      else
      begin
        Buffer := '';
      end;
    end
    else
    begin
      Buffer := Buffer + Copy(Input, StringLoop, 1);
    end;
  end;
  Result := Buffer;
end;

constructor THiddenProcessManager.Create;
begin
  inherited Create;
  SetTokenPrivileges;
end;

function THiddenProcessManager.ReturnExe(szPID : String):String;
var
  i : integer;
begin
  result := '';
  for i := 0 to Count do
  begin

    if PIDList[i]=szPID then
    begin
//      if szPid='4' then showMessage('!'+PIDList[i]+'!' + ' ' + '!'+ szPID +'!');
      result := ExePathList[i];
      Exit;
    end;

  end;

end;

procedure THiddenProcessManager.ListProcesses;
var
  Process32: TProcessEntry32;
  Module32: TModuleEntry32;
  ProcessSnapshot: THandle;
  ModuleSnapshot: THandle;
  SystemDirectory: array[0..261] of char;
begin
  Count := -1;
  GetWindowsDirectory(@SystemDirectory, 261);
  ProcessSnapshot := CreateToolHelp32SnapShot(TH32CS_SNAPALL, 0);
  Process32.dwSize := SizeOf(TProcessEntry32);
  Process32First(ProcessSnapshot, Process32);
  repeat
    Inc(Count);
    SetLength(ExePathList, Count + 1);
    SetLength(ThreadList, Count + 1);
    SetLength(PIDList, Count + 1);
    SetLength(PriorityList, Count + 1);
    ModuleSnapshot := CreateToolHelp32SnapShot(TH32CS_SNAPMODULE, Process32.th32ProcessID);
    Module32.dwSize := SizeOf(TModuleEntry32);
    Module32First(ModuleSnapshot, Module32);
    if Copy(string(Module32.szExePath), 1, 4) = '\??\' then
    begin
      ExePathList[Count] := LowerCase( Copy(string(Module32.szExePath), 5, Length(string(Module32.szExePath)) - 4) );
    end
    else if Copy(string(Module32.szExePath), 1, 11) = '\SystemRoot' then
    begin
      ExePathList[Count] := LowerCase( string(SystemDirectory) + Copy(string(Module32.szExePath), 12, Length(string(Module32.szExePath)) - 11) );
    end
    else
    begin
      ExePathList[Count] := LowerCase( string(Module32.szExePath) );
    end;
    ThreadList[Count] := IntToStr(Process32.cntThreads);
    if Process32.th32ProcessID = 0 then
    begin
      PIDList[Count] := IntToStr(GetCurrentProcessID);
    end
    else
    begin
        PIDList[Count] := IntToStr(Process32.th32ProcessID);
    end;
    PriorityList[Count] := IntToStr(Process32.pcPriClassBase);
    CloseHandle(ModuleSnapshot);
  until not (Process32Next(ProcessSnapshot, Process32));
  CloseHandle(ProcessSnapshot);
end;

procedure THiddenProcessManager.ListHiddenProcesses();
 var
   iPID: integer;
   hTmp: LongWord;
   buf: array[0..MAX_PATH+1]of char;
   szAppBrute : String;
   szPathBrute : String;
   szAppNormal : String;
begin
  ListProcesses; //list the "visible" processes so we can compare them..

  for iPID := $41EC downto 0 do
  begin

    if iPID mod 4 = 0 then
    begin

      hTmp := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, iPID);
      if hTmp <> 0 then
      begin
        szPathBrute := '';
        szAppBrute := '';
        szAppNormal := '';
        buf := '';


        GetModuleFileNameEx(hTmp, 0, @buf, MAX_PATH);
        szPathBrute := StrPas(buf);
        szAppBrute := LowerCase( ExtractFileName( szPathBrute ) );

        if szPathBrute='?' then
        begin
          szPathBrute := 'system';
          szAppBrute := 'system';
        end;

        szAppNormal := ExtractFileName( ReturnExe(IntToStr(iPID)));


          if not (szAppBrute = szAppNormal  ) then
          begin

            Inc(HiddenCount);
            SetLength(HiddenExePathList, HiddenCount + 1);
            SetLength(HiddenPIDList, HiddenCount + 1);

            if szPathBrute='?' then szPathBrute := 'system';

            HiddenExePathList[HiddenCount] := szPathBrute;
            HiddenPIDList[HiddenCount] := IntToStr(iPID);

          end;

      end;

      CloseHandle(hTmp);

    end;


  end;

end;

procedure THiddenProcessManager.KillProcessByExePath(ExePath: string);
var
  iLoop: integer;
begin
  ListProcesses;
  for iLoop := 0 to Count do
  begin
    if ExePath = ExePathList[iLoop] then
    begin
      KillProcessByPID(PIDList[iLoop]);
    end;
  end;
end;

procedure THiddenProcessManager.KillProcessByPID(PID: string);
var
  ProcessHandle: THandle;
begin
  ProcessHandle := OpenProcess(PROCESS_TERMINATE, False, StrToInt(PID));
  TerminateProcess(ProcessHandle, 0);
end;

end.
