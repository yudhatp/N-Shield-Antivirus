program navmon;

uses
  Forms,
  Windows,
  ProcessMonitor in 'ProcessMonitor.pas',
  Unit1 in 'Unit1.pas' {Form1};

{$R *.res}
{Add mutex for the system to avoid duplicate application at same time}
function IsAlreadyRunning : Boolean;
var
  mHandle : THandle;
  MyMutex : string;
begin
  Result := False;
  MyMutex := 'N-Shield Process Monitor';
  mHandle := CreateMutex(nil, True, PChar(MyMutex));
  if GetLastError = ERROR_ALREADY_EXISTS then
  begin
    Result := True;
  end;
end;

begin
if IsAlreadyRunning then
  begin
    //MessageBox(0, 'N-Shield AntiVirus is already running on your system!', 'Warning', MB_ICONWARNING or MB_SYSTEMMODAL or MB_OK);
    Exit;
  end;
  Application.Initialize;
  Application.Title := 'N-Shield Process Monitor';
  Application.CreateForm(TForm1, Form1);
  Application.ShowMainForm := false;
  Application.Run;
end.
