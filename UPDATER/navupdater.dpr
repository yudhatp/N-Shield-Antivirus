program navupdater;

uses
  Windows,
  Forms,
  MainUnit in 'MainUnit.pas' {Form1};

{$R *.res}
{Add mutex for the system to avoid duplicate application at same time}
function IsAlreadyRunning : Boolean;
var
  mHandle : THandle;
  MyMutex : string;
begin
  Result := False;
  MyMutex := 'NAV Updater';
  mHandle := CreateMutex(nil, True, PChar(MyMutex));
  if GetLastError = ERROR_ALREADY_EXISTS then
  begin
    Result := True;
  end;
end;

begin
if IsAlreadyRunning then
  begin
    Exit;
  end;

  Application.Initialize;
  Application.Title := 'N-Shield AntiVirus Updater';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
