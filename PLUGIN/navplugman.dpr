program navplugman;

uses
  Forms,
  Main in '..\..\..\..\..\Delphi Source Code\Advanced Plugin System\Main.pas' {frmMain};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
