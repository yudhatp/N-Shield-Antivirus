program navui;


uses
  madExcept,
  madLinkDisAsm,
  madListProcesses,
  Forms,
  ImgList,
  Classes,
  dialogs,
  Windows,
  Graphics,
  SysUtils,
  ComCtrls,
  MemoryUnit,
  MainUnit in 'MainUnit.pas' {MainForm},
  Lainnya in 'Lainnya.pas',
  SplashUnit in 'SplashUnit.pas' {Form1},
  ThreadUnit in 'ThreadUnit.pas',
  CureList in 'CureList.pas' {Form2},
  RTPForm in 'RTPForm.pas' {RTP};

{$R *.res}
{$R uac.res uac.rc}


{Add mutex for the system to avoid duplicate application at same time}
function IsAlreadyRunning : Boolean;
var
  mHandle : THandle;
  MyMutex : string;
begin
  Result := False;
  MyMutex := 'N-Shield_AntiVirus';
  mHandle := CreateMutex(nil, True, PChar(MyMutex));
  if GetLastError = ERROR_ALREADY_EXISTS then
  begin
    Result := True;
  end;
end;


begin
if IsAlreadyRunning then
  begin
    MessageBox(0, 'N-Shield AntiVirus is already running on your system!', 'Warning', MB_ICONWARNING or MB_SYSTEMMODAL or MB_OK);
    Exit;
  end;

Application.Initialize;
Application.Title := 'N-Shield AntiVirus';
Application.CreateForm(TMainForm, MainForm);
  Application.CreateForm(TForm1, Form1);
  Application.CreateForm(TRTP, RTP);
  Application.OnException := MainForm.ApplicationException;
    (* *)
    ChDir(ExtractFilePath(ParamStr(0)));
    (* *)
    MainForm.SettinganNormal;
    MainForm.BacaSettings;


    (* Run with parametrs *)
    {
    if LowerCase(ParamStr(1)) = '-fileinfo' then begin
        Application.ShowMainForm := False;
        pth := trim(ParamStr(2));
        MainForm.Hide;
        if FileExists(pth) then begin
            FileInfoForm.GetInformation(pth);
            FileInfoForm.ShowModal;
        end;
        MainForm.Close;
    end else
    if LowerCase(ParamStr(1)) = '-autorun' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acAutoRun.Execute;
        MainForm.Close;
    end else
    if LowerCase(ParamStr(1)) = '-descriptors' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acOpenDescriptors.Execute;
        MainForm.Close;
    end else
    if LowerCase(ParamStr(1)) = '-update' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acStartUpdate.Execute;
        MainForm.Close;
    end else
    if LowerCase(ParamStr(1)) = '-options' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acPreferences.Execute;
        MainForm.Close;        
    end else
    (* *)
    if LowerCase(ParamStr(1)) = '-process' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acProcessExplorer.Execute;
        MainForm.Close;
    end else
    (* *)
    if LowerCase(ParamStr(1)) = '-about' then begin
        MainForm.acAbout.Execute;
    end else
    (* *)
    if LowerCase(ParamStr(1)) = '-report' then begin
        Application.ShowMainForm := False;
        MainForm.Hide;
        MainForm.acDisplayScanReport.Execute;
        MainForm.Close;
    end else
    (* *)
    if LowerCase(ParamStr(1)) = '-memscan' then begin
        Application.ShowMainForm := False;
        MainForm.ScanFromParams := True;
        (* read fast opt *)
        for i := 1 to ParamCount do begin
            if LowerCase(ParamStr(i)) = '-ac' then MainForm.AutoClose := True;
            if LowerCase(ParamStr(i)) = '-fc' then MainForm.FastClose := True;
            (* *)
            if LowerCase(ParamStr(i)) = '-ad' then begin
                //MainForm.AutoRemove     := true;
                //MainForm.AutoQuarantine := false;
                MainForm.AutoReport     := false;
                Continue;
            end;
            (* *)
            if LowerCase(ParamStr(i)) = '-aq' then begin
                //MainForm.AutoRemove     := false;
                //MainForm.AutoQuarantine := true;
                MainForm.AutoReport     := false;
                Continue;
            end;
            (* *)
            if LowerCase(ParamStr(i)) = '-ar' then begin
                //MainForm.AutoRemove     := false;
                //MainForm.AutoQuarantine := false;
                MainForm.AutoReport     := true;
                Continue;
            end;
        end;
        (* *)
        ScanForm.Scanner := TAvScanner.Create(true);
        ScanForm.Scanner.Dirs := TStringList.Create;
        (* *)
        ScanForm.Scanner.Memscan := true;
        MainForm.GetProcessList(ScanForm.Scanner.Dirs);
        (* *)
        ScanForm.Scanner.Resume;
        MainForm.Hide;
        ScanForm.Show;
    end else
    (* Scanning by parametrs *)
    if ParamCount > 0 then begin
        MainForm.ScanFromParams := True;
        Application.ShowMainForm := False;
        (* start scanning by selectoin *)
        ScanForm.Scanner := TAvScanner.Create(true);
        ScanForm.Scanner.Dirs := TStringList.Create;
        ScanForm.Scanner.Memscan := false;
        (* *)
        for i := 1 to ParamCount do begin
            if LowerCase(ParamStr(i)) = '-ac' then MainForm.AutoClose := True;
            if LowerCase(ParamStr(i)) = '-fc' then MainForm.FastClose := True;
            (* *)
            if LowerCase(ParamStr(i)) = '-ad' then begin
                //MainForm.AutoRemove     := true;
                //MainForm.AutoQuarantine := false;
                MainForm.AutoReport     := false;
                Continue;
            end;
            (* *)
            if LowerCase(ParamStr(i)) = '-aq' then begin
                //MainForm.AutoRemove     := false;
                //MainForm.AutoQuarantine := true;
                MainForm.AutoReport     := false;
                Continue;
            end;
            (* *)
            if LowerCase(ParamStr(i)) = '-ar' then begin
                //MainForm.AutoRemove     := false;
                //MainForm.AutoQuarantine := false;
                MainForm.AutoReport     := true;
                Continue;
            end;
            (* *)
            if FileExists(Trim(ParamStr(i))) then
                ScanForm.Scanner.Dirs.Add(Trim(ParamStr(i)))
            else
                if DirectoryExists(Trim(ParamStr(i))) then
                    ScanForm.Scanner.Dirs.Add(Trim(ParamStr(i))+'\');
        end;
        (* *)
        //if MainForm.AutoRemove then begin
        //    MainForm.Options.Remove := true;
        //    MainForm.Options.ReportOnly := False;
        //    MainForm.Options.MoveToQuarantine := False;
        //end;
        (* *)
        if MainForm.AutoReport then begin
            //MainForm.Options.Remove := false;
            //MainForm.Options.ReportOnly := true;
            //MainForm.Options.MoveToQuarantine := False;
        end;
        (* *)
        //if MainForm.AutoQuarantine then begin
        //    MainForm.Options.Remove := false;
        //    MainForm.Options.ReportOnly := False;
        //    MainForm.Options.MoveToQuarantine := true;
        //end;
        (* *)
        ScanForm.Scanner.Resume;
        MainForm.Hide;
        ScanForm.Show;
    end;
    }
    (* *)
    //if Assigned(Form1) then
    //Form1.OKToClose := True;

    if LowerCase(ParamStr(0)) = '/STARTUP' then begin
        Application.ShowMainForm := False;
        //pth := trim(ParamStr(2));
        //MainForm.Hide;
        MainForm.Close;
        //if FileExists(pth) then begin
        //    FileInfoForm.GetInformation(pth);
        //    FileInfoForm.ShowModal;
        end;
    Application.Run;
end.
