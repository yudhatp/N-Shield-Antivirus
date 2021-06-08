unit ClamConfig;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ClamavUnit;

type
  TForm2 = class(TForm)
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form2: TForm2;

implementation

{$R *.dfm}
var
  isDBLoaded  : Boolean;
  Engine      : cl_engine;

procedure ScanClamAV;
var
 h : Integer;
  scanme          : String;
  ret             : integer;
  scanned         : Word;
  virname         : PAnsiChar;
  S               : String;
  InfectionCnt    : Integer;
  TotalFiles      : Integer;

      Function __ScanFile(const xfilex: String):Integer;
      begin
        Result := cl_scanfile(PChar(xfilex), @virname, scanned, engine, CL_SCAN_STDOPT);
      end;
begin
      begin
        scanme := PAnsiChar(AnsiString(Edit1.Text));
        virname := '';
        ret  := 0;
        //ret := cl_scandesc(h, @virname, scanned, engine, CL_SCAN_STDOPT);
        //ret := cl_scanfile(ScanMe, @virname, scanned, engine, CL_SCAN_RAW or CL_SCAN_ALGORITHMIC);
        ret := __ScanFile(scanme);
        if ret = (CL_CLEAN or CL_SUCCESS) then
          //S := strpas(cl_strerror(ret)) //str2pas
        else
          if ret = CL_VIRUS then //S:= AnsiString(virname);
          messagebox(0,virname, 'Test ClamAV', MB_ICONWARNING);
        Memo1.Lines.Add(Format('Scan --> %s <-- %s',[ExtractFileName(scanme),S]));
      end;
      //Label2.Caption := '[-] > Scan Complete..';
      StatusBar1.Panels[1].Text := 'Scan Complete ..';
end;

procedure loadpertama;
begin
 isDBLoaded := FALSE;
end;

//updated dari google code
procedure LoadClamAVEngine;
var
    s   : String;
    ret : Integer;
    sigs : word;
begin
  if isDBLoaded then
      //Timer1.Enabled := FALSE
  else
    begin
      Memo1.Lines.Add('Loading AV-Engine..');
      if not IsClamAVLibPresent then
        begin
          Application.MessageBox('Unable to Load ClamAV Engine','Error');
          Application.Terminate;
        end
      else
        begin
          Memo1.Lines.Add('Verifying AV-Engine..');
          ret := cl_init(CL_INIT_DEFAULT);
          if ret = CL_SUCCESS then
            begin
              Engine := cl_engine_new()^;
              if not Assigned(@Engine) then
                begin
                  Memo1.Lines.Add('Unable to create new AV-Engine');
                end
              else
                begin
                  //s := '>>MyScan Engine - ClamAV : ' +Strpas(cl_retver); //Str2Pas
                  Memo1.Lines.Add(s);
                  sigs :=0;
                  Memo1.Lines.Add('Loading Virus Signature');
                  ret := cl_load(cl_retdbdir, engine, sigs, CL_DB_OFFICIAL);
                  if ret <> CL_SUCCESS then
                    begin
                      Memo1.Lines.Add('Unable to LoadDB');
                      cl_engine_free(engine);
                    end
                  else
                    begin
                      ret :=  cl_engine_compile(engine);
                      if ret = CL_SUCCESS then
                        begin
                          lblclamsig.Caption := IntToStr(sigs);
                          Memo1.Lines.Add('Database Loaded : ('+IntToStr(sigs)+') Signatures');
                          isDBLoaded := TRUE;
                        end
                        else
                        begin
                          Memo1.Lines.Add('Database INIT Error');
                          cl_engine_free(engine);
                        end;
                    end;
                end;
            end;
        end;
    end;
end;
end.
 