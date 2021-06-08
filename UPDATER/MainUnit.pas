unit MainUnit;

interface

uses
  Windows,SysUtils,
  ComCtrls, StdCtrls, Controls, Forms, ShellApi,ExtActns, Classes, ExtCtrls,
  wininet, dialogs;

type
  TForm1 = class(TForm)
    ProgressBar1: TProgressBar;
    Label1: TLabel;
    lblstatus: TLabel;
    Label2: TLabel;
    txtSaveTo: TEdit;
    Label3: TLabel;
    Label4: TLabel;
    txtURL: TEdit;
    lblsize: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    lblnama: TLabel;
    Label7: TLabel;
    Button1: TButton;
    Label8: TLabel;
    procedure Button1Click(Sender: TObject);
  private
    procedure URL_OnDownloadProgress(Sender: TDownLoadURL; Progress, ProgressMax: Cardinal; StatusCode: TURLDownloadStatus; StatusText: String; var Cancel: Boolean) ;
  public

  end;

var
  Form1: TForm1;

implementation


{$R *.dfm}
function RetDelete(const str : string;
                   index     : cardinal;
                   count     : cardinal = maxInt) : string;
begin
    result := str;
    Delete(result, index, count);
end;

procedure FillStrings(var str: string; fillLen: integer; addLeft: boolean; fillChar: char);
var
    s1 : string;
begin
    if fillLen > 0 then begin
        SetLength(s1, fillLen);
        system.FillChar(pointer(s1)^, fillLen, byte(fillChar));
        if addLeft then begin
            if (fillChar in ['0'..'9']) and (str <> '') and (str[1] = '-') then
               str := '-' + s1 + RetDelete(str, 1, 1)
            else str := s1 + str;
        end else str := str + s1;
    end;
end;

function IntToStrEx(value    : int64;
                    minLen   : integer = 1;
                    fillChar : char    = '0') : string; overload;
begin
    result := IntToStr(value);
    FillStrings(result, abs(minLen) - Length(result), minLen > 0, fillChar);
end;

var FDecSep : char = #0;
function DecSep : char;
var buf : array[0..1] of char;
begin
    if FDecSep = #0 then
        if GetLocaleInfo(GetThreadLocale, LOCALE_SDECIMAL, buf, 2) > 0 then
             FDecSep := buf[0]
        else FDecSep := ',';
    result := FDecSep;
end;

function SizeToStr(size: int64) : string;
begin
    if abs(size) >= 1024 then begin
        if abs(size) >= 1024 * 1024 then begin
            if abs(size) >= 1024 * 1024 * 1024 then begin
                result := IntToStrEx(abs(size div 1024 div 1024 * 100 div 1024)) + ' GB';
                Insert(DecSep, result, Length(result) - 4);
            end else begin
                result := IntToStrEx(abs(size div 1024 * 100 div 1024)) + ' MB';
                Insert(DecSep, result, Length(result) - 4);
            end;
        end else begin
            result := IntToStrEx(abs(size * 100 div 1024)) + ' KB';
            Insert(DecSep, result, Length(result) - 4);
        end;
        end else result := IntToStrEx(abs(size)) + ' Bytes';
end;

function checkURL (url: string ): boolean;
 var
  hSession, hfile, hRequest: hInternet;
  dwindex, dwcodelen: dword;
  dwcode: array [1 .. 20] of char;
  res: pchar;
begin
  if pos ('http://', lowercase (url)) = 0 then
    url := 'http://' + url;
  Result := false;
  hSession := InternetOpen (':/ InetURL 1.0', INTERNET_OPEN_TYPE_PRECONFIG, nil , nil , 0);
   if assigned (hsession) then
  begin
    hFile := InternetOpenUrl (hsession, pchar (url), nil , 0, INTERNET_FLAG_RELOAD, 0);
    dwIndex := 0;
    dwCodeLen := 10;
    HttpQueryInfo (hfile, HTTP_QUERY_STATUS_CODE, @ dwcode, dwcodeLen, dwIndex);
    res := pchar (@ dwcode);
    result := (res = '200') or (res = '302');
     if assigned (hFile) then
      InternetCloseHandle (hfile);
    InternetCloseHandle (hsession);
  end ;
end ;

function GetUrlInfo ( const dwInfoLevel: DWORD; const FileURL: string ): 
 string ;
 var
  hSession, hFile: hInternet;
  dwBuffer: Pointer;
  dwBufferLen, dwIndex: DWORD;
begin
  Result :='';
  hSession := InternetOpen ('STEROID Download',
                           INTERNET_OPEN_TYPE_PRECONFIG, nil , nil , 0);
   if Assigned (hSession) then  begin 
    hFile := InternetOpenURL (hSession, PChar (FileURL), nil , 0,
                             INTERNET_FLAG_RELOAD, 0);
    dwIndex := 0;
    dwBufferLen := 20;
    if HttpQueryInfo (hFile, dwInfoLevel, @ dwBuffer, dwBufferLen, dwIndex)
       then Result := PChar (@ dwBuffer);
     if Assigned (hFile) then InternetCloseHandle (hFile);
    InternetCloseHandle (hsession);
  end ;
 end ;

procedure Tform1.URL_OnDownloadProgress;
begin
   ProgressBar1.Max:= ProgressMax;
   ProgressBar1.Position:= Progress;
end;

procedure DoDownload;
begin
   with TDownloadURL.Create(nil) do
   try


     Form1.lblstatus.caption := 'Downloading';
     URL:=Form1.txtURL.Text;
     FileName := Form1.txtSaveTo.Text;
     OnDownloadProgress := Form1.URL_OnDownloadProgress;
     ExecuteTarget(nil);

   finally
        Free;
        Form1.lblstatus.caption := 'Finished';
   end;
end;



procedure TForm1.Button1Click(Sender: TObject);
var
sizex : string;
URLnya : string;
begin
URLnya := txturl.Text;
if txturl.Text = '' or if txtsaveto.Text = '' then
showmessage('URL tidak boleh kosong')
else
sizex := geturlinfo(HTTP_QUERY_CONTENT_LENGTH,URLnya);
delete(sizex, length(sizex), 1);
lblsize.caption := sizetostr(strtoint(sizex));
DoDownload;
end;

end.
