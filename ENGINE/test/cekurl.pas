unit cekurl;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,wininet, StdCtrls;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    Label1: TLabel;
    lblstatus: TLabel;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}
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

procedure TForm1.Button1Click(Sender: TObject);
begin
if checkURL(edit1.Text) then
lblstatus.Caption := 'URL valid :) '
else
lblstatus.Caption := 'URL tidak valid :( '
end;

end.
 