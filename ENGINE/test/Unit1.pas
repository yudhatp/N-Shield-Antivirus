unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Wumanber;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  value:AnsiString;
  Matcher: TMatchWU;
  i, infoIndex:Integer;

implementation

{$R *.dfm}
function FileToAnsiString(sPath:string; var bFile:AnsiString):Boolean;
var
hFile:  THandle;
dSize:  DWORD;
dRead:  DWORD;
begin
 Result := FALSE;
 hFile := CreateFile(PChar(sPath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
 if hFile <> 0 then
 begin
  dSize := GetFileSize(hFile, nil);
  SetFilePointer(hFile, 0, nil, FILE_BEGIN);
  SetLength(bFile, dSize);
  if ReadFile(hFile, bFile[1], dSize, dRead, nil) then
   Result := TRUE;
  CloseHandle(hFile);
 end;
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
FileToAnsiString(paramstr(0), value);
  //codesite.SendMemoryAsHex('value', @value[1], length(value));
  Matcher := TMatchWU.Create;
  try
    Matcher.AddPattern('546869732070726F', 1);
    Matcher.AddPattern('504500004C010A00', 2);
    Matcher.InitHash;
    i := Matcher.Search(@value[1], length(value), infoIndex);
    showmessage('%x : %d', [i, infoIndex]);
    //codesite.Send('%x : %d', [i, infoIndex]);
  finally
    Matcher.Free;
end;

end.
