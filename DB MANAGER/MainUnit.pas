unit MainUnit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, EngineDLLUnit;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Edit1: TEdit;
    Edit2: TEdit;
    Label1: TLabel;
    OpenDialog1: TOpenDialog;
    procedure Edit1Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.Edit1Click(Sender: TObject);
begin
if not OpenDialog1.execute then exit;
   Edit1.Text  := OpenDialog1.FileName;
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
enkrip(pchar(edit1.text), pchar(edit2.text),'xmnepsyy')  //lisensi 8 karakter
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
dekrip(pchar(edit1.text));
end;

end.
