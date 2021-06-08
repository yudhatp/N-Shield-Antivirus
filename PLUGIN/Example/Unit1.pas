unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls;

type
  TForm1 = class(TForm)
    btn1: TButton;
    edt1: TEdit;
    procedure btn1Click(Sender: TObject);

  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  sSendFunc: function(sSendStr:string):Boolean; stdcall;
implementation

{$R *.dfm}
{
Functionname: btn1Click
Parameters: Sender: TObject
-This Function uses SendFunc to send a Message to the Host
}
procedure TForm1.btn1Click(Sender: TObject);
begin
sSendfunc(edt1.Text);
end;

end.
 