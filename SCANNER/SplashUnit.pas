unit SplashUnit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, jpeg, ExtCtrls, MMSystem;

type
  TForm1 = class(TForm)
    Panel1: TPanel;
    imgLogo: TImage;
    Image3: TImage;
    Label2: TLabel;
    Label3: TLabel;
    Label1: TLabel;
    Label4: TLabel;
    CloseTimer: TTimer;
    procedure CloseTimerTimer(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }

  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.CloseTimerTimer(Sender: TObject);
begin
form1.Close;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
//SndPlaySound(PChar(ExtractFilePath(Application.ExeName) + 'sound.wav'), SND_FILENAME);
end;

end.
