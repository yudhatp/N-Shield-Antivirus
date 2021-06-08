unit RTPForm;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, jpeg, ExtCtrls,EngineDLLUnit, NShieldCrypt;

type
  TRTP = class(TForm)
    Label1: TLabel;
    lblvirus: TLabel;
    Label2: TLabel;
    Image3: TImage;
    NshieldImage: TImage;
    btnqua: TButton;
    btnclean: TButton;
    lblfile: TLabel;
    Label4: TLabel;
    procedure btnquaClick(Sender: TObject);
    procedure btncleanClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  RTP: TRTP;

implementation

uses MainUnit;

{$R *.dfm}
Function NShieldPath: String;
begin
    Result := ExtractFilePath(ParamStr(0));
end;

Function NShieldSettings: String;
begin
    Result := NShieldPath + 'settings.ini';
end;


Function NShieldQuarantine: String;
begin
    Result := NShieldPath + 'quarantine\';
end;

procedure TRTP.btnquaClick(Sender: TObject);
var
i : integer;
filenya,namanya,alamat : string;
Kunci: TWordTriple;
begin
Kunci [0]:= 111;
Kunci [1]:= 222;
Kunci [2]:= 333;

filenya := NShieldQuarantine;
      //if not DirectoryPresent(NShieldQuarantine) then
        //  CreateDir(NShieldQuarantine);

      //if DirectoryExists(NShieldQuarantine) then begin
      namanya := ExtractFileName(lblfile.caption);
      alamat := lblfile.caption;

         if CopyFile(pchar(alamat),pChar(filenya+namanya), true) then
             begin
               FileEncrypt(filenya+namanya, filenya+namanya+'.qua',kunci );

               MainForm.lbqua.Items.Add(filenya+namanya+'.qua');
               MainForm.lbqua.Items.SaveToFile(NShieldPath+'quarantine.ini');
               DeleteFile(filenya+namanya);
               DeleteFile(alamat);
               RTP.Close;
               //messagebox(0, 'Success move file to Quarantine', ' N-Shield AntiVirus', mb_iconinformation);
              end else
              messagebox(0, 'ERROR - Cannot move file to Quarantine', ' N-Shield AntiVirus', mb_iconerror);
    End;

procedure TRTP.btncleanClick(Sender: TObject);
Var
i,j:Integer;
OffsetVX_HTML : integer;
Buf,alamat,virusnya : string;

const
VX_HTML : array [0..1] of string =
    (
     '3C68746D6C3E0A3C73637269707420747970653D22746578742F6A617661736372697074223E0A3C212D2D0A7661722061796670363D6E657720416374697665584F626A6563742827536372697074696E672E46696C6553797374656D4F626A65637427293B76617220646B3568383D6E657720416374697665584F626A',
     '3C68746D6C3E0D0A3C73637269707420747970653D22746578742F6A617661736372697074223E0D0A3C212D2D0D0A696628286E6176696761746F722E6170704E616D65213D224D6963726F736F667420496E7465726E6574204578706C6F72657222292626286E6176696761746F722E61707056657273696F6E2E696E'
    );
begin
 alamat := lblfile.caption;
 virusnya := lblvirus.Caption;

      if virusnya = 'Virus.Win32.Smellsme' then
      begin
      NShield_Heal_Smellsme(alamat);
      RTP.Close;
      //messagebox(0, 'File has been cured', ' N-Shield AntiVirus', mb_iconinformation);
      end

      //heal file HTML terinfeksi annie
      else if virusnya = 'Virus.HTML.Annie' then
      begin
      Buf := NShield_FileToString(alamat);

      for j := Low(VX_HTML) to High(VX_HTML) do
      begin
        OffsetVX_HTML := NShield_BM_SearchString(NShield_HexStrToStr(VX_HTML[j]), Buf, 1);
        if  OffsetVX_HTML > 0 then
        begin
                NShield_Heal_Annie_HTML(alamat,  OffsetVX_HTML - 1);
                RTP.Close;
                //messagebox(0, 'File has been cured', ' N-Shield AntiVirus', mb_iconinformation);
        end;
      end;
      end
      //selesai



      else if virusnya = 'Virus.Win32.Ramnit.K' then
      begin
      NShield_Heal_Ramnit_B(alamat);
      RTP.Close;
      //messagebox(0, 'File has been cured', ' N-Shield AntiVirus', mb_iconinformation);
      end

      else if virusnya = 'Virus.Win32.Ramnit.I' then
      begin
      NShield_Heal_Ramnit_B(alamat);
      RTP.Close;
      //messagebox(0, 'File has been cured', ' N-Shield AntiVirus', mb_iconinformation);
      end
      {if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Mumawow' then
      begin
      NShield_Heal_Mumawow(ListView1.Items[i].SubItems[1]);
      DeleteFile(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Cleaned';
      end;    }

      else
      begin
      DeleteFile(alamat);
      RTP.Close;
      //messagebox(0, 'File has been deleted', ' N-Shield AntiVirus', mb_iconinformation);
      end;
end;

end.
