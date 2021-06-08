{ Advanced Plugin System

  Author: Slayer616
  Description: Add plugin functionality to your Delphi applications.
  Website: http://hackhound.org
  History: First try
  Credits: steve1020 

}

unit Main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, Menus, ComCtrls, StdCtrls;

type
  TfrmMain = class(TForm)
    PopupMenu1: TPopupMenu;
    Button1: TButton;
    procedure FormCreate(Sender: TObject);
  private
    procedure PluginClick(Sender: TObject);
  public
    { Public declarations }
  end;

  type
    TPluginRec = packed record
      szName:     string;
      szVersion:  string;
      Call:       function(hWindow:pointer):boolean; stdcall;
    end;

  type
    PluginArray = array of TPluginRec;

var
  frmMain: TfrmMain;
  PluginName:     function():PChar; stdcall;
  PluginVersion:  function():PChar; stdcall;
  Plugins:        PluginArray;

implementation

{$R *.dfm}
{
Functionname: sSendFunc
Parameters: sMess:String
-This Function gives out sMess in a Messagebox
}
function sSendFunc(sMess:string):boolean; stdcall;  export;
begin
showmessage(sMess);
end;

{
Functionname: LoadPlugin
Parameters: Nothing
-This Function searches for Plugins and adds them to the Popupmenu!
}
procedure LoadPlugins();
var
  Count:    DWORD;
  NewMenu:  TMenuItem;
  WIN32:    TWin32FindData;
  hFile:    DWORD;
begin
  Count := 0;
  hFile := FindFirstFile(PChar(ExtractFilePath(ParamStr(0)) + '*.dll'), WIN32);
  if hFile <> 0 then
  begin
    repeat
      SetLength(Plugins, Count + 1);
      PluginName := GetProcAddress(LoadLibrary(WIN32.cFileName), 'PluginName');
      Plugins[Count].szName := PluginName;
      PluginVersion := GetProcAddress(LoadLibrary(WIN32.cFileName), 'PluginVersion');
      Plugins[Count].szVersion := PluginVersion;
      Plugins[Count].Call := GetProcAddress(LoadLibrary(WIN32.cFileName), 'PluginMain');
      NewMenu := TMenuItem.Create(nil);
      NewMenu.Caption := Plugins[Count].szName + ' ' + Plugins[Count].szVersion;
      NewMenu.OnClick := frmMain.PluginClick;
      NewMenu.Tag := Count;
      frmmain.PopupMenu1.Items.Add(newmenu);
      Inc(Count);
    until FindNextFile(hFile, WIN32) = FALSE;
    Windows.FindClose(hFile);
  end;
end;

{
Functionname: PluginClick
Parameters: Sender: TObject
-This Function calls the Pluginmain procedure in the Dll!
}
procedure TfrmMain.PluginClick(Sender: TObject);
begin
  TPluginRec(Plugins[TMenuItem(Sender).Tag]).Call(@sSendFunc);
end;

{
Functionname: FormCreate
Parameters: Sender: TObject
-This Function calls Loadplugins on the startup of the Form!
}
procedure TfrmMain.FormCreate(Sender: TObject);
begin
  LoadPlugins;
end;

//export sSendFunc, to share the Adress of it to the Dll!
exports
  sSendFunc;
end.
