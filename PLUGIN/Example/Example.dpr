library Example;

uses
  Windows,
  Sysutils,
  Unit1 in 'Unit1.pas' {Form1};

const
  szPluginName: PChar = 'SendMess';
  szVersion:    PChar = '0.1';
var
sForm:tForm1;

{$R *.res}
{
Functionname: PluginName
Parameters: Nothing
-This Function returns the Pluginname!
}
function PluginName():PChar; stdcall; export;
begin
  Result := szPluginName;
end;

{
Functionname: PluginVersion
Parameters: Nothing
-This Function returns the PluginVersion!
}
function PluginVersion():PChar; stdcall; export;
begin
  Result := szVersion;
end;

{
Functionname: PluginMain
Parameters: sFunc:pointer
-This Function creates a new Form and sets the Function
}
procedure PluginMain(sFunc:pointer); stdcall; export;
begin
  sSendFunc := sFunc; //here we get the Pointer for our Function
  sform := tform1.Create(nil);
  sform.Show; 
end;



exports
  PluginName,
  PluginVersion,
  PluginMain;
  
begin
end.
 