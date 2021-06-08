{
=============================
N-Shield AntiVirus Engine
1 des 2013
=============================

}
library navscan;

uses
  Fastmm4,
  SysUtils,
  Classes,
  Compare,
  Strings,
  Database,
  EHeader,
  MD5,
  DBkode,
  WhiteList,
  ntech, //Force
  FileHeader,
  PE,
  BoyerMoore in 'BoyerMoore.pas',
  Heal in 'Heal.pas';

{$R *.res}

//export functions
exports
    NShield_Start_Engine, //init_engine,
    NShield_Stop_Engine, //free_engine,
    NShield_Virus_Signature,   //membaca database
    NShield_Encrypt, //pack database
    NShield_Load_Database,   //load database utama ke memory
    NShield_Get_VBD_Dir, //panggil diektori database
    NShield_Match_File,  //cocokan file
    NShield_Heal_Smellsme,
    NShield_Heal_Mumawow,
    NShield_Heal_Ramnit_B,
    NShield_Heal_Runouce,
    NShield_Heal_Annie_HTML,
    NShield_Heal_Dorifel,
    NShield_Scan_Buffer,
    Nshield_Get_VirusCount,
    NShield_Get_VirusName,
    NShield_Get_Engine_Version,
    NShield_FileToString,
    NShield_str2hex,
    NShield_Config,
    NShield_HexStrToStr,
    NShield_Hex2Dec,
    NShield_BM_SearchString,
    NShield_CheckEncrypted,
    NShield_CheckOverlay;
    //fixhtml,
    //hexafile,
    //aturnama;
    //nshieldMD5scan,
    //nshieldScanString,
    //nshieldPEinfo,
    //nshieldfilebersih,
    //hapusfile,
    //databasedate,
    //load_xpb,   //load database user ke memory
begin

end.
