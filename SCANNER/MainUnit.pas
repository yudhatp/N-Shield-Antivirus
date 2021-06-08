{N-Shield AntiVirus - 2014 Build 1
Yudha Tri Putra
}

unit MainUnit;

interface

uses
  {EngineDLLUnit untuk berhubungan dengan file *.dll
  MemoryUnit untuk memproses file dimemory dan unhook function
  NShieldCore untuk engine hooking 32 bit
  RegistryUnit untuk membantu proses akses ke registry
  SentinelUnit untuk mendeteksi perubahan pada file dan system
  NShieldCrypt untuk meng-enkrip dan dekrip fle karantina
  ExtActns untuk download
  NewPE untuk heal}

  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ComCtrls, ExtCtrls, ImgList, ToolWin, Menus, ActnList,
  StdStyleActnCtrls, ActnMan, StdCtrls, TLHelp32, Psapi, IniFiles, ShellApi,
  AppEvnts, EngineDLLUnit, MemoryUnit, CommCtrl, VirtualTrees,
  Buttons, Spin,FileCtrl,ShlObj, jpeg, NShieldCore,Lainnya,
  registry, RegistryUnit, XPStyleActnCtrls, HiddenProcess, ThreadUnit,
  SentinelUnit, NShieldCrypt, wininet, ExtActns, CureList, RTPForm,
  NewPE,ExceptionUnit;

const
    bloglink = 'http://n-shield-labs.blogspot.com/'; //updatelink


type

    TFileCounter = class(TThread)
    private
    protected
        procedure Execute; override;
        procedure GetFileCount(Dir: String);
    public
        Filter  : String;
        Dirs    : TStringList;
        Scanner : Pointer;
        function ExtensiScan(FileName: String): boolean;
    end;
//==============================================================================
TProcessList = class(TThread)
  private
  protected
  public
    list : TStringList;
    Procedure DeleteDoobleEntry(List: TStrings);
    procedure GetProcessList(List: Tstrings);
end;

TAvScanner = class(TThread)
    private
        procedure PindaiFolder(Dir: String);
        procedure ScanRegistryRun;
    protected
        procedure Execute; override;
    public
        ENGINE       : my_engine;
        FileName     : String;
        FileProgress : String;
        UnArchName   : String;
        Dirs         : TStringList;
        ScanStopped  : boolean;
        LastCount    : integer;
        FilesCount   : integer;
        Delim        : integer;
        SetProgress  : boolean;
        //NeedReboot   : boolean;
        Scanned  , FullScanned,
        Infected , Skipped: integer;
        DirCount     : integer;
        FullSize     : int64;
        Line         : String;
        //Color        : TColor;
        //Bold         : boolean;
        Memscan      : boolean;
        Filter       : String;

        Procedure Hentikan;
        Procedure HitungFileScan;
        Procedure SelesaiScan;
        procedure AturProgramBerjalan;
        procedure AturProgramBerakhir;
        Procedure AdaKesalahan;
        procedure AturProsesFile(FP: String);
        procedure PerbaruiProses;
        function ExtensiScan(FileName: String): boolean;

  end;

  TVirRecord = record
      virname: string;
      path: string;
      deleted: boolean;
  end;
//==============================================================================

type

  TOptions = Record
      // General
      RunStartup            : Boolean;
      SelfDefense           : Boolean;
      SelfCheck             : Boolean;
      AutoSaveReport        : Boolean;
      AutoUnHidden          : Boolean;

      //scanner
      ScanInSubDirectories  : Boolean;
      Whitelist             : Boolean;
      OptimizeScan          : Boolean;
      ScanArchives          : Boolean;
      SmartScan             : Boolean;
      ScanHiddenProc        : Boolean;
      ScanMem               : Boolean;
      ScanReg               : Boolean;
      ScanHidden            : Boolean;
      UseUserDataBases      : Boolean;
      Kill                  : Boolean;
      LastScanned           : string;
      ScanEncrypted         : Boolean;

      //rtp
      RTP                   : Boolean;
      RegShield             : Boolean;
      AntiKill              : Boolean;
      AntiKeylogger         : Boolean;

      // Filter
      FilterString         : String;
      FileSizeLimit        : String;
      ArchiveLimit         : Integer;

      //updater
      UpdateDate           : string;
      AutoUpdate           : boolean;
      //lainnya
      ScanPriority         : integer;
  end;

  TMainForm = class(TForm)
    FolderImages: TImageList;
    PnlMain: TPanel;
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    lblenginever: TLabel;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    SettingsPage: TPageControl;
    GeneralTab: TTabSheet;
    UpdateTab: TTabSheet;
    btnSave: TButton;
    SaveDialog: TSaveDialog;
    Image3: TImage;
    NshieldImage: TImage;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    lbldbupdate: TLabel;
    imgrtpon: TImage;
    Label11: TLabel;
    lblrtpstatus: TLabel;
    chkscandir: TCheckBox;
    chkoptimizescan: TCheckBox;
    chkscanarch: TCheckBox;
    chkantikyelogger: TCheckBox;
    chkRegShield: TCheckBox;
    chkRunAtStartup: TCheckBox;
    PageControl2: TPageControl;
    TabSheet5: TTabSheet;
    TabSheet6: TTabSheet;
    Label1: TLabel;
    Label13: TLabel;
    FolderTreeView: TVirtualStringTree;
    BtnRefresh: TButton;
    BtnScan: TButton;
    lblfilescanned: TLabel;
    lblfilescanning: TLabel;
    btnpausescan: TButton;
    btnstopscan: TButton;
    chkSmartScan: TCheckBox;
    chkkill: TCheckBox;
    Label9: TLabel;
    Label15: TLabel;
    chkScanMem: TCheckBox;
    chkScanReg: TCheckBox;
    chkHiddenProc: TCheckBox;
    ChkScanHidden: TCheckBox;
    chkselfdefense: TCheckBox;
    chkselfcheck: TCheckBox;
    chkautoreport: TCheckBox;
    TabSheet8: TTabSheet;
    Label7: TLabel;
    Label8: TLabel;
    Label19: TLabel;
    RTPtext: TEdit;
    Label20: TLabel;
    Label21: TLabel;
    lblviruscount: TLabel;
    LVRTP: TListView;
    Label22: TLabel;
    Timer1: TTimer;
    SaveDialog1: TSaveDialog;
    Label5: TLabel;
    lblsigcount: TLabel;
    TrayPopupMenu: TPopupMenu;
    LogoffPopupMenu: TMenuItem;
    ExitPopupMenu: TMenuItem;
    Label6: TLabel;
    Label23: TLabel;
    TxtTemp: TEdit;
    TxtReport: TEdit;
    btnbrowsereport: TSpeedButton;
    btnBrowseDB: TSpeedButton;
    TxtDatabase: TEdit;
    txtFile: TEdit;
    Label16: TLabel;
    btnscansingle: TButton;
    OpenFileScan: TOpenDialog;
    ListBox1: TListBox;
    chkWhiteList: TCheckBox;
    BtnFilterRemove: TSpeedButton;
    BtnFilterAdd: TSpeedButton;
    ListFilter: TListBox;
    LblFilter: TLabel;
    btnArchSize: TSpinEdit;
    LblArchSize: TLabel;
    LblFileSize: TLabel;
    btnFileSize: TSpinEdit;
    MemoScanReport: TMemo;
    BtnClearAll: TButton;
    BtnSaveReport: TButton;
    chkcekupdate: TCheckBox;
    chkSilentUpdate: TCheckBox;
    N1: TMenuItem;
    MenuSettings1: TMenuItem;
    MnuUpdate1: TMenuItem;
    N2: TMenuItem;
    Label17: TLabel;
    CheckBox1: TCheckBox;
    CheckBox2: TCheckBox;
    CheckBox3: TCheckBox;
    CheckBox4: TCheckBox;
    CheckBox5: TCheckBox;
    CheckBox6: TCheckBox;
    CheckBox7: TCheckBox;
    CheckBox8: TCheckBox;
    CheckBox9: TCheckBox;
    Memo2: TMemo;
    chkautounhide: TCheckBox;
    Label18: TLabel;
    Label25: TLabel;
    Label26: TLabel;
    Label27: TLabel;
    Label28: TLabel;
    TabSheet7: TTabSheet;
    TabSheet9: TTabSheet;
    LBQUA: TListBox;
    Label29: TLabel;
    lbllquacount: TLabel;
    btnrestorequa: TButton;
    btndelqua: TButton;
    chkRTP: TCheckBox;
    txtDriveRTP: TEdit;
    Label24: TLabel;
    Label30: TLabel;
    lbltime: TLabel;
    lblstarttime: TLabel;
    Label32: TLabel;
    Label12: TLabel;
    imgrtpoff: TImage;
    Label31: TLabel;
    lbllastscanned: TLabel;
    Label34: TLabel;
    TabSheet10: TTabSheet;
    lvhiddenfiles: TListView;
    btnselallhdden: TButton;
    BtnUnhide: TButton;
    ListView1: TListView;
    btnselallvirus: TButton;
    btnDelete: TButton;
    btnquarantine: TButton;
    chkselectall: TCheckBox;
    Image1: TImage;
    lblstatus: TLabel;
    imgupdate: TImage;
    Image2: TImage;
    Image4: TImage;
    Image5: TImage;
    Image6: TImage;
    chkpriority: TComboBox;
    lblpriority: TLabel;
    chkloaddbcore: TCheckBox;
    Image7: TImage;
    Cancel1: TMenuItem;
    ChkAdvHeur: TCheckBox;
    txtFilterSize: TEdit;
    Label33: TLabel;
    Label36: TLabel;
    lblhiddenfile: TLabel;
    lblwarning: TLabel;
    Label38: TLabel;
    TabSheet11: TTabSheet;
    Label14: TLabel;
    Label10: TLabel;
    btnwebsite: TButton;
    btnHelp: TButton;
    Memo1: TMemo;
    Label35: TLabel;
    imgfb: TImage;
    lbldownload: TLabel;
    ProgressBar1: TProgressBar;
    Label37: TLabel;
    btndownload: TButton;
    Label39: TLabel;
    Label40: TLabel;
    lblsize: TLabel;
    TabSheet12: TTabSheet;
    lvwarning: TListView;
    chkdrive_pro: TCheckBox;
    DrivePro: TTimer;
    Label41: TLabel;
    btncurelist: TButton;
    Label43: TLabel;
    Label44: TLabel;
    lblmemusage: TLabel;
    TimerMemUsage: TTimer;
    Label42: TLabel;
    Label45: TLabel;
    btnQuickScan: TButton;
    Label46: TLabel;

    procedure ApplicationException(Sender: TObject; E: Exception);

    function KillProcess(ProcCapt: String): boolean;
    //procedure GetProcessList(List: Tstrings);

    Procedure BacaSettings;
    Procedure BuatSettinganNormal;
    Procedure BukaSettingan;
    Procedure SimpanSettingan;
    Procedure SettinganNormal;


    procedure FormCreate(Sender: TObject);

    
    procedure FolderTreeViewGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType;
      var CellText: WideString);
    procedure FolderTreeViewExpanding(Sender: TBaseVirtualTree;
      Node: PVirtualNode; var Allowed: Boolean);
    procedure FolderTreeViewGetImageIndex(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: Integer);
    procedure FolderTreeViewFreeNode(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure FolderTreeViewCompareNodes(Sender: TBaseVirtualTree; Node1,
      Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
    procedure FolderTreeViewCollapsing(Sender: TBaseVirtualTree;
      Node: PVirtualNode; var Allowed: Boolean);
    procedure FolderTreeViewResize(Sender: TObject);

    procedure FolderTreeViewDrawText(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      const Text: WideString; const CellRect: TRect;
      var DefaultDraw: Boolean);
    procedure FolderTreeViewMouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Integer);

    procedure BtnScanClick(Sender: TObject);
    procedure BtnRefreshClick(Sender: TObject);
    procedure BtnFilterAddClick(Sender: TObject);
    procedure BtnFilterRemoveClick(Sender: TObject);
 
    procedure btnBrowseDBClick(Sender: TObject);
    procedure btnbrowsereportClick(Sender: TObject);
    
    procedure btnSaveClick(Sender: TObject);
    procedure btntrayClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure btnpausescanClick(Sender: TObject);
    procedure BtnSaveReportClick(Sender: TObject);
    procedure btnstopscanClick(Sender: TObject);
    procedure btnwebsiteClick(Sender: TObject);
    procedure ExitPopupMenuClick(Sender: TObject);
    procedure btnDeleteClick(Sender: TObject);
    procedure btnscansingleClick(Sender: TObject);
    procedure txtFileClick(Sender: TObject);
    procedure BtnClearAllClick(Sender: TObject);
    procedure LogoffPopupMenuClick(Sender: TObject);
    procedure btnselectallClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure MenuSettings1Click(Sender: TObject);
    procedure MnuUpdate1Click(Sender: TObject);
    procedure BtnUnhideClick(Sender: TObject);
    procedure btnselallvirusClick(Sender: TObject);
    procedure btnselallhddenClick(Sender: TObject);
    procedure btnHelpClick(Sender: TObject);
    procedure btnquarantineClick(Sender: TObject);
    procedure TabSheet8Show(Sender: TObject);
    procedure btnrestorequaClick(Sender: TObject);
    procedure btndelquaClick(Sender: TObject);
    procedure Label35Click(Sender: TObject);
    procedure btndownloadClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure DriveProTimer(Sender: TObject);
    procedure btncurelistClick(Sender: TObject);
    procedure PageControl1Changing(Sender: TObject;
      var AllowChange: Boolean);
    procedure TimerMemUsageTimer(Sender: TObject);
    procedure imgfbClick(Sender: TObject);
    procedure btnQuickScanClick(Sender: TObject);
    
  private
    { Private declarations }
    procedure WMEndSession ( var Msg: TWMEndSession); message WM_ENDSESSION;
    procedure AppMessage(var Msg: TMsg; var Handled: boolean);
    procedure URL_OnDownloadProgress(Sender: TDownLoadURL; Progress, ProgressMax: Cardinal; StatusCode: TURLDownloadStatus; StatusText: String; var Cancel: Boolean) ;
  public
      Options: TOptions;
      VirusList: array of TVirRecord;
      Scanner        : TAvScanner;
      processlistthread : TProcessList;

      //scan single file
      engine2 : my_engine;
      LastCount2   : integer;
      procedure WndProc(var Msg: TMessage);
      procedure Protection_ON;
      procedure Protection_OFF;
      function DiskInDrive(const Drive: char): Boolean;
      function DeteksiAutorun(VirList: TStrings): boolean;
      function ScanPatternAtOffset(const FileName : string;
      const Pattern : ansistring; const PatternSize : Integer; const Offset : Integer): boolean;
  end;

  PVSTPath = ^TVSTPath;
  TVSTPath = record
      PathName : string;
      Path     : string;
      img      : integer;
      Hiden    : boolean;
      System   : boolean;
  end; 

var
  MainForm: TMainForm;
  (* *)
  DelphiReg: TRegistry;
  folderpindai : TStringList;
  listkarantina : TStringlist;
  SysImageList: TImageList;
  CloseTick: integer = 10;
  pw_x, pw_y: integer;
  Dllname:string='navhook.dll';  //engine untuk anti keylogger
  F: THandle;
  PIDx,Cnt: DWORD;
  FWindowHandle: HWND; //untuk systray
  IconData: TNOTIFYICONDATA; //untuk systray
  MyMsg: Cardinal;
  DriveList, sDrives: TStringList;
  //updatedate_default := DateToStr(Now);

    //self defense
    procedure StartGuard(pid: DWORD); stdcall; external 'navguard.dll';
    procedure EndGuard; stdcall; external 'navguard.dll';
    procedure OpenAlert(virusname:string; filename: string);


implementation


//Slotname tersebut diperlukan untuk berkomunikasi dengan DLL core yang di-inject
//dengan menggunakan mailslot
const
Slotname = 'nshieldIPC';
slotRTP = 'nshieldRTP';

//membuat type untuk proses IPC dengan mailslot
Type
  TApiMsg = record
    Pid :Dword;
    Apicall : array[0..89] of char;
  end;

var
Slot : Thandle;
Msg:TapiMsg;

procedure GetHiddenProcessList;
  var
    i      : integer;
    HPM : THiddenProcessManager;
    szPID : String;
    hTmp: LongWord;
    buf: array[0..MAX_PATH+1]of char;
    FileName : PChar;
    a : TListItem;
  begin
    //result := false;
    HPM := THiddenProcessManager.Create;
    try
      HPM.ListHiddenProcesses;
      for i := 1 to HPM.HiddenCount do // 0 to Count apa 1 to count??????
      begin
        szPID := HPM.HiddenPIDList[i];

        //jika PID bukan milik system [PID=4] maka
        if (szPID <> intToStr(4) ) then  //if (szPID <> ''
        begin
          //Convert PID to FileName (using PSAPI)
          hTmp := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, StrToInt(szPID));
          if hTmp <> 0 then
          begin
            GetModuleFileNameEx(hTmp, 0, @buf, MAX_PATH);
            FileName := buf;

            //jika file benar ada ( untuk menghindari kesalahan di windows 7 dan 8 ) maka
            if FileExists(filename) then//if (((FileName <> '?') or (FileName <> '') or (FileName <> 'E'))) then
            begin
              a := MainForm.listview1.Items.Add;
                        a.caption := 'Hidden Process';
                        a.SubItems.Add('Unknown Malware');
                        a.SubItems.add(filename);
              //List.Add(FileName);
              //if not result then result := true;
            end;
            CloseHandle(hTmp);
          end;
        end;
      end;
    finally
      HPM.Free;
    end;
  end;


//mendapatkan nama komputer
function ComputerName():String;
var
  ComputerName: Array [0 .. 256] of char;
  Size: DWORD;
begin
  Size := 256;
  GetComputerName(ComputerName, Size);
  Result := ComputerName;
end;

//deteksi memory usage yg digunakan saat ini
function CurrentMemoryUsage: Cardinal;
 var
   pmc: TProcessMemoryCounters;
 begin
   pmc.cb := SizeOf(pmc) ;
   if GetProcessMemoryInfo(GetCurrentProcess, @pmc, SizeOf(pmc)) then
     Result := pmc.WorkingSetSize
   else
     RaiseLastOSError;
 end;

//fungsi scan root drive
function ScanDrives(VirList: TStrings): String;
var
 Bufer      : array[0..1024] of char;
 RealLen, i : integer;
 S          : string;
begin
 VirList.Clear;
 RealLen := GetLogicalDriveStrings(SizeOf(Bufer),Bufer);
 i := 0; S := '';
 while i < RealLen do begin
  if Bufer[i] <> #0 then begin
   S := S + Bufer[i];
   inc(i);
  end else begin
   inc(i);
   if (GetDriveType(PChar(S)) = 2) or (GetDriveType(PChar(S)) = 3) then
   begin
     if S <> 'A:\' then VirList.Add(S);
   end;
   S := '';
  end;
 end;
end;

//scan mutex [smart scan]
function ScanMutex: boolean;

  function IsMutexExist(MutexName: PChar): boolean;
  var handle : THandle;
  begin
    Result := False;
    handle := CreateMutex(nil, true, MutexName);
    if GetLastError = ERROR_ALREADY_EXISTS then
      Result := True
    else
      if handle <> 0 then CloseHandle(handle);
  end;

const
  vxMutex : array[0..41] of PChar =
  (
   's5rBKCUVfOF8JLVi',//ngrbot   1
   'bcd8f464-Mutex', //ngrbot   2
   'f4448e25-Mutex',//ngrbot  3
   't2f-Mutex', //ngrbot     4
   '894133bf-Mutex',//ngrbot 5
   'beta100-Mutex', //ngrbot 6
   'e621ca05-Mutex',//ngrbot   7
   'xXxXxXXxXxxxxx02',//ngrbot 8
   'f5399233-Mutex',//ngrbot  9
   'faebec4a-Mutex', //ngrbot 10
   'b845ef76-Mutex',//ngrbot   11
   'IrcPeru-Mutex',//ngrbot    12
   'e26f5077-Mutex', //ngrbot  13
   '25cbfc4f-Mutex', //ngrbot  14
   '470a1245-Mutex', //ngrbot  15
   'zaber30',   //ngrbot     16
   'e621ca05Mutex', //ngrbot   17
   'e621ca05_0', //ngrbot    18
   'xXxXxXXxXxxxxx03',//ngrbot  19
   'bfbd401b-Mutex',//ngrbot  20
   'fuckareyoulookin',  //ngrbot  21
   'FvLQ49IlоIyLjj6m', //ngrbot  22
   '-312a36d2Mutex', //ngrbot 23
   '-6b00a497Mutex',   //ngrbot  24
   'SVCHOST_MUTEX_OBJECT_RELEASED_thisittotalyfuckingshit',  //ngrbot  25
   'FvLQ49IlџЇyLjj6m', //ngrbot  26
   '-48aa4276Mutex', //zbot  27
   'FvLQ49Il”IyLjj6m', //zbot  28
   'SVCHOST_MUTEX_OBJECT_RELEASED_maynadoz', //ngrbot 29
   '-1760f7dfMutex', //ngrbot 30
   'SVCHOST_MUTEX_OBJECT_RELEASED_thisittotalyfuckingshitblackk', //ngrbot 31
  '{53BA1BAE-5B58-16B4-E84C-B06DD810937F}',  //zbot 32
	'{BB460779-478F-FE48-E04F-B06DD013937F}', //zbot 33
	'{636F5B81-1B77-2661-9A3B-4CACAA676FBE}', //zbot 34
  '{0E653AA1-7A57-4B6B-9A3B-4CACAA676FBE}', //zbot 35
	'{0E653AA0-7A56-4B6B-9A3B-4CACAA676FBE}', //zbot 36
	'{B5696DB2-2D44-F067-9A3B-4CACAA676FBE}', //zbot 37
  '{ED1F9131-D1C7-A811-AC4C-B06D9C10937F}', //zbot 38
  '{6F838CB4-CC42-2A8D-9A3B-4CACAA676FBE}', //zbot 39
  '{6F838CB3-CC45-2A8D-9A3B-4CACAA676FBE}', //zbot 40
  '{2806BF61-FF97-6D08-B44C-B06D8410937F}', //zbot 41
  '{52F6A807-FDD6-8EB5-8806-4A87A132F3D6}' //zbot 42
  );


var
  i1 : Integer;
begin
  Result := False;  //set false dulu

  for i1 := Low(vxMutex) to High(vxMutex) do
    if IsMutexExist(vxMutex[i1]) then
    begin
      Result := True;

      //messagebox(0, vxMutex[i1], 'N-Shield AntiVirus :: Smart Detection', MB_ICONWARNING);
      if MessageDlg('N-Shield AntiVirus detect virus who injected process, do you want to perform infected process removal?', mtConfirmation, [mbYes, mbNo], 0) = IDYes then
      ScanThreadMemory;
      Break;
      end else
      Break;
    //end;
end;

//fungsi untuk membuat mailslot dengan nama yang sudah ditentukan sebelumnya
function MailSlotCreate( var MailSlot: THandle): Boolean;
var
  MailSlotName: string;
begin
  MailSlotName := ('\\.\mailslot\' +Slotname);    //slotname
  MailSlot := CreateMailSlot(pchar(MailSlotName), 0, MAILSLOT_WAIT_FOREVER, nil);
  Result := (MailSlot <> INVALID_HANDLE_VALUE);
end;

//fungsi untuk membaca mailslot
function MailSlotRead(MailSlot: THandle; var Msg: TApiMsg): Boolean;
var
  BytesRead, Size: DWord;
  TmpMsg: TApiMsg;
  i: Integer;
begin
  Result := (GetMailSlotInfo(MailSlot, nil, Size, nil, nil)) and
    (Size <> MAILSLOT_NO_MESSAGE) and
    (ReadFile(MailSlot, Msg, SizeOf(Msg), BytesRead, nil)) and
    (BytesRead = SizeOf(Msg));
  for i := 1 to 3 do
  begin
    if not ((GetMailSlotInfo(MailSlot, nil, Size, nil, nil)) and
    (Size <> MAILSLOT_NO_MESSAGE) and
    (ReadFile(MailSlot, TmpMsg, SizeOf(Msg), BytesRead, nil)) and
    (BytesRead = SizeOf(TmpMsg))) then Break;
  end;
end;

//fungsi untuk mendapatkan path dari suatu proses berdasarkan PID nya
function GetPathFromPID(const PID: cardinal): string;
var
  hProcess: THandle;
  path: array[0..MAX_PATH - 1] of char;
begin
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, false, PID);
  if hProcess <> 0 then
    try
      if GetModuleFileNameEx(hProcess, 0, path, MAX_PATH) = 0 then
        RaiseLastOSError;
      result := path;
    finally
      CloseHandle(hProcess)
    end
  else
    RaiseLastOSError;
end;


procedure Status(AStatus : string);
begin
  Application.ProcessMessages;
    with MainForm.MemoScanReport do
    begin
        Lines.Add(AStatus);
    end;
end;

//fungsi untuk cek URL
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

//========================================================================
//fungsi untuk mendapatkan folder khusus (ex : folder user, folder startup
function SpecialFolder(Folder: Integer): String;
var
    SFolder : pItemIDList;
    SpecialPath : Array[0..MAX_PATH] Of Char;
    Handle:THandle;
begin
    SHGetSpecialFolderLocation(Handle, Folder, SFolder);
    SHGetPathFromIDList(SFolder, SpecialPath);
    Result := StrPas(SpecialPath);
end;

function GetSmallIconIndex(const AFile: string; Attrs: DWORD): integer;
var
    SFI: TSHFileInfo;
    //icon: ticon;
begin
    SHGetFileInfo(PChar(AFile), Attrs, SFI, SizeOf(TSHFileInfo),
    SHGFI_ICON or SHGFI_SMALLICON or SHGFI_SYSICONINDEX);
    Result := SFI.iIcon;
end;

//fungsi untuk mendapatkan path temporary
function NShieldGetTempDir: string;
var
	  buf: packed array [0..4095] of Char;
begin
  	GetTempPath(4096,buf);
	  Result := StrPas(buf);
  	Result := buf;
    Result := Result+'\';
end;

//fungsi untuk mendapatkan path system32
function NShieldGetSysDir: string;
var
  	buf: packed array [0..4095] of Char;
begin
	  GetWindowsDirectory(buf,4096);
  	Result:=StrPas(buf);
	  Result:=buf+'\system32\';
end;

//fungsi untuk mendapatkan path windows
function NShieldGetWinDir: string;
var
  	buf: packed array [0..4095] of Char;
begin
	  GetWindowsDirectory(buf,4096);
  	Result:=StrPas(buf)+'\';
end;
(* *)
Function NShieldPath: String;
begin
    Result := ExtractFilePath(ParamStr(0));
end;

Function NShieldBug: String;
begin
    Result := NShieldPath + 'log\';
end;

Function NShieldSettings: String;
begin
    Result := NShieldPath + 'settings.ini';
end;


Function NShieldQuarantine: String;
begin
    Result := NShieldPath + 'quarantine\';
end;

Function NShieldTemp: String;
begin
    Result := NShieldPath + 'database\temp\';
end;

Function NShieldReport: String;
begin
    Result := NShieldPath + 'log\Scan_Report.log';
end;

Function NShieldDatabase: String;
begin
    Result := NShieldPath + 'database\';
end;

Function NShieldDatabase_Update: String;
begin
    Result := NShieldPath + 'database\update.vdb';
end;

procedure baca_file_karantina;
begin
listkarantina := TStringList.Create;
listkarantina.LoadFromFile(NShieldPath+'quarantine.ini');

mainform.LBQUA.Items.AddStrings(listkarantina);
mainform.lbllquacount.Caption := IntToStr(mainform.LBQUA.Items.Count);
listkarantina.Free;
end;

procedure MakeLog;
var
  SL : TStringList;
  LogFile : string;
begin
  try
    LogFile := NShieldReport; //mainform.Options.ReportLocFile;
    //Kalau udah ada file log, so append!
    if FileExists(LogFile) then
    begin
      SL := TStringList.Create;
      try
        SL.LoadFromFile(LogFile);
        SL.AddStrings(MainForm.MemoscanReport.Lines);
        SL.SaveToFile(LogFile);
      finally
        SL.Free;
      end;
    end
    else //kalau belum ada, buat aja yg baru!
      MainForm.MemoscanReport.Lines.SaveToFile(LogFile);
  except
    //takut disk gak bisa ditulisin
  end;
end;


procedure ListFileDir(Path: string; FileList: TStrings);
var
  SR: TSearchRec;
begin
  if FindFirst(Path + '*.*', faAnyFile, SR) = 0 then
  begin
    repeat
      if (SR.Attr <> faDirectory) then
      begin
        FileList.Add(SR.Name);
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
end;

function ReplaseString(InStr,FindStr,ReplaseStr: String) : string;
var
    id  : integer;
    str : string;
begin
    Result := InStr;
    id     := pos(LowerCase(FindStr), LowerCase(InStr));
    str    := InStr;
    Delete(str,id,length(FindStr));
    Insert(ReplaseStr,str,id);
    Result := str;
end;

function ReplaseAllString(Line, Prefix, Return: String) : String;
var
    tmp  : string;
begin
    tmp := Line;
    while pos(Prefix,tmp) > 0 do
        tmp := ReplaseString(tmp,prefix,return);

    Result := tmp;
end;

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
//==============================================================================


{procedure BootReplaceFile(TargetFileName, SourceFileName: string);
var
    WinInitName: string;
    P: PChar;

    procedure InternalGetShortPathName(var S: string);
    begin
        UniqueString(S);
        GetShortPathName(PChar(S), PChar(S), Length(S));
        SetLength(S, StrLen(@S[1]));
        CharToOEM(PChar(S), PChar(S));
    end;

begin
    if Win32Platform = VER_PLATFORM_WIN32_NT then
    begin
        if TargetFileName <> '' then P:=PChar(TargetFileName)
        else P:=nil;
            MoveFileEx(PChar(SourceFileName), P, MOVEFILE_DELAY_UNTIL_REBOOT or MOVEFILE_REPLACE_EXISTING);
    end else begin
        try
            SetLength(WinInitName, MAX_PATH);
            GetWindowsDirectory(@WinInitName[1], MAX_PATH);
            SetLength(WinInitName, StrLen(@WinInitName[1]));
            WinInitName:=IncludeTrailingBackslash(WinInitName)+'WININIT.INI';
            if TargetFileName = '' then TargetFileName := 'NUL'
            else InternalGetShortPathName(TargetFileName);
            InternalGetShortPathName(SourceFileName);
            WritePrivateProfileString('Rename', PChar(TargetFileName),
            PChar(SourceFileName), PChar(WinInitName));
        except
        end;
    end;
end; }


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

{function BytesToMegaBytes(Bytes: int64): String;
begin
    Result := sizetostr(Bytes);
end; }

function processExists(exeFileName: string): Boolean;
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
begin
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result := False;
  while Integer(ContinueLoop) <> 0 do
  begin
    if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) =
      UpperCase(ExeFileName)) or (UpperCase(FProcessEntry32.szExeFile) =
      UpperCase(ExeFileName))) then
    begin
      Result := True;
    end;
    ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
  end;
  CloseHandle(FSnapshotHandle);
end;

function MsToStr(time: cardinal) : string;
begin
    if time >= 1000 then begin
        if time >= 1000 * 60 then begin
            if time >= 1000 * 60 * 60 then begin
                time := time div (1000 * 60);
                result := IntToStrEx(time mod 60);
                if Length(result) = 1 then result := '0' + result;
                result := IntToStrEx(time div 60) + ':' + result + ' h';
            end else begin
                time := time div 1000;
                result := IntToStrEx(time mod 60);
                if Length(result) = 1 then result := '0' + result;
                result := IntToStrEx(time div 60) + ':' + result + ' min';
            end;
        end else begin
            result := IntToStrEx(time mod 1000 div 10);
            if Length(result) = 1 then result := '0' + result;
            result := IntToStrEx(time div 1000) + DecSep + result + ' s';
        end;
    end else result := IntToStrEx(time) + ' ms';
end;

//fungsi untuk menampilkan file yang sedang di scan
function listnama(fname: string): string;   //xc_format_name
const
    __scan    = '%-70s';
    __maxline = 70;
var
    drive, path, name, _name : string;
    i, cn : integer;
begin
    result := fname;
    drive  := extractfiledrive(fname) + '\ \';
    path   := extractfilepath(fname);
    name   := extractfilename(fname);

    if length(fname) < __maxline then exit;

    if length(fname) > __maxline then
        if length(drive + name) < __maxline then
        begin
            result := drive + name;
            exit;
        end else begin
            _name  := '';
            for i := length(name) downto length(drive) do begin
                _name  := name[i] + _name;
                if length(drive + _name) >= __maxline then break;
            end;
            result := drive + _name;
        end;
end;

//function ConvertToDate(Str: String): String;
//begin
//    Result := Str;
//    Insert('.',Result,3);
//    Insert('.',Result,6);
//end;

//fungsi untuk mengecek apakah database virus sudah expired atau tidak

function isDBExpired(date: string): boolean;
var
    DT,DTNOW: TDate;
begin
    Result := False;
    dt := StrToDate(date);
    (* *)
    try
        if Date = '0'  then result := true   //DateToStr(Now)
        else begin
            Dt := StrToDate(FormatDateTime('mm/dd/yy',dt));
            DTNOW := StrToDate(FormatDateTime('mm/dd/yy',now));

            //jika lebih dari 7 hari maka db harus diupdate
            if DT+7 < DTNOW then Result := true;
        end;
    except
    end;
end;

procedure DoDownload;
begin
   with TDownloadURL.Create(nil) do
   try
     MainForm.lbldownload.caption := 'Downloading..';
     URL:='http://nshieldantivirus.url.ph/UpdateDB/update.vdb';
     FileName := NShieldDatabase_Update;
     OnDownloadProgress := MainForm.URL_OnDownloadProgress;
     ExecuteTarget(nil);
     Free;
     MainForm.lbldownload.caption := 'Finished';
     MainForm.lbldbupdate.Caption := DateToStr(Date);
   except
   on E : Exception do
      ShowMessage(E.ClassName+' update failed with error : '+E.Message);
  { end
   finally
        Free;
        MainForm.lbldownload.caption := 'Finished';
        MainForm.lbldbupdate.Caption := DateToStr(Date);
        messagebox(0, 'Update Database Finished', 'N-Shield AntiVirus', MB_ICONINFORMATION);
   }
   end;
end;

procedure NShieldScandbg(msg: dword; const args: array of const);
begin
    case msg of
        NSHIELD_UNARCH_FILE : begin
                           MainForm.Scanner.UnArchName := listnama(MainForm.Scanner.FileName +'/'+ format('%s',args));
                           inc(MainForm.Scanner.FullScanned);
                       end;
        NSHIELD_LOAD_PDB  : begin
                           MainForm.Scanner.LastCount := Nshield_Get_VirusCount(MainForm.Scanner.ENGINE) - MainForm.Scanner.LastCount;
                           MainForm.Scanner.LastCount := Nshield_Get_VirusCount(MainForm.Scanner.ENGINE);
                       end;
        NSHIELD_LOADDB   : begin
                           MainForm.Scanner.LastCount := Nshield_Get_VirusCount(MainForm.Scanner.ENGINE) - MainForm.Scanner.LastCount;
                           MainForm.Scanner.LastCount := Nshield_Get_VirusCount(MainForm.Scanner.ENGINE);
                       end;
    end;
end;


procedure NShieldScandbg_dua(msg: dword; const args: array of const);
begin
    case msg of
        //NSHIELD_UNARCH_FILE : begin
        //                   MainForm.UnArchName := listnama(MainForm.Scanner.FileName +'/'+ format('%s',args));
        //                   inc(MainForm.Scanner.FullScanned);
        //               end;
        NSHIELD_LOAD_PDB  : begin
                           MainForm.LastCount2 := Nshield_Get_VirusCount(MainForm.ENGINE2) - MainForm.LastCount2;
                           MainForm.LastCount2 := Nshield_Get_VirusCount(MainForm.ENGINE2);
                       end;
        NSHIELD_LOADDB   : begin
                           MainForm.LastCount2 := Nshield_Get_VirusCount(MainForm.ENGINE2) - MainForm.LastCount2;
                           MainForm.LastCount2 := Nshield_Get_VirusCount(MainForm.ENGINE2);
                       end;
    end;
end;


//menampilkan progress scan pada file, jika file yang discan adalah file arsip maka
//akan menampilkan persentase scan,contoh -> C:\1.rar [10%]
procedure ScanProgress(progres: integer);
begin
    if progres < 0 then begin
         MainForm.Scanner.AturProsesFile(MainForm.Scanner.FileName);
    end
    else begin
        if MainForm.Scanner.UnArchName = '' then
            MainForm.Scanner.AturProsesFile(MainForm.Scanner.FileName) // +' ['+ inttostr(progres)+'%]')
        else begin
            MainForm.Scanner.AturProsesFile(MainForm.Scanner.UnArchName +' ['+ inttostr(progres)+'%]');
        end;
    end;
end;

Procedure TProcessList.DeleteDoobleEntry(List: TStrings);
var
    i,j: integer;
begin
    i := 0;
    while i < List.Count-1 do begin
        j := i+1;
        while j < List.Count-1 do begin
            if LowerCase(List[i]) = LowerCase(List[j]) then
                list.Delete(j);
            inc(j);
        end;
        inc(i);
    end;
end;

procedure TProcessList.GetProcessList(List: Tstrings);
var
    ProcList: ProcessList;
    i: integer;
begin
    ProcList := ProcessList.Create;
    Exgetprocesslist(ProcList);

    for i := 0 to ProcList.Count-1 do begin
        (* *)
        List.Add(getpathbyPID(PProcessRecord(ProcList[i]).ProcessId));
        getmoduleslist(PProcessRecord(ProcList[i]).ProcessId, List);
        (* *)
    end;

    DeleteDoobleEntry(List);
    freeprocesslist(ProcList);
end;


function TFileCounter.ExtensiScan(FileName: String): boolean;
var
    ext: string;
    i: integer;
begin
    ext := LowerCase(ExtractFileExt(FileName))+'|';

    //if MainForm.Options.FilterString = '|' then begin
        Result := true;
    //end else
    //if Pos('.*|', lowercase(Filter)) <> 0 then begin
    //    Result := true;
    //end else
    //if Pos(ext, lowercase(Filter)) <> 0 then
    //    Result := true
    //    else
    //    Result := false;
end;

procedure TFileCounter.GetFileCount(Dir: String);
Var
    SR        : TSearchRec;
    FindRes,i : Integer;
    EX        : String;
begin
    FindRes:=sysutils.FindFirst(Dir+'*.*',faAnyFile,SR);
    While FindRes=0 do
    begin

        if TAvScanner(Scanner).ScanStopped then Exit;

        if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then
        begin
            FindRes:=FindNext(SR);
            Continue;
        end;

        if MainForm.Options.ScanInSubDirectories then
            if ((SR.Attr and faDirectory)=faDirectory) then
            begin
                GetFileCount(Dir+SR.Name+'\');
                FindRes:=sysutils.FindNext(SR);
                Continue;
            end;

        if FileExists(Dir+Sr.Name) then begin
            //if ExtensiScan(Sr.Name) then
            TAvScanner(Scanner).FilesCount := TAvScanner(Scanner).FilesCount + 1;
        end;

        FindRes:=sysutils.FindNext(SR);
    end;
    sysutils.FindClose(SR);
end;

Procedure TFileCounter.Execute;
var
    i : integer;
begin
    TAvScanner(Scanner).FilesCount := 0;
    Filter := MainForm.Options.FilterString;
    for i := 0 to Dirs.Count-1 do begin
        if TAvScanner(Scanner).ScanStopped then Exit;
        if FileExists(Dirs[i]) then begin
            //if ExtensiScan(ExtractFileName(Dirs[i])) then
                TAvScanner(Scanner).FilesCount := TAvScanner(Scanner).FilesCount + 1;
        end
        else
        begin
            if DirectoryExists(Dirs[i]) then
                GetFileCount(Dirs[i]);
        end;
    end;
    //TAvScanner(Scanner).SetMaximalFiles(TAvScanner(Scanner).FilesCount);
end;



//==============================================================================
procedure TAvScanner.PindaiFolder(Dir:String);
    procedure setnormattr(filename: string);
    var
        Flags : cardinal;
    begin
        Flags := 0;
        Flags := Flags - faReadOnly;
        SetFileAttributes(PChar(FileName),Flags);
        Flags := 0;
        Flags := Flags - faReadOnly;
        Flags := Flags - faHidden;
        Flags := Flags - faSysFile;
        Flags := Flags - faArchive;
        Flags := Flags + faAnyFile;
        SetFileAttributes(PChar(FileName),Flags);
    end;
var
    SR      : TSearchRec;
    FindRes : Integer;
    vn      : pchar;
    ret     : integer;
    a       : Tlistitem;  //untuk mainform.listview
    sementara, teksnya : String;
    //desc: tfilestream;
    //sizenya : int64;
begin
    FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
    (* *)
    inc(DirCount);
    (* *)
    While FindRes=0 do
    begin

        //jika scan dihentikan, keluar =))
        if ScanStopped then exit;

        if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then
        begin
            FindRes:=FindNext(SR);
            Continue;
        end;

        if MainForm.Options.ScanInSubDirectories then
            if ((SR.Attr and faDirectory)=faDirectory) then
            begin
                PindaiFolder(Dir+SR.Name+'\');
                FindRes:=FindNext(SR);
                Continue;
            end;

        if FileExists(Dir+SR.Name) then
        //if ExtensiScan(SR.Name) then
        begin
            (* *)
            if ScanStopped then exit;
            try
                try
                    FileName := listnama(Dir + SR.Name);
                except
                end;
                UnArchName := '';
                inc(scanned);
                inc(FullScanned);
                Synchronize(HitungFileScan);

                ret := NShield_Match_File(ENGINE, pchar(Dir+SR.Name), vn, ScanProgress, NShieldScandbg,true);

                //jika file positif virus maka
                if ret = BERVIRUS then begin
                    inc(Infected);
                    setlength(MainForm.VirusList, Infected + 1);
                    MainForm.VirusList[Infected-1].virname := vn;
                    MainForm.VirusList[Infected-1].path := dir+sr.Name;
                    MainForm.VirusList[Infected-1].deleted := false;

                    //format log : nama file + nama virus
                    status(format('%s - %s',[Dir+SR.Name, vn]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add(vn);
                        a.SubItems.add(Dir+SR.Name);

                    //if MainForm.Options.Kill then
                    //    teksnya := ' : this Malware active in memory, do you want to terminate it?';
                    //    sementara := (Dir+SR.Name);
                    //      if MessageBox(0,pchar(sementara + teksnya), 'N-Shield AntiVirus', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
                    //        begin
                            //TerminateProcess(OpenProcess(PROCESS_TERMINATE,Bool(1),msg.pid),0);
                    //        MainForm.KillProcess(Dir+SR.Name);
                    //        end else
                            //nothing =))
                            //end;
                    end;

                    if MainForm.Options.AutoUnHidden = true then
                    begin
                       SetFileAttributes(pchar(Dir+SR.Name),FILE_ATTRIBUTE_NORMAL);
                    end;

                    if isfilehiden(Dir+SR.Name) then
                    begin
                        status(format('Hidden Files - %s',[Dir+SR.Name]));
                        a := MainForm.lvhiddenfiles.Items.Add;
                        a.caption := 'Hidden';
                        a.SubItems.add(Dir+SR.Name);
                  end;

//scan double extension
{if (LowerCase(ExtractFileExt(FileNAme)) = '.doc.exe') or (LowerCase(ExtractFileExt(FileName)) = '.jpg.exe') then
  begin
    status(format('Double Extensions - %s',[Dir+SR.Name]));
       a := MainForm.lvwarning.Items.Add;
       a.caption := 'Double Extensions';
       a.SubItems.add(Dir+SR.Name);
  end;}
                //FullSize := FullSize + ExGetFileSize(Dir + SR.Name);
                //try
                //  desc := tfilestream.create(Dir+SR.Name, fmShareDenyNone);
                //    except
                //  exit;
                //end;

                //sizenya := desc.size;
                //if sizenya < 1000000 then
                //if ExGetFileSize(Dir + SR.Name) < 1000000 then  // 1mb
                if MainForm.Options.ScanEncrypted = true then
                  if NShield_CheckEncrypted(Dir+SR.Name) then
                    begin
                        setlength(MainForm.VirusList, Infected + 1);
                        status(format('%s - %s',[Dir+SR.Name, vn]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add('Heur.Win32.Encrypted-File');
                        a.SubItems.add(Dir+SR.Name);
                    //end;
                  end;

                //if ExGetFileSize(Dir + SR.Name)< 1000000 then  // 1mb
                //if sizenya < 1000000 then
                  {if NShield_CheckOverlay(Dir+SR.Name) then
                    begin
                        setlength(MainForm.VirusList, Infected + 1);
                        status(format('%s - %s',[Dir+SR.Name, vn]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add('Heur.Win32.NewPE');
                        a.SubItems.add(Dir+SR.Name);
                    //end;
                  end;  }

                if (ret = DIBACA) or (ret = UKURAN) then begin //XC_ESIZE XC_EREAD
                    inc(Skipped);
                    status(format('WARNING - This File is not scanned : %s',[Dir+SR.Name]));
                end
                else
                    FullSize := FullSize + ExGetFileSize(Dir + SR.Name);
            (* *)
            except
            end;
        end;
        FindRes:=FindNext(SR);
    end;
    SysUtils.FindClose(SR);
    //desc.Free;
end;



Procedure TAvScanner.SelesaiScan;
begin
    MainForm.lblfilescanning.Caption := 'Finished';
end;

Procedure TAvScanner.AdaKesalahan;
begin
   messagebox(0, 'ERROR - scanning interrupted', 'N-Shield AntiVirus', MB_ICONERROR);
end;

Procedure TAvScanner.HitungFileScan;
begin
    MainForm.lblfilescanned.Caption := Format('%d',[FullScanned]);
    MainForm.lblviruscount.Caption := Format('%d',[Infected]); //scanform
end;

Procedure TAvScanner.Hentikan;
begin
    Resume;
    ScanStopped := true;
end;

procedure TAvScanner.ScanRegistryRun;
var
  Startup: TRegistry; //set root di HKLM
  key1 : String;    //string item startup di logon
  Nams:  TStringList;
  i, ret: Integer;
  vn      : pchar;
  a       : Tlistitem;  //untuk mainform.listview
begin
 Nams := TStringList.Create;
 Startup.RootKey := HKEY_LOCAL_MACHINE;
 Key1 := '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
 if Startup.OpenKey(Key1, False) then
  begin
    Startup.GetValueNames(Nams);
    for i := 0 to Nams.Count - 1 do
      begin
          Startup.ReadString(Nams[i]);
          showmessage(nams[i]);
            {ret := cocokanfile(ENGINE, pchar(Nams[i]), vn, ScanProgress, ScanDebug,true);
                (* *)
                if ret = BERVIRUS then begin
                    inc(Infected);
                    setlength(MainForm.VirusList, Infected);
                    MainForm.VirusList[Infected-1].virname := vn;
                    MainForm.VirusList[Infected-1].path := dirs[i];
                    MainForm.VirusList[Infected-1].deleted := false;
                    status(format('Registry Infected - (%s): %s',[vn, Nams[i]]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Infected';
                        a.SubItems.Add(vn);
                        a.SubItems.add('REGISTRY :'+Nams[i]);}
      //end;
    Startup.CloseKey;
  end;
Nams.Free;
end;
end;

{
prosedur thread scanner utama
}
Procedure TAvScanner.Execute;
var
    i, ret, ts, te, mf, ma : integer;
    a : tlistitem;
    vn: pchar;
    Opt: myscan_options;
    FCN: TFileCounter;
    ProcList: ProcessList;
    ProcID: integer;
    ProcPath: string;
    label finish;

begin

    LastCount   := 0;
    Scanned     := 0;
    DirCount    := 0;
    FullSize    := 0;
    Infected    := 0;
    Skipped     := 0;
    FullScanned := 0;
    FileName    := '';
    UnArchName  := '';
    ScanStopped := false;
    SetProgress := false;
    Filter      := '.*';
    FileProgress:= '';

    Synchronize(AturProgramBerjalan);

    status('=========================================');
    status('N-Shield AntiVirus 2014 Scan Report');
    status('Copyright(c) 2014 by N-Shield labs');
    status('=========================================');
    status('                                   ');
    status('Build Version    : ' + mainform.label26.Caption);
    status('Build Date       : ' + mainform.label28.Caption);
    status('Engine Version   : ' + mainform.lblenginever.Caption);
    status('Signature Loaded : ' + mainform.lblsigcount.Caption);
    status('Last Update      : ' + mainform.lbldbupdate.Caption);

    case MainForm.Options.ScanPriority of
        0 : Self.Priority := tpNormal;
        1 : Self.Priority := tpLower;
    end;

    opt := [];

    //Filter scan berdasarkan tipe file
    //optimize scanning, hanya file PE,PDF dan file khusus lainnya [masuk ke file PDF]
    if MainForm.Options.OptimizeScan then
        opt := opt + [pindai_pe]
    else begin
        opt := opt + [pindai_pdf, pindai_gambar, pindai_pe, pindai_lainnya];
    end;
    if MainForm.Options.ScanArchives then begin
        opt := opt + [pindai_rar, pindai_zip];
    end;
    if MainForm.Options.Whitelist then begin
        opt := opt + [pindai_force];
    end;

    //filter scanning berdasarkan ukuran file
    mf := (1024 * 1024) * strtoint(MainForm.Options.FileSizeLimit);
    ma := (1024 * 1024) * MainForm.Options.ArchiveLimit;

    NShield_Start_Engine(ENGINE, @NShieldScandbg);
    NShield_Config(ENGINE, opt, mf, ma, pchar(NShieldTemp));

    if not DirectoryExists(NShieldTemp) then
        SurePath(NShieldTemp);

    NShield_Get_VBD_Dir(ENGINE,pchar(NShieldDatabase),MainForm.Options.UseUserDataBases);

    MainForm.lblsigcount.Caption := inttostr(Nshield_Get_VirusCount(ENGINE));
    status('                                   ');

   if Nshield_Get_VirusCount(ENGINE) = 0 then begin
        messagebox(0, 'ERROR 1 - Database not found', 'N-shield AntiVirus',MB_ICONERROR);
        Synchronize(AdaKesalahan);
        goto finish;
    end else
    //if isExpired(databasedate(ENGINE)) then begin
    //    messagebox(0, 'WARNING - Database is expired,please update it','N-shield AntiVirus',MB_ICONWARNING);
    //    status(' WARNING - Database is expired');
    //    status('                                   ');
    //end;



    (* Set file scan count *)
    FCN         := TFileCounter.Create(true);
    FCN.Dirs    := Dirs;
    FCN.Scanner := Pointer(Self);
    FCN.Resume;

    MainForm.btnPausescan.Enabled := true;
    try

    //mulai scan registry
    //if mainform.Options.ScanReg then begin
    //status('Scanning Registry...');
    //scanregistryrun;
    //end;

    (* Print InVisible in ProcessList *)
        if Memscan then begin
            status('Scanning Memory...');
            ProcList := ProcessList.Create;
            Exgetprocesslist(ProcList);
            (* *)
            if Mainform.options.SmartScan = true then
               begin
               ScanMutex;
               end;

           if Mainform.options.ScanHiddenProc = true then
              begin
              GetHiddenProcessList;
              end;
            for i := 0 to ProcList.Count - 1 do begin
                ProcID := PProcessRecord(ProcList[i]).ProcessId;
                ProcPath := getpathbyPID(ProcID);
                if IsFileHiden(getpathbyPID(ProcID)) then
                    //status(format('WARNING - File Hidden [PID %d]: %s',[ProcID, ProcPath])) //, $000036C6)
                    //setlength(MainForm.VirusList, Infected + 1);
                    //MainForm.VirusList[Infected-1].virname := vn;
                    //MainForm.VirusList[Infected-1].path := dir+sr.Name;
                    //MainForm.VirusList[Infected-1].deleted := false;
                        //a := MainForm.listview1.Items.Add;
                        //a.caption := 'Hidden File';
                        //a.SubItems.Add(inttostr(ProcID));
                        //a.SubItems.add(ProcPath)
                else
                //catat ke log process yang discan
                status(format('Scanned : %s',[ProcPath]));
                //status(format('Scanned - [PID %d]: %s',[ProcID, ProcPath]));
                if not PProcessRecord(ProcList[i]).IsVisible then
                    status(format('WARNING - Not Scanned : %s',[ProcPath]));
            end;
            (* *)
            freeprocesslist(ProcList);
        end;
    (* *)
        i := 0;
        while i < Dirs.Count do begin

            if ScanStopped then break;

            if FileExists(Dirs[i]) then //and ExtensiScan(ExtractFileName(Dirs[i])) then
            begin
                inc(scanned);
                inc(FullScanned);
                Synchronize(HitungFileScan);
                try
                    FileName := listnama(Dirs[i]);
                except
                end;

                ret := NShield_Match_File(ENGINE, pchar(Dirs[i]), vn, ScanProgress, NShieldScandbg,true);

                if ret = BERVIRUS then begin
                    inc(Infected);

                    setlength(MainForm.VirusList, Infected);
                    MainForm.VirusList[Infected-1].virname := vn;
                    MainForm.VirusList[Infected-1].path := dirs[i];
                    MainForm.VirusList[Infected-1].deleted := false;
                    status(format('%s - %s',[dirs[i], vn]));
                    //status(format('Virus Detected - (%s): %s',[vn, dirs[i]]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add(vn);
                        a.SubItems.add(dirs[i]);
                    //MainForm.lblviruscount.Caption := format('%d', [Infected]);

                    if MainForm.Options.Kill then
                          MainForm.KillProcess(Dirs[i]);
                    end;
                        //MainForm.lblviruscount.Caption := format('%d', [Infected]);
                if (ret = DIBACA) or (ret = UKURAN) then begin
                    inc(Skipped);
                    //status(format('WARNING - This file is not scanned: %s',[Dirs[i]]));
                end
                else
                    FullSize := FullSize + ExGetFileSize(Dirs[i]);
            end else
                if DirectoryExists(Dirs[i]) then
                    //ScanDir (path yang disimpan pada variabel Dirs yg bertipe TStringList
                    //showmessage(dirs[i]);
                    PindaiFolder(Dirs[i]);

            inc(i);
        end;

    except
    end;

    finish:


    case ScanStopped of
        True  : begin
                    status('            ');
                    status('Scan aborted');
                end;
        False : begin
                    status('            ');
                    status('Scan Finished');
                end;
    end;

    status('                                   ');
    status('Scan Started at    : ' + mainform.lblstarttime.Caption);
    status('Scan Finished at   : ' + mainform.lbltime.Caption);
    status(format('Files Scanned       : %d', [Scanned]));
    status(format('Threat(s) Detected  : %d', [Infected]));

    //status(format('File Found      : %d', [FullScanned]));
    //status(format('Scanned Folders : %d', [DirCount]));
    //statusformat('Skipped Files : %d',[Skipped]), clBlack);

    MainForm.lblviruscount.Caption := format('%d', [Infected]);

    //jika file yg discan = 0 (pertama kali n-shield dijalankan maka
    //bersihkan report memo
    if scanned = 0 then begin
    MainForm.MemoScanReport.Clear;
    end;

    if MainForm.Options.AutoSaveReport then begin
    makelog;
    end;

    (* free engine *)
    Dirs.Free;
    try
        FCN.Free;
    except
    end;

    NShield_Stop_Engine(ENGINE);
    FreeMem(ENGINE);
    (* Set controls *)
    Synchronize(SelesaiScan);
    Synchronize(AturProgramBerakhir);
    Free;
end;


function TAvScanner.ExtensiScan(FileName: String): boolean;
var
    ext: string;
    i: integer;
begin
    ext := LowerCase(ExtractFileExt(FileName))+'|';

    if Filter = '|' then begin
        Result := true;
    end else
    if Pos('.*|', lowercase(Filter)) <> 0 then begin
        Result := true;
    end else
    if Pos(ext, lowercase(Filter)) <> 0 then
        Result := true
        else
        Result := false;
end;

procedure TAvScanner.PerbaruiProses;
begin
    MainForm.lblfilescanning.Caption := FileProgress;
end;

procedure TAvScanner.AturProsesFile(FP: String);
begin
    FileProgress := FP;
    Synchronize(PerbaruiProses);
end;

procedure TAvScanner.AturProgramBerakhir;
begin
    MainForm.lblstatus.Caption := 'Scanning Finished';
    MainForm.lblfilescanning.Visible := false;
    mainform.lbltime.Caption := timetostr(gettime);
    MainForm.btnPausescan.Enabled  := False;
    MainForm.btnSaveReport.Enabled := true;
    MainForm.btnStopscan.Enabled  := False;
    MainForm.btnselallvirus.Enabled := true;
    MainForm.btnselallhdden.Enabled := true;
    MainForm.btnDelete.Enabled := true;
    MainForm.btnquarantine.Enabled := true;
    MainForm.BtnUnhide.Enabled := true;
    MainForm.btnscan.Enabled := true;
    MainForm.btnrefresh.Enabled := true;
    MainForm.btnscansingle.Enabled := true;
    Mainform.btnsave.Enabled := true;
end;

procedure TAvScanner.AturProgramBerjalan;
begin
    CloseTick := 10;
    MainForm.lblstatus.Caption := 'Scanning File...Please Wait';
    MainForm.lblfilescanning.Visible := true;
    MainForm.lblfilescanning.Caption     := '--';
    MainForm.lblviruscount.Caption := '00';
    MainForm.lblfilescanned.Caption := '00';
    MainForm.lbllastscanned.Caption := (Format('%s', [DateTimeToStr(Now)]));
    mainform.lblstarttime.Caption := timetostr(gettime);
    mainform.lbltime.Caption := '--';
    MainForm.Memoscanreport.Clear;
    MainForm.btnSaveReport.Enabled := false;
    MainForm.btnStopscan.Enabled := true;
    MainForm.btnStopscan.Caption := 'Stop';
    MainForm.btnPausescan.Enabled := false;
    MainForm.btnselallvirus.Enabled := false;
    MainForm.btnselallhdden.Enabled := false;
    MainForm.btnDelete.Enabled := false;
    MainForm.btnquarantine.Enabled := false;
    MainForm.BtnUnhide.Enabled := false;
    MainForm.btnscan.Enabled := false;
    MainForm.btnrefresh.Enabled := false;
    MainForm.btnscansingle.Enabled := false;
    Mainform.btnsave.Enabled := false;
    MainForm.SimpanSettingan;
end;

procedure scanRTP;
var
ret,mf,ma : integer;
Opt: myscan_options;
vn: pchar;
sementara,teksnya : string;
a : tlistitem;
begin

if FileExists(Mainform.Label8.Caption) then
begin
    opt := [];
    if mainform.Options.OptimizeScan then
        opt := opt + [pindai_pe]
    else begin
        opt := opt + [pindai_pdf, pindai_gambar, pindai_pe, pindai_lainnya];
    end;
    if mainform.Options.ScanArchives then begin
        opt := opt + [pindai_rar, pindai_zip];
    end;
    if mainform.Options.Whitelist then begin
        opt := opt + [pindai_force];
    end;
    //mf := (1024 * 1024) * strtoint(Options.FileSizeLimit);
    mf := (1024 * 1024) * strtoint(MainForm.txtFilterSize.Text);
    ma := (1024 * 1024) * mainform.Options.ArchiveLimit;
    NShield_Config(Mainform.ENGINE2, opt, mf, ma, pchar(NShieldTemp));
    ret := NShield_Match_File(Mainform.ENGINE2, pchar(Mainform.Label8.Caption), vn, ScanProgress, NShieldScandbg_dua,true);
                (* *)
                if ret = BERVIRUS then begin

                sementara := 'Virus Detected : ' + vn + ' = ' ;
                teksnya := Mainform.Label8.Caption;
                 a := MainForm.lvrtp.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add('');
                        a.SubItems.add(Mainform.Label8.Caption);
                        a.SubItems.Add(vn);

                    OpenAlert(vn,Mainform.Label8.Caption);
                   //if MessageBox(0,pchar(sementara + teksnya), 'Delete it?', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
                      //begin
                      //deletefile(teksnya);
                      //end
                      //else
                      //nothing
                      end
else
exit;
end;
end;

procedure MyInfoCallBack(pInfo: TInfoCallBack);
  const
    Action: array[1..3] of String = ('%s', '%s', '%s');
  begin

    case pInfo.FAction of
      FILE_ACTION_RENAMED_NEW_NAME: MainForm.Memo2.Lines.Add(Format('%s %s',
          [pInfo.FDrive+pInfo.FOldFileName,pInfo.FDrive+pInfo.FNewFileName]));
    else
      if pInfo.FAction<FILE_ACTION_RENAMED_OLD_NAME then
      begin
        try
        //error :  EConvertError, sysutils
        //MainForm.Memo2.Lines.Add(Format(Action[pInfo.Faction], [pInfo.FDrive+pInfo.FNewFileName]));
        MainForm.Label8.Caption := format(Action[pInfo.Faction], [pInfo.FDrive+pInfo.FNewFileName]);
        scanrtp; //DISABLE DULU SEMENTARA
        except
        end;
        end;
    end;
{
   case pInfo.FAction of
FILE_NOTIFY_CHANGE_FILE_NAME:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_FILE_NAME');
FILE_NOTIFY_CHANGE_DIR_NAME:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_DIR_NAME');
FILE_NOTIFY_CHANGE_ATTRIBUTES:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_ATTRIBUTES');
FILE_NOTIFY_CHANGE_SIZE:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_SIZE');
FILE_NOTIFY_CHANGE_LAST_WRITE:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_LAST_WRITE');
FILE_NOTIFY_CHANGE_LAST_ACCESS:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_LAST_ACCESS');
FILE_NOTIFY_CHANGE_CREATION:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_CREATION');
FILE_NOTIFY_CHANGE_SECURITY:Form1.Memo1.Lines.Add('FILE_NOTIFY_CHANGE_SECURITY');
   end;}
  end;

procedure TMainForm.AppMessage(var Msg: TMsg; var Handled: boolean);
begin
  {One Instance}
  if Msg.message = MyMsg then
   begin
    Application.Restore;
    SetForeGroundWindow(Application.MainForm.Handle);
    Handled := True;
   end;
end;

procedure TMainForm.WMEndSession ( var Msg: TWMEndSession);
  begin 
   if Msg.EndSession = True then
     //ShowMessage ('Windows is shutting down!');
     EndGuard;
     application.Terminate;
   Inherited ;
  end ;

procedure TMainForm.WndProc(var Msg: TMessage);
begin
  {Icon in the Tray}
  if (Msg.Msg = WM_USER + 1) then
   begin
    case Msg.lParam of
     WM_LBUTTONDBLCLK:
      begin
       MainForm.Show;
      end;
     WM_RBUTTONUP: TrayPopupMenu.Popup(Mouse.CursorPos.X, Mouse.CursorPos.Y);
    end;
   end
  else
   DefWindowProc(FWindowHandle, Msg.Msg, Msg.wParam, Msg.lParam);
end;

function TMainForm.DeteksiAutorun(VirList: TStrings): boolean;
var
  i,atr: integer;
  alamat,teksnya : string;
begin
  if chkdrive_pro.Checked then
  begin
    for i := 0 to VirList.Count - 1 do
    begin
      if FileExists(VirList.Strings [i] + UpperCase('autorun.inf')) then
      begin
        DrivePro.Enabled := False;
        alamat := (VirList.Strings [i] + UpperCase('autorun.inf'));
        teksnya := ' : detected, do you want to delete it?';
    if MessageBox(0,pchar(alamat + teksnya), 'N-Shield AntiVirus', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
      begin
        Atr := FileGetAttr(alamat);
        SetFileAttributes(PChar(alamat), Atr - faReadOnly + faHidden + faSysFile + faArchive);
        DeleteFile(alamat);
        DrivePro.Enabled := true;
      end else
        DrivePro.Enabled := true;
      end;
    end;
  end;
end;

//============================================================
//fungsi untuk membaca setting dan menampilkannya di form main
Procedure TMainForm.BukaSettingan;
begin
    BacaSettings;

    //general
    MainForm.chkRunAtStartup.Checked  := Options.RunStartup;
    MainForm.chkselfdefense.Checked   := Options.SelfDefense;
    MainForm.chkselfcheck.Checked     := Options.SelfCheck;
    MainForm.chkautoreport.Checked    := Options.AutoSaveReport;
    MainForm.chkautounhide.Checked    := Options.AutoUnHidden;

    //scanner
    MainForm.chkScanDir.Checked       := Options.ScanInSubDirectories;
    MainForm.chkWhiteList.Checked     := Options.Whitelist;
    MainForm.chkoptimizescan.Checked  := Options.OptimizeScan;
    MainForm.chkScanArch.Checked      := Options.ScanArchives;
    MainForm.chkSmartScan.Checked     := Options.SmartScan;
    MainForm.chkHiddenProc.Checked    := Options.ScanHiddenProc;
    MainForm.chkScanMem.Checked       := Options.ScanMem;
    MainForm.chkScanReg.Checked       := Options.ScanReg;
    MainForm.ChkScanHidden.Checked    := Options.ScanHidden;
    MainForm.chkkill.Checked          := Options.Kill;
    MainForm.lbllastscanned.Caption   := Options.LastScanned;
    MainForm.ChkAdvHeur.Checked       := Options.ScanEncrypted;

    //rtp
    MainForm.chkRTP.Checked           := Options.RTP;
    MainForm.chkantikyelogger.Checked := Options.AntiKeylogger;
    MainForm.chkRegShield.Checked     := Options.RegShield;

    //update
    MainForm.lbldbupdate.Caption      := Options.UpdateDate;
    MainForm.chkcekupdate.Checked     := options.AutoUpdate;
    //filter
    //MainForm.lbFilter.Items.Text      := ReplaseAllString(Options.FilterString,'|',#13#10);
    MainForm.txtFilterSize.Text       := Options.FileSizeLimit;
    //MainForm.seArchLimit.Value        := Options.ArchiveLimit;

    //MainForm.cbPriority.ItemIndex     := Options.ScanPriority;
end;

Procedure TMainForm.SettinganNormal;
begin
    //general
    Options.RunStartup           := true;
    Options.SelfDefense          := false;
    Options.SelfCheck            := false;
    Options.AutoSaveReport       := false;
    Options.AutoUnHidden         := false;

    //scanner
    Options.ScanInSubDirectories := true;
    Options.Whitelist            := true;
    Options.OptimizeScan         := false;
    Options.ScanArchives         := false;
    Options.SmartScan            := false;
    Options.ScanHiddenProc       := false;
    Options.ScanMem              := true;
    Options.ScanReg              := true;
    Options.ScanHidden           := false;
    Options.Kill                 := true;
    Options.LastScanned          := MainForm.lbllastscanned.Caption;
    Options.ScanEncrypted        := false;

    //rtp
    Options.RTP                  := true; //false;
    Options.AntiKeylogger        := false;
    Options.RegShield            := false;

    //update
    options.UpdateDate           := MainForm.lbldbupdate.Caption;
    options.autoupdate           := true;
    //filter
    //Options.FilterString         := '.*';
    Options.FileSizeLimit        := '100'; //100 MB
    //Options.ArchiveLimit         := 10;

    (* *)
    //Options.ScanPriority         := 0;
end;

Procedure TMainForm.SimpanSettingan;
var
    IniFile : TIniFile;
begin
    //general
    Options.RunStartup           := MainForm.chkRunAtStartup.Checked;
    Options.SelfDefense          := MainForm.chkselfdefense.Checked;
    Options.SelfCheck            := MainForm.chkselfcheck.Checked;
    Options.AutoSaveReport       := MainForm.chkautoreport.Checked;
    Options.AutoUnHidden         := MainForm.chkautounhide.Checked;

    //scanner
    Options.ScanInSubDirectories := MainForm.chkScanDir.Checked;
    Options.Whitelist            := MainForm.chkWhiteList.Checked;
    Options.OptimizeScan         := MainForm.chkoptimizescan.Checked;
    Options.ScanArchives         := MainForm.chkScanArch.Checked;
    Options.SmartScan            := MainForm.chkSmartScan.Checked;
    Options.ScanHiddenProc       := MainForm.chkHiddenProc.Checked;
    Options.ScanMem              := MainForm.chkScanMem.Checked;
    Options.ScanReg              := MainForm.chkScanReg.Checked;
    Options.ScanHidden           := MainForm.ChkScanHidden.Checked;
    Options.Kill                 := MainForm.chkkill.Checked;
    Options.LastScanned          := MainForm.lbllastscanned.Caption;
    Options.ScanEncrypted        := MainForm.ChkAdvHeur.Checked;

    //rtp
    Options.RTP                  := MainForm.chkRTP.Checked;
    Options.AntiKeylogger        := MainForm.chkantikyelogger.Checked;
    Options.RegShield            := MainForm.chkRegShield.Checked;

    //update
    options.UpdateDate           := MainForm.lbldbupdate.Caption;
    options.AutoUpdate           := MainForm.chkcekupdate.Checked;
    //filter
    //Options.FilterString         := ReplaseAllString(MainForm.lbFilter.Items.Text,#13#10,'|');
    Options.FileSizeLimit        := MainForm.txtFilterSize.Text;
    //Options.ArchiveLimit         := MainForm.seArchLimit.Value;

    //location
    //Options.DataBaseLocDir       := MainForm.edDataBase.Text;
    //Options.TempLocDir           := MainForm.edTemp.Text;
    //Options.ReportLocFile        := MainForm.edReport.Text;
    (* *)
    //Options.UpdateURL            := MainForm.edUpdate.Text;
    (* *)
    //Options.ScanPriority         := MainForm.cbPriority.ItemIndex;
    (* *)
    try
        IniFile := TIniFile.Create(NShieldSettings);

        //general
        Inifile.WriteBool('General','RunAtStartup',Options.RunStartup);
        Inifile.WriteBool('General','SelfDefense',Options.SelfDefense);
        Inifile.WriteBool('General','SelfCheck',Options.SelfCheck);
        Inifile.WriteBool('General','AutoSaveReport',Options.AutoSaveReport);
        Inifile.WriteBool('General','AutoUnHidden',Options.AutoUnHidden);

        //scanner
        IniFile.WriteBool('Scanner','ScanSubDir',Options.ScanInSubDirectories);
        IniFile.WriteBool('Scanner','WhiteList',Options.Whitelist);
        IniFile.WriteBool('scanner','OptimizeScan',Options.OptimizeScan);
        IniFile.WriteBool('scanner','ScanArchives',Options.ScanArchives);
        IniFile.WriteBool('scanner','SmartScan',Options.SmartScan);
        IniFile.WriteBool('scanner','ScanHiddenProc',Options.ScanHiddenProc);
        IniFile.WriteBool('scanner','ScanMemory',Options.ScanMem);
        IniFile.WriteBool('scanner','ScanRegistry',Options.ScanReg);
        IniFile.WriteBool('scanner','ScanHiddenFile',Options.ScanHidden);
        IniFile.WriteBool('scanner','Kill',Options.Kill);
        inifile.WriteString('Scanner','LastScanned',lbllastscanned.Caption);
        IniFile.WriteString('Scanner','FileSizeLimit',Options.FileSizeLimit);
        IniFile.WriteBool('scanner','ScanEncrypted',Options.ScanEncrypted);

        //rtp
        IniFile.WriteBool('RTP','Engine',Options.RTP);
        IniFile.WriteBool('RTP','AntiKeylogger',Options.AntiKeylogger);
        IniFile.WriteBool('RTP','RegistryShield',Options.RegShield);

        //updater
        inifile.WriteString('Update','UpdateDate',lbldbupdate.Caption);
        IniFile.WriteBool('Update','AutoUpdate',Options.AutoUpdate);
        //filter
        //IniFile.WriteString('Filter','FilterString',Options.FilterString);
        (* Limits *)

        //IniFile.WriteInteger('Filter','ArchiveLimit',Options.ArchiveLimit);

        (* Priority *)
        //IniFile.WriteInteger('Priority','ScanPriority',Options.ScanPriority);
        (* *)
        IniFile.Free;
    except
    end;
end;

function TMainForm.ScanPatternAtOffset(const FileName : string;
  const Pattern : ansistring; const PatternSize : Integer; const Offset : Integer): boolean;
Var
  FS : TFilestream;
  FileSize : Int64;
  FileBuff : AnsiString;
  I : LongInt;
Begin
  result := false;
  try
    FS := TFilestream.Create(filename, fmOpenRead or fmShareDenyNone);
    try
      FileSize := FS.Size;
      if (FileSize <= 0) then exit;
      i := FS.Seek(Offset, soFromBeginning);
      if (i = Offset) and (i+PatternSize <= FileSize) then
      begin
        SetLength(FileBuff, PatternSize);
        FS.Read(FileBuff[1], PatternSize);
        if Pattern =  FileBuff then result := true;
      end;
    finally
      FS.free;
      FileBuff := '';
      FileSize := 0;
    end;
  except
    result := false;
  end;
end;

procedure TMainForm.URL_OnDownloadProgress;
begin
   ProgressBar1.Max:= ProgressMax;
   ProgressBar1.Position:= Progress;
end;

Procedure TMainForm.BuatSettinganNormal;
var
    IniFile : TIniFile;
begin
    try
        IniFile := TIniFile.Create(NShieldSettings);
        //general
        Inifile.WriteBool('General','RunAtStartup',True);
        Inifile.WriteBool('General','SelfDefense',False);
        Inifile.WriteBool('General','SelfCheck',False);
        Inifile.WriteBool('General','AutoSaveReport',False);
        Inifile.WriteBool('General','AutoUnHidden',False);

        //scanner
        IniFile.WriteBool('Scanner','ScanSubDir',true);
        IniFile.WriteBool('Scanner','Whitelist',true);
        IniFile.WriteBool('scanner','OptimizeScan',false);
        IniFile.WriteBool('scanner','ScanArchives',false);
        IniFile.WriteBool('scanner','SmartScan',false);
        IniFile.WriteBool('scanner','ScanHiddenProc',false);
        IniFile.WriteBool('scanner','ScanMemory',true);
        IniFile.WriteBool('scanner','ScanRegistry',true);
        IniFile.WriteBool('scanner','ScanHiddenFile',false);
        IniFile.WriteBool('scanner','Kill',true);
        inifile.WriteString('Scanner','LastScanned',lbllastscanned.Caption);
        IniFile.WriteInteger('Scanner','FileSizeLimit',100);
        IniFile.WriteBool('scanner','ScanEncrypted',false);

        //rtp
        IniFile.WriteBool('RTP','Engine',true);  //false
        IniFile.WriteBool('RTP','AntiKeylogger',false);
        IniFile.WriteBool('RTP','RegistryShield',false);

        //update
        inifile.WriteString('Update','UpdateDate',lbldbupdate.Caption);
        IniFile.WriteBool('Update','AutoUpdate',true);
        (* Filter *)
        //IniFile.WriteString('Filter','FilterString','.*|');
        //
        //IniFile.WriteInteger('Filter','ArchiveLimit',10);

        (* Update *)
        //IniFile.WriteString('Update','UpdateURL',updatelink);
        (* Priority *)
        //IniFile.WriteInteger('Priority','ScanPriority',0);
        (* *)
        IniFile.Free;
    except
        SettinganNormal;
    end;
end;

Procedure TMainForm.BacaSettings;
var
    IniFile : TIniFile;
begin
    if not FileExists(NShieldSettings) then
        BuatSettinganNormal;

    try
        IniFile := TIniFile.Create(NShieldSettings);
        //general
        Options.RunStartup            := Inifile.ReadBool('General','RunAtStartup',True);
        Options.SelfDefense           := Inifile.ReadBool('General','SelfDefense',False);
        Options.SelfCheck             := Inifile.ReadBool('General','SelfCheck',False);
        Options.AutoSaveReport        := Inifile.ReadBool('General','AutoSaveReport',False);
        Options.AutoUnHidden          := inifile.ReadBool('General','AutoUnHidden',False);

        //scanner
        Options.ScanInSubDirectories := IniFile.ReadBool('scanner','ScanSubDir',true);
        Options.Whitelist            := IniFile.ReadBool('scanner','Whitelist',true);
        Options.OptimizeScan         := IniFile.ReadBool('scanner','OptimizeScan',False);
        Options.ScanArchives         := IniFile.ReadBool('scanner','ScanArchives',false);
        Options.SmartScan            := IniFile.ReadBool('scanner','SmartScan',false);
        Options.ScanHiddenProc       := IniFile.ReadBool('scanner','ScanHiddenProc',false);
        Options.ScanMem              := IniFile.ReadBool('scanner','ScanMemory',true);
        Options.ScanReg              := IniFile.ReadBool('scanner','ScanRegistry',true);
        Options.ScanHidden           := IniFile.ReadBool('scanner','ScanHiddenFile',false);
        Options.Kill                 := IniFile.ReadBool('Scanner','Kill',True);
        Options.LastScanned          := IniFile.ReadString('Scanner','LastScanned',lbllastscanned.Caption);
        Options.FileSizeLimit        := IniFile.ReadString('Scanner','FileSizeLimit','100');
        Options.ScanEncrypted        := IniFile.ReadBool('Scanner','ScanEncrypted',false);

        //rtp
        Options.RTP                  := IniFile.ReadBool('RTP','Engine',true); //false
        Options.AntiKeylogger        := IniFile.ReadBool('RTP','AntiKeylogger',false);
        Options.RegShield            := IniFile.ReadBool('RTP','RegistryShield',false);

        //update
        Options.UpdateDate           := IniFile.ReadString('Update','UpdateDate',lbldbupdate.Caption);
        options.AutoUpdate           := inifile.ReadBool('Update','AutoUpdate',True);
        //filter
        //Options.FilterString         := IniFile.ReadString('Filter','FilterString','.*|');

        //Options.ArchiveLimit         := IniFile.ReadInteger('Filter','ArchiveLimit',10);


        //Options.ScanPriority         := IniFile.ReadInteger('Priority','ScanPriority',0);
        (* *)
        IniFile.Free;
    except
        SettinganNormal;
    end;
end;

function RestoreLongName(fn: string): string;
    function LookupLongName(const filename: string): string;
    var
        sr: TSearchRec;
    begin
        if FindFirst(filename, faAnyFile, sr) = 0 then
            Result := sr.Name
        else
            Result := ExtractFileName(filename);
        SysUtils.FindClose(sr);
    end;
    function GetNextFN: string;
    var
        i: integer;
    begin
        Result := '';
        if Pos('\\', fn) = 1 then
        begin
            Result := '\\';
            fn := Copy(fn, 3, length(fn) - 2);
            i := Pos('\', fn);
            if i <> 0 then
            begin
                Result := Result + Copy(fn, 1, i);
                fn := Copy(fn, i + 1, length(fn) - i);
            end;
        end;
        i := Pos('\', fn);
        if i <> 0 then
        begin
            Result := Result + Copy(fn, 1, i - 1);
            fn := Copy(fn, i + 1, length(fn) - i);
        end
        else begin
            Result := Result + fn;
            fn := '';
        end;
    end;
var
    name: string;
begin
    fn := ExpandFileName(fn);
    Result := GetNextFN;
    repeat
        name := GetNextFN;
        Result := Result + '\' + LookupLongName(Result + '\' + name);
    until length(fn) = 0;
end;


{Procedure DeleteDoobleEntry(List: TStrings);
var
    i,j: integer;
begin
    i := 0;
    while i < List.Count-1 do begin
        j := i+1;
        while j < List.Count-1 do begin
            if LowerCase(List[i]) = LowerCase(List[j]) then
                list.Delete(j);
            inc(j);
        end;
        inc(i);
    end;
end; }

{procedure TMainForm.GetProcessList(List: Tstrings);
var
    ProcList: ProcessList;
    i: integer;
begin
    ProcList := ProcessList.Create;
    Exgetprocesslist(ProcList);

    for i := 0 to ProcList.Count-1 do begin
        (* *)
        List.Add(getpathbyPID(PProcessRecord(ProcList[i]).ProcessId));
        getmoduleslist(PProcessRecord(ProcList[i]).ProcessId, List);
        (* *)
    end;

    DeleteDoobleEntry(List);
    freeprocesslist(ProcList);
end; }

function TMainForm.KillProcess(ProcCapt: String): boolean;
var
    hSnapShot     : THandle;
    uProcess      : PROCESSENTRY32;
    r             : longbool;
    KillProc      : DWORD;
    hProcess      : THandle;
    cbPriv        : DWORD;
    Priv,PrivOld  : TOKEN_PRIVILEGES;
    hToken        : THandle;
    dwError       : DWORD;
begin
    hSnapShot:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    uProcess.dwSize := Sizeof(uProcess);

    try
        if(hSnapShot<>0)then
        begin
            r:=Process32First(hSnapShot, uProcess);
            while r <> false do
            begin
                hProcess:=OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,false,uProcess.th32ProcessID);
                if LowerCase(ProcCapt) = LowerCase(RestoreLongName(getPathbyPID(hProcess))) then
                    KillProc:= uProcess.th32ProcessID;
                r:=Process32Next(hSnapShot, uProcess);
                CloseHandle(hProcess);
            end;
            CloseHandle(hProcess);
            CloseHandle(hSnapShot);
        end;
    except
    end;

    hProcess:=OpenProcess(PROCESS_TERMINATE,false,KillProc);
    if hProcess = 0 then
    begin
        cbPriv:=SizeOf(PrivOld);
        OpenThreadToken(GetCurrentThread,TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES,false,hToken);
        OpenProcessToken(GetCurrentProcess,TOKEN_QUERY or  TOKEN_ADJUST_PRIVILEGES,hToken);
        Priv.PrivilegeCount:=1;
        Priv.Privileges[0].Attributes:=SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(nil,'SeDebugPrivilege',Priv.Privileges[0].Luid);
        AdjustTokenPrivileges(hToken,false,Priv,SizeOf(Priv),PrivOld,cbPriv);
        hProcess:=OpenProcess(PROCESS_TERMINATE,false,KillProc);
        dwError:=GetLastError;
        cbPriv:=0;
        AdjustTokenPrivileges(hToken,false,PrivOld,SizeOf(PrivOld),nil,cbPriv);
        CloseHandle(hToken);
    end;

    if TerminateProcess(hProcess,$FFFFFFFF) then
    begin
        Result := True;
    end
    else
    begin
        Result := False;
    end;
end;

procedure RecursiveDir(Root: PVirtualNode; List: TStrings);
var
    Node : PVirtualNode;
    Data : PVSTPath;
begin
    Node := Root;
    if node = nil then exit;
    while Node <> nil do begin
        if Node.CheckState = csCheckedNormal then begin
            //if PVSTPath(MainForm.PathView.GetNodeData(Node)).Path = '\\MEMORY' then begin
            //    List.Add('\\MEMORY');
            //    MainForm.GetProcessList(List);
            //end else
                List.Add(PVSTPath(MainForm.FolderTreeView.GetNodeData(Node)).Path)
        end
        else
            if Node.CheckState = csMixedNormal then
                if Node.ChildCount > -1 then
                    RecursiveDir(Node.FirstChild, List);

        Node := Node.NextSibling;
    end;
end;

procedure OpenAlert(virusname:string; filename: string);
begin
  with RTP do //namaformnya
  begin
    lblvirus.caption := virusname; //text di form nya
    lblfile.caption := filename;
    FormStyle := fsStayOnTop;
    ShowModal;
    Application.RestoreTopMosts ;
  end;
end;

function TMainForm.DiskInDrive(const Drive: char): Boolean;
var
    DrvNum: byte;
    EMode : Word;
begin
    result := false;
    DrvNum := ord(Drive);
    if DrvNum >= ord('a') then
        dec(DrvNum, $20);
    EMode := SetErrorMode(SEM_FAILCRITICALERRORS);
    try
        if DiskSize(DrvNum - $40) <> -1 then
            result := true;
    finally
        SetErrorMode(EMode);
    end;
end;

Procedure ExpandFileinFolder(Dir:String; Node: PVirtualNode);
Var
    SR        : TSearchRec;
    FindRes   : Integer;
    Root      : PVirtualNode;
    CurNode   : PVirtualNode;
    Data      : PVSTPath;
begin
    FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
    While FindRes = 0 do
    begin
        if FileExists(Dir+SR.Name) then
        begin
            Root := MainForm.FolderTreeView.AddChild(Node);
            Root.CheckType := ctTriStateCheckBox;
            Root.CheckState := Node.CheckState;
            if not (vsInitialized in Root.States) then
                MainForm.FolderTreeView.ReinitNode(Root, False);
            (* *)
            Data := MainForm.FolderTreeView.GetNodeData(Root);
            Data.PathName := Sr.Name;
            Data.Path     := Dir + Sr.Name;
            Data.img      := -1;
            Data.Hiden    := IsPathHiden(Dir + Sr.Name);
            Data.System   := IsFileSystem(Dir + Sr.Name);
            (* *)
        end;
        FindRes:=FindNext(SR);
    end;
    FindClose(SR);
end;

//fungsi untuk menampilkan sub dir di TVirtual TreeView
Procedure ExpandFolder(Dir:String; Node: PVirtualNode);
Var
    SR        : TSearchRec;
    FindRes   : Integer;
    Root      : PVirtualNode;
    child     : PVirtualNode;
    Data      : PVSTPath;
begin
    
    FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
    While FindRes=0 do
    begin
        if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then
        begin
            FindRes:=FindNext(SR);
            Continue;
        end;
        if ((SR.Attr and faDirectory)=faDirectory) then
        begin
            (* *)
            Root := MainForm.FolderTreeView.AddChild(Node);
            Root.CheckType := ctTriStateCheckBox;
            Root.CheckState := Node.CheckState;
            if not (vsInitialized in Root.States) then
                MainForm.FolderTreeView.ReinitNode(Root, False);
            (* *)
            Data := MainForm.FolderTreeView.GetNodeData(Root);
            Data.PathName := Sr.Name;
            Data.Path     := Dir + Sr.Name + '\';
            Data.img      := 1; //-1
            Data.Hiden    := IsPathHiden(Dir + Sr.Name + '\');
            Data.System   := false;
            (* *)
            child := MainForm.FolderTreeView.AddChild(root);
            Data := MainForm.FolderTreeView.GetNodeData(child);
            Data.PathName := 'nil';
            (* *)
            FindRes := FindNext(SR);
            Continue;
        end;
        FindRes:=FindNext(SR);
    end;
    FindClose(SR);
end;

procedure CreateDrivesList;
var
    Bufer : array[0..1024] of char;
    RealLen, i : integer;
    S : string;

    root  : PVirtualNode;
    child : PVirtualNode;
    data  : PVSTPath;
    //icon  : ticon;
    list  : tlist;
begin

    MainForm.FolderTreeView.Clear;
    RealLen := GetLogicalDriveStrings(SizeOf(Bufer),Bufer);
    i := 0; S := '';
    (* MEMORY *)
    //Root := MainForm.PathView.AddChild(MainForm.PathView.RootNode);
    //Root.CheckType := ctTriStateCheckBox;
    //if not (vsInitialized in Root.States) then
    //    MainForm.PathView.ReinitNode(Root, False);
    //Data := MainForm.PathView.GetNodeData(Root);

    //Data.PathName := 'Memory';
    //Data.Path     := '\\MEMORY';
    //Data.Hiden    := false;
    //Data.System   := false;

    //icon := TIcon.Create;
    //if FileExists(ExtractFilePath(paramstr(0))+'Images\scanmem.ico') then begin
    //    icon.LoadFromFile(ExtractFilePath(paramstr(0))+'Images\scanmem.ico');
    //    SysImageList.AddIcon(icon);
    //    Data.img := SysImageList.Count - 1;
    //end;
    //icon.Free;

    while i < RealLen do begin
        if Bufer[i] <> #0 then begin
            S := S + Bufer[i];
            inc(i);
        end else begin
            inc(i);
            (* *)
            Root := MainForm.FolderTreeView.AddChild(MainForm.FolderTreeView.RootNode);
            Root.CheckType := ctTriStateCheckBox;
            if not (vsInitialized in Root.States) then
                MainForm.FolderTreeView.ReinitNode(Root, False);
            (* *)
            Data := MainForm.FolderTreeView.GetNodeData(Root);
            Data.PathName := S;
            Data.Path     := S;
            Data.img      := 1; //-1
            Data.Hiden    := false;
            (* *)
            if MainForm.DiskInDrive(S[1]) then begin
                child := MainForm.FolderTreeView.AddChild(root);
                Data := MainForm.FolderTreeView.GetNodeData(child);
                Data.PathName := 'nil';
            end;
            (* *)
            S := '';
        end;
    end;
end;

{$R *.dfm}

procedure TMainForm.FormCreate(Sender: TObject);
var
    SysSIL  : THandle;
    BtnSIL  : THandle;
    SFI     : TSHFileInfo;

begin
    DelphiReg := TRegistry.Create;
    //drive protection
    DriveList := TStringList.Create;
    sDrives := TStringList.Create;
    {set systray}
    FWindowHandle := AllocateHWnd(WndProc);
    IconData.cbSize := SizeOf(TNOTIFYICONDATA);
    IconData.wnd := FWindowHandle;
    IconData.uID := 0;
    IconData.uFlags := NIF_MESSAGE + NIF_ICON + NIF_TIP;
    IconData.hIcon := Application.Icon.Handle;
    StrPCopy(IconData.szTip, ' N-Shield AntiVirus 9.0 ');
    IconData.uCallbackMessage := WM_USER + 1;
    Shell_NotifyIcon(NIM_ADD, @IconData);

    //set debug
    SHGetFileInfo(PChar(NShieldGetSysDir + 'services.exe'), 0, SFI, SizeOf(TSHFileInfo), SHGFI_ICON or SHGFI_SMALLICON or SHGFI_SYSICONINDEX);

    FolderTreeView.NodeDataSize := SizeOf(TVSTPath);
    SysImageList := TImageList.Create(self);
    FolderTreeView.Images := FolderImages;

    lblenginever.Caption := NShield_Get_Engine_Version;
    CreateDrivesList;
    BukaSettingan;
    Options.FilterString         := '.*';
    //Options.FileSizeLimit        := 512;   //aslinya 1024 MB/ 1GB
    Options.ArchiveLimit         := 10;

    //buat mailslot untuk anti keylogger
    if not MailSlotCreate(slot) then exit;

    //cek bugreport.txt
    //if sysutils.FileExists((PChar(ExtractFilePath(Application.ExeName) + 'bugreport.txt'))) then
    //begin
    //messagebox(0,'Dear user, N-Shield AntiVirus still have bug report, please send the bug report file to developer', ' N-Shield AntiVirus', MB_ICONINFORMATION);
    //end;

    NShield_Start_Engine(ENGINE2, @NShieldScandbg_dua);
    NShield_Get_VBD_Dir(ENGINE2,pchar(NShieldDatabase),Options.UseUserDataBases);
    lblsigcount.Caption := inttostr(Nshield_Get_VirusCount(ENGINE2));
    //jangan di free engine, karena menyebabkan scan single file tdk bisa dijalankan
    //NShield_Stop_Engine(ENGINE2);
    //FreeMem(ENGINE2);

    if lblsigcount.Caption = '0' then
    begin
    messagebox(0, 'Database is Corrupt or Missing', 'N-Shield AntiVirus',MB_ICONERROR);
    application.Terminate;
    end;

    if Options.AntiKeylogger = true then
       begin
           if not IsWinNt then begin
           MessageBox(0,'sorry, this feature is not supported for your Windows','N-Shield AntiVirus',MB_ICONERROR);
           Exit;
           end;
           //if not IsFileExist(DllName) then begin
           //MessageBox(0,Pchar('ERROR!! File not found : '+DllName),'N-Shield AntiVirus',MB_ICONERROR);
           //Exit;
           //end;
    ShellExecute(0,'open','navmon.exe','','',0);
    InjectAllProc(GetPath(ParamStr(0))+DllName);
    Timer1.Enabled := true;
    end;

  //cek startup
  DelphiReg.RootKey := HKEY_LOCAL_MACHINE;
  DelphiReg.OpenKey('Software\Microsoft\Windows\CurrentVersion\Run', true);
  if Options.RunStartup then DelphiReg.WriteString('N-Shield AntiVirus', Application.ExeName) else DelphiReg.DeleteValue('N-Shield AntiVirus');

  //hide form [?]
  //MainForm.Hide;

 //cek apakah user ingin menginstall self defense modul / anti kill
 if options.SelfDefense = true then
 begin
 StartGuard(GetCurrentProcessId);
 end
 else
 //nothing

 if options.ScanHidden = true then
 begin
    UnloadHooked('ntdll.dll', 'NtQueryDirectoryFile');
    UnloadHooked('ntdll.dll', 'ZwQueryDirectoryFile');
    UnloadHooked('ntdll.dll', 'NtEnumerateValueKey');
    UnloadHooked('ntdll.dll', 'ZwEnumerateValueKey');
    UnloadHooked('ntdll.dll', 'NtResumeThread');
    UnloadHooked('ntdll.dll', 'ZwResumeThread');
 end;

    btnPausescan.Enabled  := False;
    btnSaveReport.Enabled := true;
    btnStopscan.Enabled   := False;
    baca_file_karantina;

 IF isDBexpired(lbldbupdate.Caption) = true then
 begin
 messagebox(0, 'WARNING - Database is Expired. Please Update as soon as possible', ' N-Shield AntiVirus ', mb_iconwarning);
 end;

 if options.AutoUpdate = true then
 begin
    IF isDBexpired(lbldbupdate.Caption) = true then
    begin
        doDownload;
  end;
  end;

  if options.RTP = true then
  begin
  protection_on;
  end;


  lblmemusage.Caption := formatfloat('# MB', CurrentMemoryUsage / 1024 / 1024) ;
    //test 3 mei 2014  ,jika di non-aktifkan,scan single file dan RTP not working
    MainForm.Scanner := TAvScanner.Create(true);
    MainForm.Scanner.Dirs := TStringList.Create;
    MainForm.Scanner.Memscan := false;
     {jika diaktifkan, scan single file dapat bekerja dgn baik, tapi label file scanning
     akan error [?] }
    //MainForm.Scanner.Resume;
end;

procedure TMainForm.ApplicationException(Sender: TObject; E: Exception);
begin
    //status('N-Shield ERROR.. !!');
    //showmessage(E.Message);
    raise Exception.Create('ERROR');
end;

procedure TMainForm.FolderTreeViewGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: WideString);
var
    Data: PVSTPath;
begin
    Data := Sender.GetNodeData(Node);
    if Assigned(Data) then
        CellText := Data.PathName;
end;

procedure TMainForm.FolderTreeViewExpanding(Sender: TBaseVirtualTree;
  Node: PVirtualNode; var Allowed: Boolean);
var
    root: PVirtualNode;
    data: PVSTPath;
begin
    if node.ChildCount = 0 then exit;
    Data := Sender.GetNodeData(Node.FirstChild);
    if Data.PathName = 'nil' then begin
        FolderTreeView.DeleteChildren(node,true);
        Data := Sender.GetNodeData(Node);
        if Assigned(Data) then begin
            FolderTreeView.BeginUpdate;

            //di properties, cek sortdirection = ascending
            FolderTreeView.Sort(Node,0,sdAscending); //ascending
            ExpandFolder(Data.Path, Node);
            //PathView.Sort(Node,1,sdAscending); //ascending
            //ShowSubFiles(Data.Path, Node);
            FolderTreeView.EndUpdate;
        end;
    end;
end;

procedure TMainForm.FolderTreeViewGetImageIndex(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: Integer);
var
    data: PVSTPath;
    FileInfo : TSHFileInfo;
begin
    Data := Sender.GetNodeData(Node);
    if Assigned(Data) then
        if Data.img = -1 then
        begin
            ImageIndex := GetSmallIconIndex(Data.Path, 0);
            data.img := ImageIndex;
        end else
            ImageIndex := data.img;
end;

procedure TMainForm.FolderTreeViewFreeNode(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
var
    Data: PVSTPath;
begin
    Data := Sender.GetNodeData(Node);
    if Assigned(Data) then
        Finalize(Data^);
end;

procedure TMainForm.FolderTreeViewCompareNodes(Sender: TBaseVirtualTree; Node1,
  Node2: PVirtualNode; Column: TColumnIndex; var Result: Integer);
begin
    with TVirtualStringTree(Sender) do
    Result := AnsiCompareText(Text[Node2, Column], Text[Node1, Column]);
end;

procedure TMainForm.FolderTreeViewCollapsing(Sender: TBaseVirtualTree;
  Node: PVirtualNode; var Allowed: Boolean);
begin
    Sender.FullCollapse(Node);
end;

procedure TMainForm.FolderTreeViewResize(Sender: TObject);
begin
    FolderTreeView.BackgroundOffsetY := FolderTreeView.Height - FolderTreeView.Background.Height - 25;
    FolderTreeView.BackgroundOffsetX := FolderTreeView.Width  - FolderTreeView.Background.Width - 25;
end;

procedure TMainForm.FolderTreeViewDrawText(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  const Text: WideString; const CellRect: TRect; var DefaultDraw: Boolean);
var
    data: PVSTPath;
    tw: integer;
begin
    if node = nil then exit;

    data := FolderTreeView.GetNodeData(node);
    if data <> nil then begin
        if data.System then begin
            tw := TargetCanvas.TextWidth(text);
        end;
        if not (vsSelected in node.States) then begin
            case data.Hiden of
            True  : TargetCanvas.Font.Color := $00535353;
            False : TargetCanvas.Font.Color := clBlack;
            end;
        end else TargetCanvas.Font.Color := clWhite;
    end;
end;

procedure TMainForm.FolderTreeViewMouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
    pw_x := x;
    pw_y := y;
end;

procedure TMainForm.BtnScanClick(Sender: TObject);
begin
    ListView1.Clear;
    lvhiddenfiles.Clear;
   
    MainForm.Scanner := TAvScanner.Create(true);

    //mempersiapkan file yang akan di scan
    MainForm.Scanner.Dirs := TStringList.Create;;

    //atur scan memory menjadi false terlebih dahulu
    MainForm.Scanner.Memscan := false;

    //list file yang di generate disimpan di variabel Dirs
    RecursiveDir(FolderTreeView.GetFirst, MainForm.Scanner.Dirs);

    //cek dulu apakah directory sudah dipilih
    if MainForm.Scanner.Dirs.Count = 0 then
    begin
         showmessage('Please choose any directory to scan');
         exit;
    end
    else

        //jika opsi scan memory di aktifkan maka sacn memory
        if chkscanmem.Checked = true then
            begin
              MainForm.Scanner.Memscan := true;
            end;

    //if MainForm.Scanner.Dirs.Count > 0 then
    //    if MainForm.Scanner.Dirs[0] = '\\MEMORY' then begin
    //        MainForm.Scanner.Memscan := true;
    //        MainForm.Scanner.Dirs.Delete(0);
    //    end;
    (* *)
          MainForm.Scanner.Resume;
          pagecontrol2.ActivePage := tabsheet6;
          lblfilescanning.Caption := 'Starting engine..please wait =) ';
end;

procedure TMainForm.BtnRefreshClick(Sender: TObject);
begin
    CreateDrivesList;
end;


procedure TMainForm.BtnFilterAddClick(Sender: TObject);
var
    ext: string;
begin
    ext := InputBox('Add Filter','Select:','');
    if ext <> '' then begin
        listfilter.Items.Add(ext);
    end;
end;

procedure TMainForm.BtnFilterRemoveClick(Sender: TObject);
begin
listfilter.DeleteSelected;
end;


procedure TMainForm.btnBrowseDBClick(Sender: TObject);
var
    F: String;
begin
    if SelectDirectory('Select Dir:',SpecialFolder(CSIDL_DRIVES),F) then
    begin
        TxtDatabase.Text := F;
    end;
end;



procedure TMainForm.btnbrowsereportClick(Sender: TObject);
begin
if SaveDialog.Execute then
        TxtReport.Text := SaveDialog.FileName;
end;



procedure TMainForm.btnSaveClick(Sender: TObject);
begin
 SimpanSettingan;
 MessageDlg('All Settings Has Been Saved Succesfully, Please restart N-Shield',mtInformation,[mbOK],0);
end;

procedure TMainForm.btntrayClick(Sender: TObject);
begin
MainForm.Hide;
end;

//dimodifikasi untuk RTP scan (aslinya untuk anti-keylogger)
procedure TMainForm.Timer1Timer(Sender: TObject);
var
a : Tlistitem;
sementara,teksnya : string;
begin
  if MailSlotRead(slot,msg) then begin
    a := LVRTP.Items.Add;
    a.caption := 'Detected';
    a.Data:= Pointer(clLime);

    a.SubItems.Add(inttostr(msg.Pid));
    a.SubItems.add(GetPathFromPID(MSG.Pid));
    a.SubItems.Add(msg.Apicall);
    Timer1.Enabled := false;  //matiin dulu timernya
    sementara := GetPathFromPID(MSG.Pid);
    label8.Caption := sementara;
    
    teksnya := ' : is a keylogger, do you want to terminate it?';

    if MessageBox(0,pchar(sementara + teksnya), 'N-Shield AntiVirus', MB_ICONQUESTION or MB_YESNO or MB_TASKMODAL or MB_TOPMOST) = ID_YES then
    begin
    TerminateProcess(OpenProcess(PROCESS_TERMINATE,Bool(1),msg.pid),0);
    Timer1.enabled := true;
    end else
    Timer1.enabled := true;
  end;
end;

procedure TMainForm.FormClose(Sender: TObject; var Action: TCloseAction);
begin
mainform.Hide;

end;

procedure TMainForm.btnpausescanClick(Sender: TObject);
begin
if Assigned(Scanner) then begin
        if not Scanner.Suspended then begin
            Scanner.Suspend;
            btnPausescan.Caption := 'Resume';
        end
        else begin
            Scanner.Resume;
            btnPausescan.Caption := 'Pause';
        end;
    end;
end;

//==============================================================================
//Fungsi untuk menyimpan log scanning dengan format *.rtf
//==============================================================================
procedure TMainForm.BtnSaveReportClick(Sender: TObject);
begin
    if SaveDialog1.Execute then begin

        //simpan text pada memo report ke file
        Memoscanreport.Lines.SaveToFile(SaveDialog1.FileName);
    end;
end;

//==============================================================================
//fungsi untuk menghentikkan thread scanner
//==============================================================================
procedure TMainForm.btnstopscanClick(Sender: TObject);
begin

//tanya dulu =))
if MessageDlg('Do you really want to stop scanning?', mtConfirmation, [mbYes, mbNo], 0) = IDYes then
 begin
    case btnStopscan.Tag of
        0 : if Assigned(Scanner) then
                Scanner.Hentikan;
    end;
    end;
end;

procedure TMainForm.btnwebsiteClick(Sender: TObject);
begin
ShellExecute(0,'open','http://yudha.binushacker.net','','',1);
end;

procedure TMainForm.ExitPopupMenuClick(Sender: TObject);
var logni,logtu,jam : string;
begin
jam := timetostr(gettime);
logni := NShieldpath + 'exception.log';
logtu := 'exception-'+jam+'-.log';
 if MessageDlg('Do you really want to close N-Shield AntiVirus?', mtConfirmation, [mbYes, mbNo], 0) = IDYes then
 begin
      //cek apakah file exception.log terisi oleh log
      if ExGetFileSize(logni) > 0 then
      begin
      showmessage('N-Shield has an exception log report, please send it to nshieldlabs@gmail.com');
          if CopyFile(pchar(logni),pChar(NShieldbug+logtu), true) then
             begin
             DeleteFile(logni);
             end;
      end;
 application.Terminate;
 finalize(VirusList);

 Shell_NotifyIcon(NIM_DELETE, @IconData);

 if options.AntiKeylogger then
 begin
 UnInjectAllProc(GetPath(ParamStr(0))+DllName);
 end;

  if options.RTP = true then
  begin
  protection_off;
  end;

 if options.SelfDefense then EndGuard;
 end;

end;



procedure TMainForm.btnDeleteClick(Sender: TObject);
Var
i,j,k :Integer;
OffsetVX_HTML : integer;
Offset : integer;
Buf : string;
PE : TPeFile;
RawData : Cardinal;
Sec : byte;
VirusSign : ansistring;
VirusSignLength : integer;

const
VSIG  : array [0..3] of string = (
  '5B2B2B2B73636172666163652B2B2B5D',
  {
      Dorifel.A
      -------------------- signature diambil dari bagian ini ----------------------------
         Offset    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   Ascii

        00025000  00 5B 2B 2B 2B 73 63 61 72 66 61 63 65 2B 2B 2B  .[+++scarface+++
        00025010  5D                                               ]
      -----------------------------------------------------------------------------------
  }

  '5B2D2D2D7A786667746862762D2D2D5D',
  {
      Dorifel.B
      -------------------- signature diambil dari bagian ini ----------------------------

         Offset    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   Ascii

        0003F200  00 5B 2D 2D 2D 7A 78 66 67 74 68 62 76 2D 2D 2D  .[---zxfgthbv---
        0003F210  5D                                               ]

      -----------------------------------------------------------------------------------
  }
  '5B2D2D2D7A786667746862762D2D2D5D', // sama dengan Dorifel.B tetapi beda offset
  '5B2B2B2B73636172666163652B2B2B5D'  // sama dengan Dorifel.A tetapi beda offset
  );

KEY : array[0..3] of string = (

  '0D0A050F597B385A5B3631697E0D0D09',  // <-- nilai hexa key ini dapat di-search di body virus
  '325A030B096F212C08211236421F0C0D',

      {
      pilihan key untuk Dorifel.B:
      0x325A030B096F212C08211236421F0C0D
      0x380922734F0B372D59170F3BA6216F03
      (credit to: Fabian Woser/EmsiSoft)
      }

  '380922734F0B372D59170F3BA6216F03',
  '325A030B096F212C08211236421F0C0D'
  );

  RAW_SIZE : array[0..3] of integer = (
  $7A00,  // raw size .rsrc file host Dorifel.A: 0x7A00
  $6800,  // raw size .rsrc file host Dorifel.B: 0x6800
  $8600,  // raw size .rsrc file host Dorifel.C: 0x8600
  $23000  // raw size .rsrc file host Dorifel.D: 0x23000
  );

  VX_OFFSET : array[0..3] of integer = (
   $25001,
   $3F201,
   $25C01,
   $5C601
  );

  VX_NAME : array[0..3] of string = (
   'Dorifel.A',
   'Dorifel.B',
   'Dorifel.C',
   'Dorifel.D'
  );
ID_LENGTH = 16;

//untuk virus annie
VX_HTML : array [0..1] of string =
    (
     '3C68746D6C3E0A3C73637269707420747970653D22746578742F6A617661736372697074223E0A3C212D2D0A7661722061796670363D6E657720416374697665584F626A6563742827536372697074696E672E46696C6553797374656D4F626A65637427293B76617220646B3568383D6E657720416374697665584F626A',
     '3C68746D6C3E0D0A3C73637269707420747970653D22746578742F6A617661736372697074223E0D0A3C212D2D0D0A696628286E6176696761746F722E6170704E616D65213D224D6963726F736F667420496E7465726E6574204578706C6F72657222292626286E6176696761746F722E61707056657273696F6E2E696E'
    );
//end

begin

   For i:=0 to ListView1.Items.Count -1 do
    If ListView1.Items[i].Checked then //begin
      if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Smellsme' then
      begin
      NShield_Heal_Smellsme(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Cleaned'
      end

      //heal file HTML terinfeksi annie
      else if ListView1.Items[i].SubItems[0] = 'Virus.HTML.Annie' then
      begin
      Buf := NShield_FileToString(ListView1.Items[i].SubItems[1]);

      for j := Low(VX_HTML) to High(VX_HTML) do
      begin
        OffsetVX_HTML := NShield_BM_SearchString(NShield_HexStrToStr(VX_HTML[j]), Buf, 1);
        if  OffsetVX_HTML > 0 then
        begin
                NShield_Heal_Annie_HTML(ListView1.Items[i].SubItems[1],  OffsetVX_HTML - 1);
                ListView1.Items[i].Caption := 'Cleaned';
        end;
      end;
      end
      //selesai

      else if ListView1.Items[i].SubItems[0] = 'Hidden Process' then
      begin
      killprocess(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Terminated';
      end

      else if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Dorifel' then
      begin
      {
           --------------------------------------------------------------------------------
           ambil RawSize section .rsrc
           karena sebagian *.exe yang terinfeksi memiliki offset pattern yang berbeda
           jadi harus dicari dulu offset yang tepat dengan membaca raw size section .rsrc
           --------------------------------------------------------------------------------
          }
          RawData := PE.ImageSections[Sec].SizeOfRawData;

          for k := Low(VX_Name) to High(VX_Name) do
          begin

            Offset := VX_OFFSET[k] + RawData - RAW_SIZE[k];
            VirusSign := NShield_HexStrToStr(VSIG[k]);
            VirusSignLength := Length(NShield_HexStrToStr(VSIG[k]));
            if ScanPatternAtOffset(ListView1.Items[i].SubItems[1], VirusSign, VirusSignLength, Offset ) then
            begin
            NShield_Heal_Dorifel(ListView1.Items[i].SubItems[1], Offset + ID_LENGTH, KEY[k] );
            ListView1.Items[i].Caption := 'Cleaned';
            end;
      end;
      end

      else if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Ramnit.K' then
      begin
      NShield_Heal_Ramnit_B(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Cleaned';
      end

      else if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Ramnit.I' then
      begin
      NShield_Heal_Ramnit_B(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Cleaned';
      end
      {if ListView1.Items[i].SubItems[0] = 'Virus.Win32.Mumawow' then
      begin
      NShield_Heal_Mumawow(ListView1.Items[i].SubItems[1]);
      DeleteFile(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Cleaned';
      end;    }

      else
      begin
      DeleteFile(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Deleted';
      end;
end;

procedure TMainForm.btnscansingleClick(Sender: TObject);
var
ret,mf,ma : integer;
Opt: myscan_options;
vn: pchar;
a : tlistitem;
begin
ListView1.Clear;
    pagecontrol1.ActivePage := tabsheet2;
    pagecontrol2.ActivePage := tabsheet6;
    lblfilescanning.Caption := 'Finished';
    lblfilescanned.Caption := '1';

    opt := [];
    if Options.OptimizeScan then
        opt := opt + [pindai_pe]
    else begin
        opt := opt + [pindai_pdf, pindai_gambar, pindai_pe, pindai_lainnya];
    end;
    if Options.ScanArchives then begin
        opt := opt + [pindai_rar, pindai_zip];
    end;
    if Options.Whitelist then begin
        opt := opt + [pindai_force];
    end;
    //mf := (1024 * 1024) * strtoint(Options.FileSizeLimit);
    mf := (1024 * 1024) * strtoint(MainForm.txtFilterSize.Text);
    //showmessage(inttostr(mf));
    ma := (1024 * 1024) * Options.ArchiveLimit;
    NShield_Config(ENGINE2, opt, mf, ma, pchar(NShieldTemp));
    ret := NShield_Match_File(ENGINE2, pchar(txtFile.Text), vn, ScanProgress, NShieldScandbg_dua,true);
                (* *)
                if ret = BERVIRUS then begin
                    lblviruscount.Caption := '1';
                    status(format('%s - %s',[txtFile.Text, vn]));
                        a := MainForm.listview1.Items.Add;
                        a.caption := 'Detected';
                        a.SubItems.Add(vn);
                        a.SubItems.add(txtFile.Text);
                        exit;
                    end else
                    lblviruscount.Caption := '0';
                    //showmessage('bersih');
end;

procedure TMainForm.txtFileClick(Sender: TObject);
begin
if not OpenFileScan.execute then exit;
   txtFile.Text  := OpenFileScan.FileName;
end;

procedure TMainForm.BtnClearAllClick(Sender: TObject);
begin
    MemoscanReport.Clear;
    DeleteFile(NShieldReport);
end;

procedure TMainForm.LogoffPopupMenuClick(Sender: TObject);
begin
MainForm.Show;
end;

procedure TMainForm.Protection_ON;
var
  Flags:Cardinal;
begin

//sentinel
{
FILE_NOTIFY_CHANGE_FILE_NAME        = $00000001;//изменение имени файла
FILE_NOTIFY_CHANGE_DIR_NAME         = $00000002;//изм. имени папки
FILE_NOTIFY_CHANGE_ATTRIBUTES       = $00000004;//атрибутов файла
FILE_NOTIFY_CHANGE_SIZE             = $00000008;//размера
FILE_NOTIFY_CHANGE_LAST_WRITE       = $00000010;//последней записи
FILE_NOTIFY_CHANGE_LAST_ACCESS      = $00000020;//последнего доступа
FILE_NOTIFY_CHANGE_CREATION         = $00000040;//создания
FILE_NOTIFY_CHANGE_SECURITY         = $00000100;//прав доступа
}
Flags:=0;
if CheckBox2.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_FILE_NAME;
if CheckBox3.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_DIR_NAME;
if CheckBox4.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_ATTRIBUTES;
if CheckBox5.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_SIZE;
if CheckBox6.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_LAST_WRITE;
if CheckBox7.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_LAST_ACCESS;
if CheckBox8.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_CREATION;
if CheckBox9.Checked then Flags:=Flags or FILE_NOTIFY_CHANGE_SECURITY;

StartWatch(txtDriveRTP.Text, Flags, CheckBox1.Checked, @MyInfoCallBack);
lblrtpstatus.Caption := 'ON';
imgrtpoff.Visible := false;
imgrtpon.Visible := true;                                                                                                                                                                                                                                                                           //включая подкаталоги
//StartWatch('C:\', Flags, CheckBox1.Checked, @MyInfoCallBack);
end;

procedure TMainForm.Protection_OFF;
begin
StopWatch;
lblrtpstatus.Caption := 'OFF';
imgrtpon.Visible := false;
imgrtpoff.Visible := true;
end;


procedure TMainForm.btnselectallClick(Sender: TObject);
var
i : integer;
begin
For i:=0 to ListView1.Items.Count -1 do
    ListView1.Items[i].Checked:= true;
end;

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
CanClose := False;
MainForm.Hide;
end;


procedure TMainForm.MenuSettings1Click(Sender: TObject);
begin
MainForm.Show;
MainForm.PageControl1.ActivePage := Tabsheet3;
end;

procedure TMainForm.MnuUpdate1Click(Sender: TObject);
begin
MainForm.Show;
MainForm.PageControl1.ActivePage := Tabsheet9;
end;

procedure TMainForm.BtnUnhideClick(Sender: TObject);
var
i : integer;
begin
For i:=0 to Lvhiddenfiles.Items.Count -1 do
    If Lvhiddenfiles.Items[i].Checked then begin
    SetFileAttributes( pchar(Lvhiddenfiles.Items[i].SubItems[0]),FILE_ATTRIBUTE_NORMAL);
    Lvhiddenfiles.Items[i].Caption := 'Normalized';
    end;
end;


procedure TMainForm.btnselallvirusClick(Sender: TObject);
var
i: integer;
begin
For i:=0 to ListView1.Items.Count -1 do
ListView1.Items[i].Checked:= true;
end;

procedure TMainForm.btnselallhddenClick(Sender: TObject);
var
i : integer;
begin
For i:=0 to Lvhiddenfiles.Items.Count -1 do
Lvhiddenfiles.Items[i].Checked:= true;
end;

procedure TMainForm.btnHelpClick(Sender: TObject);
begin
ShellExecute(0,'open','readme.txt','','',1);
end;

procedure TMainForm.btnquarantineClick(Sender: TObject);
var
i : integer;
filenya,namanya : string;
Kunci: TWordTriple;
begin
Kunci [0]:= 111;
Kunci [1]:= 222;
Kunci [2]:= 333;

filenya := NShieldQuarantine;

For i:=0 to ListView1.Items.Count -1 do
    If ListView1.Items[i].Checked then begin

      if ListView1.Items[i].SubItems[0] = 'Hidden Process' then
      begin
      killprocess(ListView1.Items[i].SubItems[1]);
      ListView1.Items[i].Caption := 'Terminated';;
      end;

      //if not DirectoryPresent(NShieldQuarantine) then
        //  CreateDir(NShieldQuarantine);

      //if DirectoryExists(NShieldQuarantine) then begin
      namanya := ExtractFileName(ListView1.Items[i].SubItems[1]);

         if CopyFile(pChar(ListView1.Items[i].SubItems[1]),pChar(filenya+namanya), true) then
             begin
               FileEncrypt(filenya+namanya, filenya+namanya+'.qua',kunci );

               lbqua.Items.Add(filenya+namanya+'.qua');
               lbqua.Items.SaveToFile(NShieldPath+'quarantine.ini');
               DeleteFile(filenya+namanya);
               DeleteFile(ListView1.Items[i].SubItems[1]);
               ListView1.Items[i].Caption := 'Quarantined';
              end else
              messagebox(0, 'ERROR - Cannot move file to Quarantine', ' N-Shield AntiVirus', mb_iconerror);
    End;
end;

procedure TMainForm.TabSheet8Show(Sender: TObject);
begin
lbllquacount.Caption := IntToStr(LBQUA.Items.Count);
end;

procedure TMainForm.btnrestorequaClick(Sender: TObject);
var
filequa,pathkembali : String;
Kunci: TWordTriple;
begin
Kunci [0]:= 111;
Kunci [1]:= 222;
Kunci [2]:= 333;

if not SaveDialog1.execute then exit;
   pathkembali  := SaveDialog1.FileName;

filequa := Lbqua.Items.Strings[Lbqua.ItemIndex]; //Gets Selected String In The ListBox
FileDecrypt(filequa,pathkembali, kunci);
DeleteFile(filequa);
Lbqua.DeleteSelected;
MessageBox(0,'File Restored', ' N-Shield AntiVirus ', MB_ICONINFORMATION);
lbqua.Items.SaveToFile(NShieldPath+'quarantine.ini');
lbllquacount.Caption := IntToStr(LBQUA.Items.Count);
end;


procedure TMainForm.btndelquaClick(Sender: TObject);
var
filequa: String;
begin

filequa := Lbqua.Items.Strings[Lbqua.ItemIndex]; //Gets Selected String In The ListBox
DeleteFile(filequa);
Lbqua.DeleteSelected;
MessageBox(0,'File Deleted', ' N-Shield AntiVirus ', MB_ICONINFORMATION);
lbqua.Items.SaveToFile(NShieldPath+'quarantine.ini');
lbllquacount.Caption := IntToStr(LBQUA.Items.Count);
end;



procedure TMainForm.Label35Click(Sender: TObject);
begin
ShellExecute(0,'open','https://www.facebook.com','','',1);
end;


procedure TMainForm.btndownloadClick(Sender: TObject);
var
sizex : string;
begin
lbldownload.caption := 'Downloading..';
sizex := GetUrlInfo(HTTP_QUERY_CONTENT_LENGTH, 'http://nshieldantivirus.url.ph/UpdateDB/update.vdb');
delete(sizex, length(sizex), 1);
lblsize.caption := sizetostr(strtoint(sizex));
//sleep(5000);
if lblsize.Caption <> '0' then
doDownload
else
lbldownload.caption := 'FAILED - Not Connected to Update Server';

end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  DriveList.Free ;
end;

procedure TMainForm.DriveProTimer(Sender: TObject);
begin
  ScanDrives(sDrives);
  Application.ProcessMessages ;
  DeteksiAutorun(sDrives);
end;

procedure TMainForm.btncurelistClick(Sender: TObject);
begin
ShellExecute(0,'open','readme.txt','','',1);
//CureList.Form2.ShowModal;
end;

procedure TMainForm.PageControl1Changing(Sender: TObject;
  var AllowChange: Boolean);
begin
//AllowChange := PageControl1.ActivePage.PageIndex+1);
end;

procedure TMainForm.TimerMemUsageTimer(Sender: TObject);
begin
lblmemusage.Caption := formatfloat('# MB', CurrentMemoryUsage / 1024 / 1024) ;
end;

procedure TMainForm.imgfbClick(Sender: TObject);
begin
ShellExecute(0,'open','http://www.facebook.com/yudhatp07','','',1);
end;

procedure TMainForm.btnQuickScanClick(Sender: TObject);
begin
ListView1.Clear;
    lvhiddenfiles.Clear;
    pagecontrol1.ActivePage := tabsheet2;
    pagecontrol2.ActivePage := tabsheet6;

    (* start scanning by selectoin *)
    MainForm.Scanner := TAvScanner.Create(true);
    MainForm.Scanner.Dirs := TStringList.Create;
    MainForm.Scanner.Memscan := true;

    Mainform.processlistthread := TProcessList.Create(true);

    //isi Dirs dengan semua file pada process

    Mainform.processlistthread.GetProcessList(MainForm.Scanner.Dirs);   //GetProcessList

    MainForm.Scanner.Resume;
    if options.SmartScan = true then
    begin
    ScanMutex;
    end;

    if options.ScanHiddenProc = true then
    begin
    GetHiddenProcessList;
    end;
end;

end.
