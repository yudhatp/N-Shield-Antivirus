{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: VCLUnZip.pas                                                      }
{     Description: VCLUnZip component - native Delphi unzip component.               }
{     Date:        March 1997                                                        }
{     Author:      Kevin Boylan, boylank@bigfoot.com                                 }
{                                                                                    }
{                                                                                    }
{ ********************************************************************************** }
unit UnZip;
{$P-}   {Added 5-26-97 KLB}
{$R-}   { 3/10/98 2.03 }
{$Q-}   { 3/10/98 2.03 }

{ $Log:  D:\Util\GP-Version\Archives\Components\VCLZip\Component Files\VCLUnZip.UFV 
{
{   Rev 1.3    Sun 29 Mar 1998   10:51:34  Supervisor    Version: 2.1
{ Version 2.1 additions
{ 
{ - Capability of 16bit VCLZip to store long filenames/paths 
{ when running on 32 bit OS.
{ - New Store83Names property to force storing short 
{ filenames and paths
{ - Better UNC path support.
{ - Fixed a bug to allow adding files to an empty archive.
}
{
{   Rev 1.2    Tue 24 Mar 1998   19:00:21  Supervisor
{ Modifications to allow files and paths to be stored in DOS 
{ 8.3 filename format.  New property is Store83Names.
}
{
{   Rev 1.1    Wed 11 Mar 1998   21:10:15  Supervisor    Version: 2.03
{ Version 2.03 Files containing many fixes
}

interface

uses
{$IFDEF WIN32}
	Windows,
{$ELSE}
	WinTypes, WinProcs,
{$ENDIF}
	SysUtils, Classes,{ Controls,}
	{Forms, Dialogs,} kpCntn, {FileCtrl,} kpMatch, KpLib, kpZipObj;

Const
  kpThisVersion = 210; {added this constant 3/1/98 for version 2.03}

type
 {$IFNDEF WIN32}
 DWORD = LongInt;
 {$ENDIF}
 TVCLUnZip = class(TComponent)
  private
    { Private declarations }
    FZipName: String;
    FDestDir: String;
    FSortMode: TZipSortMode;
	  FReCreateDir: Boolean;
    FOverwriteMode: TUZOverwriteMode;
	  FFilesList: TStrings;
    FDoAll: Boolean;
    FPassword: String;
	  FIncompleteZipMode: TIncompleteZipMode;
    FKeepZipOpen: Boolean;
    FDoProcessMessages: Boolean;
    FNumDisks: Integer;
    FRetainAttributes: Boolean;
    FThisVersion: Integer;

    { Event variables }
    FOnStartUnzipInfo: TStartUnzipInfo;
	  FOnStartUnZip: TStartUnZipEvent;
    FOnEndUnZip: TEndUnZipEvent;
    FOnPromptForOverwrite: TPromptForOverwrite;
			FOnBadPassword: TBadPassword;
    FOnBadCRC: TBadCRC;
    FOnInCompleteZip: TInCompleteZip;

  { Decrypt }
	protected
	  FOnFilePercentDone: TFilePercentDone;
	  FOnTotalPercentDone: TTotalPercentDone;
	  FOnSkippingFile: TSkippingFile;
	  FOnGetNextDisk: TGetNextDisk;
    FArchiveStream: TStream;
    FBusy: Boolean;
    FRootDir: String;
    ArchiveIsStream: Boolean;
	  FCheckDiskLabels: Boolean;
    FMultiMode: TMultiMode;
    file_info: TZipHeaderInfo;
    files: TSortedZip;
    sortfiles: TSortedZip;
    filesDate: TDateTime;
    ZipIsBad: Boolean;
	  CurrentDisk: Integer;
	  theZipFile: TStream;
	  Crc32Val: LongInt;
	  lrec: local_file_header;
	  crec: central_file_header;
	  ecrec: TEndCentral;
	  ZipCommentPos: LongInt;
	  Key: DecryptKey;
    CancelOperation: Boolean;
    ZipStream: TStream;
    StreamZipping: Boolean;
    Fixing: Boolean;
    DR: Boolean;

    TotalUncompressedSize: Comp;
    TotalBytesDone: Comp;

    {$IFDEF DEMO2}
    OpCount: Integer;
    DemoApp: Boolean;
    HowOften: Integer;
   {$ENDIF}

	  procedure OpenZip;
    procedure CloseZip;
    function GetCount: Integer;
    procedure GetFileInfo;
    function GetZipName: String;
    procedure SetZipName( ZName: String ); virtual;
    procedure SetArchiveStream( theStream: TStream );
    function GetDestDir: String;
    procedure SetDestDir( DDir: String );
    procedure SetRootDir(Value: String);
	  function UnZipFiles( zip_in_file: TStream ): Integer;
    function UpdCRC(Octet: Byte; Crc: LongInt) : LongInt;
    function SwapDisk( NewDisk: Integer): TStream;
    procedure SetFileComment( Index: Integer; theComment: String );
    procedure SetZipComment( theComment: String );
    procedure WriteNumDisks( NumberOfDisks: Integer );
    procedure NewDiskEvent( Sender: TObject; var S: TStream );
    procedure SetThisVersion( v: Integer );
    function GetCheckDiskLabels: Boolean; virtual;
    procedure SetCheckDiskLabels( Value: Boolean ); virtual;
    
    { GetMultiMode and SetMultiMode added 3/10/98 for 2.03}
    function GetMultiMode: TMultiMode; virtual;
    procedure SetMultiMode( Value: TMultiMode ); virtual;

	  { List functions }
	  procedure SetFilesList( Value: TStrings );
    function GetFilename(Index: Integer): TZipFilename;
    function GetPathname(Index: Integer): TZipPathname;
    function GetFullname(Index: Integer): String;
    function GetCompressMethod(Index: Integer): WORD;
    function GetCompressMethodStr(Index: Integer): String;
    function GetDateTime(Index: Integer): TDateTime;
    function GetCrc(Index: Integer): LongInt;
    function GetCompressedSize(Index: Integer): LongInt;
    function GetUnCompressedSize(Index: Integer): LongInt;
    function GetExternalFileAttributes(Index: Integer): LongInt;
    function GetIsEncrypted(Index: Integer): Boolean;
    function GetHasComment(Index: Integer): Boolean;
    function GetFileComment(Index: Integer): String;
    function GetDiskNo(Index: Integer): Integer;
    function GetZipHasComment: Boolean;
    function GetZipComment: String;
    function GetZipSize: LongInt;
    
    {Decryption}
    function DecryptTheHeader( Passwrd: String; zfile: TStream ): BYTE;
    procedure update_keys( ch: char );
    function decrypt_byte: BYTE;
    procedure Init_Keys( Passwrd: String );
    procedure decrypt_buff( bufptr: BYTEPTR; num_to_decrypt: WORD );
    procedure Update_CRC_buff( bufptr: BYTEPTR; num_to_update: WORD );

    procedure Loaded; override;

  public
    { Public declarations }
    constructor Create( AOwner: TComponent ); override;
    destructor Destroy; override;
    procedure ReadZip;
	  function UnZip: Integer;
    procedure ClearZip;
    procedure FillList( FilesList: TStrings );
    procedure Sort( SMode: TZipSortMode );
    procedure CancelTheOperation;
    function UnZipToStream( theStream: TStream; FName: String ): Integer;

    property ArchiveStream: TStream read theZipFile write SetArchiveStream;
	  property Count: Integer read GetCount;
	  property Filename[Index: Integer]: TZipFilename read GetFilename;
    property Pathname[Index: Integer]: TZipPathname read GetPathname;
    property FullName[Index: Integer]: String read GetFullName;
    property CompressMethod[Index: Integer]: WORD read GetCompressMethod;
    property CompressMethodStr[Index: Integer]: String read GetCompressMethodStr;
    property DateTime[Index: Integer]: TDateTime read GetDateTime;
    property Crc[Index: Integer]: LongInt read GetCrc;
    property CompressedSize[Index: Integer]: LongInt read GetCompressedSize;
    property UnCompressedSize[Index: Integer]: LongInt read GetUnCompressedSize;
    property ExternalFileAttributes[Index: Integer]: LongInt read GetExternalFileAttributes;
    property IsEncrypted[Index: Integer]: Boolean read GetIsEncrypted;
    property FileHasComment[Index: Integer]: Boolean read GetHasComment;
    property FileComment[Index: Integer]: String read GetFileComment;
    property DiskNo[Index: Integer]: Integer read GetDiskNo;
    property ZipComment: String read GetZipComment;
    property Password: String read FPassword write FPassword;
    property ZipHasComment: Boolean read GetZipHasComment;
    property NumDisks: Integer read FNumDisks;
    property ZipSize: LongInt read GetZipSize;
    property CheckDiskLabels: Boolean read GetCheckDiskLabels write SetCheckDiskLabels default True;
    property MultiMode: TMultiMode read GetMultiMode write SetMultiMode default mmNone;
    property Busy: Boolean read FBusy default False;

  published
    { Published declarations }
    property ThisVersion: Integer read FThisVersion write SetThisVersion default kpThisVersion;
	  property ZipName: String read GetZipName write SetZipName;
    property DestDir: String read GetDestDir write SetDestDir;
    property RootDir: String read FRootDir write SetRootDir;
    property SortMode: TZipSortMode read FSortMode write FSortMode default ByNone;
    property RecreateDirs: Boolean read FRecreateDir write FRecreateDir default False;
    property OverwriteMode: TUZOverwriteMode read FOverwriteMode
                                             write FOverwriteMode default Prompt;
	  property FilesList: TStrings read FFilesList write SetFilesList;
    property DoAll: Boolean read FDoAll write FDoAll default False;
    property IncompleteZipMode: TIncompleteZipMode read FIncompleteZipMode
                 write FIncompleteZipMode default izAssumeMulti;
    property KeepZipOpen: Boolean read FKeepZipOpen write FKeepZipOpen default False;
    property DoProcessMessages: Boolean read FDoProcessMessages write FDoProcessMessages
                                                                default True;
    property RetainAttributes: Boolean read FRetainAttributes write FRetainAttributes default True;
     { Event Properties }
	  property OnStartUnZipInfo: TStartUnzipInfo read FOnStartUnzipInfo
    															write FOnStartUnzipInfo;
    property OnFilePercentDone: TFilePercentDone read FOnFilePercentDone
    															  write FOnFilePercentDone;
    property OnTotalPercentDone: TTotalPercentDone read FOnTotalPercentDone
    																 write FOnTotalPercentDone;
    property OnStartUnZip: TStartUnZipEvent read FOnStartUnZip write FOnStartUnZip;
    property OnEndUnZip: TEndUnZipEvent read FOnEndUnZip write FOnEndUnZip;
    property OnPromptForOverwrite: TPromptForOverwrite read FOnPromptForOverwrite
    				write FOnPromptForOverwrite;
    property OnSkippingFile: TSkippingFile read FOnSkippingFile write FOnSkippingFile;
    property OnBadPassword: TBadPassword read FOnBadPassword write FOnBadPassword;
    property OnBadCRC: TBadCRC read FOnBadCRC write FOnBadCRC;
    property OnInCompleteZip: TInCompleteZip read FOnInCompleteZip write FOnInCompleteZip;
    property OnGetNextDisk: TGetNextDisk read FOnGetNextDisk write FOnGetNextDisk;
  end;

	function IsAZipFile( FileName: String ): Boolean;

//var
//  OpenZipDlg: TOpenDialog;

//  procedure Register;
//  function DelphiIsRunning: Boolean;

implementation

{$I kpUnzipp.Pas}

{******************************************************************}
constructor TVCLUnZip.Create( AOwner: TComponent );
begin
//	inherited Create(AOwner);
	FSortMode := ByNone;
	FDoAll := False;
	RecreateDirs := False;
	FFilesList := TStringList.Create;
	file_info := TZipHeaderInfo.Create;
	Password := '';
	ZipIsBad := False;
	theZipFile := nil;
	files := nil;
	sortfiles := nil;
	FIncompleteZipMode := izAssumeMulti;
  ecrec := TEndCentral.Create;
  CancelOperation := False;
  FKeepZipOpen := False;
  FDoProcessMessages := True;
  FCheckDiskLabels := True;
  StreamZipping := False;
  ArchiveIsStream := False;
  Fixing := False;
  FNumDisks := 1;
  CurrentDisk := 0;
  FRetainAttributes := True;
  FBusy := False;
  FThisVersion := kpThisVersion;
end;

destructor TVCLUnZip.Destroy;
begin
  ClearZip;
	If (FFilesList <> nil) then
     FFilesList.Free;
  If (file_info <> nil) then
     file_info.Free;
  If (ecrec <> nil) then
     ecrec.Free;
  inherited Destroy;
end;

procedure TVCLUnZip.Loaded;
begin
	Inherited Loaded;
  {$IFDEF KPDEMO}
	if not (csDesigning In ComponentState) then
   begin
     DR := DelphiIsRunning;
     If not DelphiIsRunning then
      begin
        ShowMessage('This unregistered verion of VCLZip will only run while the Delphi IDE is running');
        Application.Terminate;
      end;
   end;
   {$ENDIF}
end;

procedure TVCLUnZip.SetZipName( ZName: String );
var
	tempZipName: String;
	Canceled: Boolean;
begin
FZipName := ZName;
{  If AnsiCompareText(ZName,FZipName) = 0 then
     exit;
	Canceled := False;
	If (ZName <> '') and (ZName[Length(ZName)] = '?') then
   begin
//     OpenZipDlg := TOpenDialog.Create(Application);
    try
//     OpenZipDlg.Title := 'Open a Zip File';
     OpenZipDlg.Filter := 'Zip Files (*.ZIP)|*.zip|SFX Files (*.EXE)|*.exe' +
									'|All Files (*.*)|*.*';
		If DirExists(ExtractFilePath(ZName)) then
			OpenZipDlg.InitialDir := ExtractFilePath(ZName)
		Else
     	OpenZipDlg.InitialDir := 'C:\';
		If OpenZipDlg.Execute then
			tempZipName := OpenZipDlg.Filename
		Else
			Canceled := True;
	  finally
		OpenZipDlg.Free;
	  end;
	 end
	Else
		tempZipName := ZName;

	If not Canceled then
	 begin
     FZipName := tempZipName;
		If (sortfiles <> nil) and (FSortMode <> ByNone) then
		 begin
			sortfiles.Free;
			sortfiles := nil;
		 end;
		files.Free;
		files := nil;
		filesDate := 0;
     ecrec.Clear;
		theZipFile.Free;
		theZipFile := nil;
		ZipIsBad := False;
     ArchiveIsStream := False;
	 end
	Else
  	raise EUserCanceled.Create('User canceled setting zip file name.'); }
end;

function TVCLUnZip.GetZipName: String;
begin
  Result := FZipName;
end;

procedure TVCLUnZip.SetArchiveStream( theStream: TStream );
begin
  If theStream = nil then
     theZipFile := nil;
  ClearZip;
  theZipFile := theStream;
  If theZipFile <> nil then
   begin
     FKeepZipOpen := True;
     ArchiveIsStream := True;
   end
  Else
     ArchiveIsStream := False;
end;

procedure TVCLUnZip.SetDestDir( DDir: String );
var
	theDir: String;
begin
  If DDir = '?' then
	 begin
		theDir := FDestDir;
		If not DirExists(theDir+'\') then
			GetDirectory(0,theDir);
		{$IFNDEF WIN32}
		{$IFNDEF NOLONGNAMES}
		If OSVersion > 3 then
			theDir := LFN_ConvertLFName(theDir,SHORTEN);
		{$ENDIF}
		{$ENDIF}
		{If SelectDirectory(theDir, [sdAllowCreate, sdPerformCreate, sdPrompt], 0) then
        FDestDir := theDir
     Else
        raise EUserCanceled.Create('User canceled Set Desination Directory');}
   end
	Else
		FDestDir := DDir;

	If (FDestDir <> '') and (FDestDir[Length(FDestDir)] = '\') then    { Remove slash }
		SetLength(FDestDir,Length(FDestDir)-1);
end;

function TVCLUnZip.GetDestDir: String;
begin
  Result := FDestDir;
end;

procedure TVCLUnZip.SetRootDir( Value: String );
begin
  If Length(Value) > 0 then
   begin
     If RightStr(Value,1) <> '\' then
        FRootDir := Value + '\'
     Else
        FRootDir := Value;
   end
  Else FRootDir := '';
end;

procedure TVCLUnZip.SetFilesList(Value: TStrings);
begin
	FFilesList.Assign(Value);
end;

{ List Properties }

function TVCLUnZip.GetFilename(Index: Integer): TZipFilename;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.filename;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetPathname(Index: Integer): TZipPathname;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.Directory;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetFullname(Index: Integer): String;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
  begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.Directory + finfo.filename;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetCompressMethod(Index: Integer): WORD;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.compression_method;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetCompressMethodStr(Index: Integer): String;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := comp_method[finfo.compression_method];
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetDateTime(Index: Integer): TDateTime;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      try
        Result := FileDateToDateTime( finfo.last_mod_file_date_time )
      except
        Result := Now;
      end;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetCrc(Index: Integer): LongInt;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
  begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.Crc32;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetCompressedSize(Index: Integer): LongInt;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.compressed_size;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetUnCompressedSize(Index: Integer): LongInt;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.uncompressed_size;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetExternalFileAttributes(Index: Integer): LongInt;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.external_file_attributes;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetIsEncrypted(Index: Integer): Boolean;
var
	finfo: TZipHeaderInfo;
begin
	If (Index > -1) and (Index < Count) then
   begin
   	finfo := sortfiles.Items[Index] as TZipHeaderInfo;
     Result := finfo.Encrypted;
   end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetHasComment(Index: Integer): Boolean;
var
	finfo: TZipHeaderInfo;
begin
	If (Index > -1) and (Index < Count) then
   begin
   	finfo := sortfiles.Items[Index] as TZipHeaderInfo;
     Result := finfo.HasComment;
   end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetZipHasComment: Boolean;
begin
  Result := ecrec.zip_comment_length > 0;
end;

function TVCLUnZip.GetFileComment(Index: Integer): String;
var
	finfo: TZipHeaderInfo;
  crec: central_file_header;
  CommentLength: LongInt;
  RememberModified: Boolean;
begin
	If (Index > -1) and (Index < Count) then
   begin
   	finfo := sortfiles.Items[Index] as TZipHeaderInfo;
     With finfo do
      begin
      	If HasComment then
         begin
          If finfo.filecomment = nil then
          try
     		OpenZip;
     		theZipFile.Seek(central_offset, soFromBeginning	);
           theZipFile.Read(crec, SizeOf(central_file_header));
           With crec do
            begin
           	theZipFile.Seek( filename_length+extra_field_length, soFromCurrent);
              {$IFDEF WIN32}
              CommentLength := file_comment_length;
              {$ELSE}
              CommentLength := min(file_comment_length,255);
              {$ENDIF}
        		SetLength( Result, CommentLength );
        		theZipFile.Read( Result[1], CommentLength );
              RememberModified := ecrec.Modified;
              SetFileComment( Index, Result );  { Save it in central header }
              ecrec.Modified := RememberModified;
            end;
          finally
           CloseZip;
          end
          Else Result := StrPas(finfo.filecomment);
         end
        Else
         Result := '';    { No comment }
      end;
   end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetZipComment: String;
var
  CommentLength: LongInt;
  RememberModified: Boolean;
begin
	If ecrec.zip_comment_length = 0 then
  	Result := ''
  Else
   With ecrec do
    begin
      If ecrec.ZipComment = nil then
       begin
        OpenZip;
        try
      	   theZipFile.Seek( ZipCommentPos, soFromBeginning );
           {$IFDEF WIN32}
           CommentLength := zip_comment_length;
           {$ELSE}
           CommentLength := min(zip_comment_length,255);
           {$ENDIF}
           SetLength( Result, CommentLength );
           theZipFile.Read( Result[1], CommentLength );
           RememberModified := Modified;
           SetZipComment( Result );  { Save it in ecrec }
           Modified := RememberModified;
        finally
      	   CloseZip;
        end;
       end
      Else Result := PCharToStr(ecrec.ZipComment);
    end;
end;

procedure TVCLUnZip.SetZipComment( theComment: String );
begin
  If ((ecrec.ZipComment = nil) and (theComment <> '')) or
		(StrComp( ecrec.ZipComment, StringAsPChar(theComment) ) <> 0) then
   begin
     If ecrec.ZipComment <> nil then
        StrDispose( ecrec.ZipComment );
     If theComment = '' then
        ecrec.ZipComment := nil
     Else
      begin
        ecrec.ZipComment := StrToPChar( theComment );
      end;
     ecrec.zip_comment_length := Length(theComment);
     ecrec.Modified := True;
   end;
end;

procedure TVCLUnZip.SetFileComment( Index: Integer; theComment: String );
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
   begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      If ((finfo.filecomment = nil) and (theComment <> '')) or
			 (StrComp(finfo.filecomment, StringAsPChar(theComment)) <> 0) then
       begin
        If finfo.filecomment <> nil then
           finfo.filecomment := nil;
        If theComment = '' then
           finfo.filecomment := nil
        Else
         begin
           finfo.filecomment := StrToPChar(theComment);
         end;
        ecrec.Modified := True;
       end;
   end
  Else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

{ 3/10/98  2.03}
{ These are overriden in VCLZip }
function TVCLUnZip.GetMultiMode: TMultiMode;
begin
  Result := FMultiMode;
end;

{ 3/10/98  2.03}
procedure TVCLUnZip.SetMultiMode( Value: TMultiMode );
begin
  FMultiMode := Value;
end;

function TVCLUnZip.GetDiskNo( Index: Integer): Integer;
var
	finfo: TZipHeaderInfo;
begin
  If (Index > -1) and (Index < Count) then
    begin
      finfo := sortfiles.Items[Index] as TZipHeaderInfo;
      Result := finfo.disk_number_start+1;
    end
  else Raise EListError.CreateFmt('Index %d is out of range',[Index]);
end;

function TVCLUnZip.GetZipSize: LongInt;
begin
  Result := 0;
  If FZipName <> '' then
   begin
     OpenZip;
     try
        Result := theZipFile.Size;
     finally
        CloseZip;
     end;
   end;
end;

procedure TVCLUnZip.WriteNumDisks( NumberOfDisks: Integer );
begin
  FNumDisks := NumberOfDisks;
end;

{ Added these so that they could be overriden in VCLZip 3/11/98  2.03 }
function TVCLUnZip.GetCheckDiskLabels: Boolean;
begin
  Result := FCheckDiskLabels;
end;

procedure TVCLUnZip.SetCheckDiskLabels( Value: Boolean );
begin
  FCheckDiskLabels := Value;
end;

function TVCLUnZip.UnZip: Integer;
begin
  FBusy := True;
  CancelOperation := False;
  Result := 0;
	If DestDir <> '?' then
	begin
     OpenZip;
  	Result := UnzipFiles(theZipFile);
     CloseZip;
	end;
  FBusy := False;
end;

function TVCLUnZip.UnZipToStream( theStream: TStream; FName: String ): Integer;
begin
  FBusy := True;
  ZipStream := theStream;
  CancelOperation := False;
  StreamZipping := True;
  OpenZip;
  FilesList.Clear;
  FilesList.Add( FName );
  Result := UnzipFiles(theZipFile);
  StreamZipping := False;
  CloseZip;
  FBusy := False;
end;

procedure TVCLUnZip.OpenZip;
{$IFDEF DEMO2}
var
  Msg: String;
{$ENDIF}
begin
  {$IFDEF KPDEMO}
	if not (csDesigning In ComponentState) then
   begin
     If not DelphiIsRunning then
      begin
        ShowMessage('This unregistered verion of VCLZip will only run while the Delphi IDE is running');
        Application.Terminate;
      end;
   end;
   {$ENDIF}
  {$IFDEF KPDEMO2}
  If not DemoApp then
   begin
     Inc(OpCount);
     Msg := 'Thanks for trying the ' + ClassName + ' component. ';
     Msg := Msg + 'See the help file for registration instructions.';
     If OpCount mod HowOften = 0 then
      begin
        Dec(HowOften);
        If HowOften = 1 then
           HowOften := 3;
        MessageBeep(0);
        ShowMessage(Msg);
      end;
   end;
  {$ENDIF}
  If theZipFile = nil then
		theZipFile := TLFNFileStream.Create( FZipName, fmOpenRead or fmShareDenyWrite );
  If files = nil then
     GetFileInfo
  Else
     If (not ArchiveIsStream) and
        (FileDateToDateTime(FileGetDate( TLFNFileStream(theZipFile).Handle )) <> filesDate) then
           GetFileInfo;
end;

procedure TVCLUnZip.CloseZip;
begin
  If not FKeepZipOpen then
   begin
     theZipFile.Free;
     theZipFile := nil;
   end;
end;

function TVCLUnZip.SwapDisk( NewDisk: Integer): TStream;
{ NewDisk is the disk number that the user sees. Starts with 1 }
var
  tmpZipName: String;

  function CurrentDiskLabel( NewDisk: Integer ): Boolean;
  var
		VolName: String[11];
		Disk: String;
	begin
     {Need to check disk label here}
     If MultiMode = mmSpan then
		 begin
      	Disk := UpperCase(LeftStr(FZipName,3));
			VolName := GetVolumeLabel( Disk );
			If RightStr(VolName,3) = Format('%3.3d',[NewDisk]) then
           Result := True
        Else
           Result := False;
      end
     Else Result := True;
  end;

begin
  theZipFile.Free;
  theZipFile := nil; {1/27/98 to avoid GPF when Freeing file in CloseZip. v2.00+}
  tmpZipName := FZipName;
  Repeat
     Repeat
        FOnGetNextDisk( Self, NewDisk, tmpZipName );
     Until (not CheckDiskLabels) or (tmpZipName = '') or (CurrentDiskLabel(NewDisk));
     If tmpZipName = '' then
        raise EUserCanceled.Create('User canceled loading new disk.');
  Until FileExists(tmpZipName); {1/29/98 To avoid problem if file doesn't exist}
	theZipFile := TLFNFileStream.Create( tmpZipName, fmOpenRead );
	CurrentDisk := NewDisk-1;   { CurrentDisk starts with 0 }
  filesDate := FileDateToDateTime(FileGetDate( TLFNFileStream(theZipFile).Handle ));
  FZipName := tmpZipName;
  Result := theZipFile;
end;

procedure TVCLUnZip.NewDiskEvent( Sender: TObject; var S: TStream );
begin
  SwapDisk(CurrentDisk+2);
  S := theZipFile;
end;

procedure TVCLUnZip.ClearZip;
var
  SaveKeepZipOpen: Boolean;
begin
  SaveKeepZipOpen := FKeepZipOpen;
  FKeepZipOpen := False;
  CloseZip;
  FKeepZipOpen := SaveKeepZipOpen;
  If (sortfiles <> nil) and (sortfiles <> files) then
     sortfiles.Free;
  files.Free;
  files := nil;
  sortfiles := nil;
  ecrec.Clear;
  ZipIsBad := False;
  filesDate := 0;
  FNumDisks := 1;
  MultiMode := mmNone;
  If not ArchiveIsStream then
     FZipName := '';
end;

procedure TVCLUnZip.ReadZip;
begin
  CancelOperation := False;
  OpenZip;
  CloseZip;
end;

procedure TVCLUnZip.GetFileInfo;
var
  finfo: TZipHeaderInfo;

function ReadZipHardWay: Boolean;
var
  sig: Byte;
  AmtRead: LongInt;
  CancelCheck: LongInt;
begin
   ZipIsBad := True;
   Result := False;
   CancelCheck := 0;
   If files <> nil then
    begin
     files.Free;
     files := nil;
    end;
   theZipFile.Seek(0, soFromBeginning);
	 AmtRead := theZipFile.Read( sig, SizeOf(sig) );
   Repeat
     Repeat
        Repeat
           While (AmtRead = SizeOf(sig)) and (sig <> $50) do
            begin
              Inc(CancelCheck);
              If (DoProcessMessages) and (CancelCheck mod 10240 = 0) then
               begin
//                 Application.ProcessMessages;
                 If CancelOperation then
                  begin
                    CancelOperation := False;
                    raise EUserCanceled.Create('User Aborted Operation');
                  end;
               end;
              AmtRead := theZipFile.Read( sig, SizeOf(sig) );
            end;
           If AmtRead <> SizeOf(sig) then
              Result := False
           Else
              AmtRead := theZipFile.Read( sig, SizeOf(sig) );
        Until (AmtRead <> SizeOf(sig)) or (sig = $4B);
        AmtRead := theZipFile.Read( sig, SizeOf(sig) );
     Until (AmtRead <> SizeOf(sig)) or (sig = $03);
     AmtRead := theZipFile.Read( sig, SizeOf(sig) );
   Until (AmtRead <> SizeOf(sig)) or (sig = $04);
   If (AmtRead <> SizeOf(sig)) or (sig <> $04) then
      exit;
   theZipFile.Seek(-4, soFromCurrent);
   files := TSortedZip.Create( DupError );
   files.SortMode := ByNone;  { Force for later compare }
   sortfiles := files;  { added 3/10/98 2.03 }
   finfo := TZipHeaderInfo.Create;
   While finfo.ReadLocalFromStream(theZipFile) do
    begin
     files.AddObject(finfo);
     If finfo.HasDescriptor then
        theZipFile.Seek(finfo.compressed_size+finfo.extra_field_length+
                                SizeOf(DataDescriptorType), soFromCurrent )
     Else
        theZipFile.Seek( finfo.compressed_size + finfo.extra_field_length, soFromCurrent );
     finfo := TZipHeaderInfo.Create;
   end ;
   finfo.Free;
   finfo := nil;

	 ecrec.this_disk := 0;
   CurrentDisk := 0;
   ecrec.offset_central := theZipFile.Seek(0, soFromCurrent);  {assume}
   ecrec.num_entries := Count;

   FNumDisks := ecrec.this_disk+1;

   Result := True;
end;

var
  tmpfinfo: TZipHeaderInfo;
  i: Integer;
  Index: Integer;

procedure GetDescriptorInfo;
var
  savepos: LongInt;
  lrecord: local_file_header;
  drecord: DataDescriptorType;
begin
  with finfo do
   begin
     savepos := theZipFile.Seek(0, soFromCurrent);
     theZipFile.Seek( relative_offset, soFromBeginning );
     theZipFile.Read( lrecord, SizeOf(lrecord) );
     theZipFile.Seek( lrecord.filename_length + lrecord.compressed_size +
                                   lrecord.extra_field_length, soFromCurrent );
     theZipFile.Read( drecord, SizeOf(drecord) );
     theZipFile.Seek( savepos, soFromBeginning );
   end;
end;

var
  sig: LongInt;
  saveOffset: LongInt;
	RootPath: String;
	Disk: Integer;
begin   { GetFileInfo }
   If not ArchiveIsStream then
     filesDate := FileDateToDateTime(FileGetDate( TLFNFileStream(theZipFile).Handle ))
   Else
     filesDate := Now;
	 If Count > 0 then
    begin
     If (sortfiles <> nil) and (FSortMode <> ByNone) then
      begin
        sortfiles.Free;
        sortfiles := nil;
      end;
     files.Free;
     files := nil;
    end;
   If (not ecrec.ReadFromStream(theZipFile)) then  { False = couldn't find the end central directory }
    begin
      If not Fixing then
       begin
        If Assigned( FOnIncompleteZip ) then
           FOnIncompleteZip( Self, FIncompleteZipMode );
        If (FIncompleteZipMode = izAssumeMulti) then
			   raise EIncompleteZip.Create('Incomplete Zip File');
       end;
      If (FIncompleteZipMode = izAssumeBad) or (Fixing) then
       begin
//         Screen.Cursor := crHourGlass;
         If not ReadZipHardWay then  { False = there's no central directories }
          begin
            Sort(FSortMode);
//            Screen.Cursor := crDefault;
            exit;
          end;
//         Screen.Cursor := crDefault;
       end;
    end
   else
    begin
     CurrentDisk := ecrec.this_disk;
     If ecrec.this_disk > 0 then
		 begin
			RootPath := UpperCase(LeftStr(FZipName,3));
			Disk := Ord(RootPath[1])-65; { -65 for 16bit GetDriveType }
			If RootPath[2] <> ':' then
				MultiMode := mmBlocks
			{$IFDEF WIN32}
			Else If ( GetDriveType(StringAsPChar(RootPath)) = DRIVE_REMOVABLE ) then
			{$ELSE}
			Else
				If ( GetDriveType(Disk) = DRIVE_REMOVABLE ) then
			{$ENDIF}
					MultiMode := mmSpan
			Else
				MultiMode := mmBlocks;
		 end
		Else
			MultiMode := mmNone;
     { Moved the following down lower 3/10/98  2.03 }
{     if (ecrec.this_disk > 0) and (ecrec.ZipHasComment) then
        GetZipComment;  }
		If (ecrec.start_central_disk <> CurrentDisk) then
        SwapDisk(ecrec.start_central_disk+1);
     theZipFile.Seek( ecrec.offset_central, soFromBeginning );
     theZipFile.Read( sig, SizeOf(sig) );
     If sig <> $02014b50 then
      begin
//        Screen.Cursor := crHourGlass;
         If not ReadZipHardWay then
          begin
            Sort(FSortMode);
//            Screen.Cursor := crDefault;
            exit;
          end;
//         Screen.Cursor := crDefault;
      end
     Else
      begin
        theZipFile.Seek( -4, soFromCurrent );
        files := TSortedZip.Create( DupError );
        files.SortMode := ByNone;
        sortfiles := files;  { added 3/10/98 2.03 }
      end;
    end;
   For i := 0 to ecrec.num_entries-1 do
   begin
     finfo := TZipHeaderInfo.Create;
     If (ZipIsBad) or (MultiMode = mmNone) then
        finfo.ReadCentralFromStream(theZipFile, nil)
     Else
        finfo.ReadCentralFromStream(theZipFile, NewDiskEvent);
     If ZipIsBad then
      begin
        If (files.Search( Pointer(finfo), Index )) then
         begin
           tmpfinfo := files.Items[Index] as TZipHeaderInfo;
           saveOffset := tmpfinfo.relative_offset;
           tmpfinfo.Assign(finfo);
           tmpfinfo.relative_offset := saveOffset;
           finfo.Free;
           finfo := nil;
         end
        Else   { don't mess with it if there's no local header }
         begin
           finfo.Free;
           finfo := nil;
           continue;
         end;
     end;
     If not ZipIsBad then
        files.AddObject(finfo);  { If ZipIsBad then it has already been added }
     If (ecrec.this_disk > 0) and (finfo.HasComment) then
        GetFileComment(i);
     theZipFile.Seek( crec.extra_field_length + crec.file_comment_length, soFromCurrent );
   end;
   { Moved the following to here from further up since GetZipComment could not be called
     until the central directories were read  3/10/98  2.03 }
   if (ecrec.this_disk > 0) and (ecrec.ZipHasComment) then
    begin
		   If ecrec.this_disk <> CurrentDisk then
           SwapDisk(ecrec.this_disk+1);
        GetZipComment;
    end;
	 FNumDisks := ecrec.this_disk+1;
	 CurrentDisk := ecrec.this_disk;
   Sort( FSortMode );
end;

procedure TVCLUnZip.Sort( SMode: TZipSortMode );
var
  i: Integer;
begin
   If (sortfiles <> nil) and (sortfiles <> files) and (FSortMode <> ByNone) then
     sortfiles.Free;
   If SMode = ByNone then
     sortfiles :=  files
   Else
    begin
     sortfiles := TSortedZip.Create( dupAccept );
     sortfiles.SortMode := SMode;
     sortfiles.DestroyObjects := False;
     For i := 0 to Count-1 do
        sortfiles.AddObject(files.Items[i] as TZipHeaderInfo);
    end;
   FSortMode := SMode;
end;

procedure TVCLUnZip.CancelTheOperation;
begin
  CancelOperation := True;
end;

function TVCLUnZip.GetCount: Integer;
begin
  If files <> nil then
     Result := files.Count
  else
     Result := 0;
end;

procedure TVCLUnZip.FillList( FilesList: TStrings );
var
  AddBuffer: String;
  i: Integer;
  ZipTimeStr: String;
  ZipDate: TDateTime;
  ZipDateStr: String;
  finfo: TZipHeaderInfo;
  encryptmark, commentmark: string[1];
begin
   FilesList.Clear;
   For i := 0 to Count-1 do
   begin
     finfo := sortfiles.Items[i] as TZipHeaderInfo;
     try
        ZipDate := FileDateToDateTime( finfo.last_mod_file_date_time )
     except
        ZipDate := Now;
     end;
     ZipDateStr := Format( '%8s', [FormatDateTime( 'mm/dd/yy', ZipDate )] );
     ZipTimeStr := Format( '%7s', [FormatDateTime( 'hh:mmam/pm', ZipDate )] );
     If (finfo.general_purpose_bit_flag and 1) <> 0 then
     	encryptmark := '#'
     else
     	encryptmark := '';
     If finfo.HasComment then
     	commentmark := '@'
     else
     	commentmark := '';
     With finfo do
        AddBuffer := filename + encryptmark + commentmark + #9 + ZipDateStr + #9 + ZipTimeStr + #9
           + Format('%8d',[uncompressed_size]) + #9 + Format('%8d',[compressed_size]) + #9
           + Format('%3d%s',[CRate(uncompressed_size,compressed_size),'%']) + #9
           + comp_method[compression_method] + #9 + Directory;
        FilesList.Add(LowerCase(AddBuffer));
   end;
end;

procedure TVCLUnZip.SetThisVersion( v: Integer );
begin
  FthisVersion := kpThisVersion;
end;

{ This function not used }

{ This function isn't used right now and isn't even really correct.  This won't
	work for SFX files or any zip file that doesn't start with a local header.  I'll
	work on this later. }
function IsAZipFile( FileName: String ): Boolean;
var
	TestFile: TFileStream;
	xlrec: local_file_header;
	SearchRec: TSearchRec;
	SearchResult: Integer;
begin
	If (ExtractFileExt( Filename ) <> '.ZIP') and (ExtractFileExt( Filename ) <> '.EXE') then
	 begin
		Result := False;
		exit;
	 end;
	SearchResult := FindFirst( FileName, faAnyFile, SearchRec );
  If (SearchResult <> 0) then
  	Result := False
  Else If (SearchRec.Attr and faDirectory > 0) then
		Result := False
	else
	 begin
		TestFile := TFileStream.Create( FileName, fmOpenRead );
		try
			TestFile.Read( xlrec, SizeOf(local_file_header) );
			If xlrec.Signature.ID2 = $0403 then
				Result := True
			else
				Result := False;
		finally
			TestFile.Free;
        TestFile := nil;
		end;
	 end;
end;

function DelphiIsRunning: Boolean;
const
  A1: array[0..12] of char = 'TApplication'#0;
  A2: array[0..15] of char = 'TAlignPalette'#0;
  A3: array[0..18] of char = 'TPropertyInspector'#0;
  A4: array[0..11] of char = 'TAppBuilder'#0;
  {$IFDEF WIN32}
  {$IFDEF VER100}
  T1: array[0..15] of char = 'Delphi 3'#0;
  {$ELSE}
  T1: array[0..15] of char = 'Delphi 2.0'#0;
  {$ENDIF}
  {$ELSE}
  T1: array[0..15] of char = 'Delphi'#0;
  {$ENDIF}
begin
  Result := (FindWindow(A1,T1)<>0) and
            (FindWindow(A2,nil)<>0) and
            (FindWindow(A3,nil)<>0) and
            (FindWindow(A4,nil)<>0);
end;

procedure Register;
begin
//  RegisterComponents('Samples', [TVCLUnZip]);
end;

end.
