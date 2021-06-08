{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: UnZipObj.Pas                                                      }
{     Description: VCLUnZip/VCLZip component - native Delphi unzip component.        }
{     Date:        May 1997                                                          }
{     Author:      Kevin Boylan, boylank@bigfoot.com                                 }
{                                                                                    }
{                                                                                    }
{ ********************************************************************************** }
unit kpZipObj;
{$P-} {Added 6-8-97 KLB}

{$R-}   { 3/10/98 2.03 }
{$Q-}   { 3/10/98 2.03 }


{ $Log:  D:\Util\GP-Version\Archives\Components\VCLZip\Component Files\kpZipObj.UFV 
{
{   Rev 1.1    Tue 10 Mar 1998   20:36:37  Supervisor
{ Modified the Compare procedure for the ByNone sort 
{ because in Delphi 1 the integer wasn't big enough to 
{ handle the difference operation which caused "duplicate 
{ object" errors.
}

interface

uses
{$IFDEF WIN32}
	Windows,
{$ELSE}
  WinTypes, WinProcs,
{$ENDIF}
	SysUtils, Classes, KpLib, kpCntn;

type
	cpltype = array[0..30] of WORD;
  cpdtype = array[0..29] of WORD;

{$I kpZConst.Pas}
{$I kpZTypes.Pas}

type
{*********************  HEADER INFO  **************************************}

  SignatureType = packed Record
     Case Integer of
      0: (Sig:      LongInt);     { $04034b50    }
      1: (ID1,ID2:  WORD   );     { $4b50, $0403 }
  end;

  local_file_header = packed Record
     Signature                  : SignatureType;
     version_needed_to_extract  : WORD;
     general_purpose_bit_flag   : WORD;
     compression_method         : WORD;
     last_mod_file_date_time    : LongInt;
     crc32                      : LongInt;
     compressed_size            : LongInt;
     uncompressed_size          : LongInt;
     filename_length            : WORD;
     extra_field_length         : WORD;
  end;
  localPtr = ^local_file_header;

  central_file_header = packed Record
     Signature                  : SignatureType;
     version_made_by            : WORD;
     version_needed_to_extract  : WORD;
     general_purpose_bit_flag   : WORD;
     compression_method         : WORD;
     last_mod_file_date_time    : LongInt;
     crc32                      : LongInt;
     compressed_size            : LongInt;
     uncompressed_size          : LongInt;
     filename_length            : WORD;
     extra_field_length         : WORD;
     file_comment_length        : WORD;
     disk_number_start          : WORD;
     internal_file_attributes   : WORD;
     external_file_attributes   : LongInt;
     relative_offset            : LongInt;
  end;
  centralPtr = ^central_file_header;

  TZipHeaderInfo = class(TPersistent)   {****************TZipHeaderInfo******************}
  { This class contains all the information reflected in both the central and local
    headers for a particular compressed file within a zip file }
  private
     DR: Boolean;
     Fversion_made_by            : WORD;
     Fversion_needed_to_extract  : WORD;
     Fgeneral_purpose_bit_flag   : WORD;
     Fcompression_method         : WORD;
     Flast_mod_file_date_time    : LongInt;
     Fcrc32                      : LongInt;
     Fcompressed_size            : LongInt;
     Funcompressed_size          : LongInt;
     Ffilename_length            : WORD;
     Fextra_field_length         : WORD;
     Ffile_comment_length        : WORD;
     Fdisk_number_start          : WORD;
     Finternal_file_attributes   : WORD;
     Fexternal_file_attributes   : LongInt;
     Frelative_offset            : LongInt;
     Fcentral_offset             : LongInt;
     Ffilename                   : String;
     Fdirectory                  : String;
     Ffilecomment                : PChar;
     FMatchFlag                  : Boolean;

     procedure AssignTo(Dest: TPersistent); override;


  protected
     function GetHasComment: Boolean;
     function GetIsEncrypted: Boolean;
     function GetHasDescriptor: Boolean;
     function Getfilecomment(S: TStream): PChar;

     function GetLocalSize: Integer;
     function GetCentralSize: Integer;
     procedure Setfilename( FName: String );
     procedure Setdirectory( Directory: String );
     procedure SetFileComment( FComment: PChar );

  public
     Constructor Create;
     Constructor InitWithCentral( crec: centralPtr; FName: String );
     Constructor InitWithLocal( lrec: localPtr; FName: String );
     Destructor  Destroy; override;
     procedure Assign(Source: TPersistent); override;

     procedure   SetFromCentral( crec: centralPtr; FName: String );
     procedure   SetFromLocal( lrec: localPtr; FName: String );
     procedure   Clear;
     procedure   SaveCentralToStream( S: TStream );
     procedure   SaveLocalToStream( S: TStream );
     function    ReadCentralFromStream( S: TStream; NewDiskEvent: TNewDiskEvent ): Boolean;
     function    ReadLocalFromStream( S: TStream ): Boolean;

     procedure SetDateTime( DateTime: TDateTime );
     procedure SetNewFileComment( NewComment: String );

     property version_made_by: WORD read Fversion_made_by write Fversion_made_by;
     property version_needed_to_extract: WORD read Fversion_needed_to_extract
                                              write Fversion_needed_to_extract;
     property general_purpose_bit_flag: WORD read Fgeneral_purpose_bit_flag
                                             write Fgeneral_purpose_bit_flag;
     property compression_method: WORD read Fcompression_method write Fcompression_method;
     property last_mod_file_date_time: LongInt read Flast_mod_file_date_time
                                               write Flast_mod_file_date_time;
     property crc32: LongInt read Fcrc32 write Fcrc32;
     property compressed_size: LongInt read Fcompressed_size write Fcompressed_size;
     property uncompressed_size: LongInt read Funcompressed_size write Funcompressed_size;
     property filename_length: WORD read Ffilename_length write Ffilename_length;
     property extra_field_length: WORD read Fextra_field_length write Fextra_field_length;
     property file_comment_length: WORD read Ffile_comment_length write Ffile_comment_length;
     property disk_number_start: WORD read Fdisk_number_start write Fdisk_number_start;
     property internal_file_attributes: WORD read Finternal_file_attributes
                                             write Finternal_file_attributes;
     property external_file_attributes: LongInt read Fexternal_file_attributes
                                                write Fexternal_file_attributes;
     property relative_offset: LongInt read Frelative_offset write Frelative_offset;
     property central_offset: LongInt read Fcentral_offset write Fcentral_offset;
     property filename: String read Ffilename write Setfilename;
     property directory: String read Fdirectory write Setdirectory;
     property MatchFlag: Boolean read FMatchFlag write FMatchFlag;
     property HasComment: Boolean read GetHasComment;
     property Encrypted: Boolean read GetIsEncrypted;
     property HasDescriptor: Boolean read GetHasDescriptor;
     property filecomment: PChar read FFilecomment write SetFileComment;
     property LocalSize: Integer read GetLocalSize;
     property CentralSize: Integer read GetCentralSize;

  end;

{****************************  END OF CENTRAL  **********************************}

  end_of_central = packed Record
     ID                         : LongInt;  { $06054b50 }
     this_disk                  : WORD;
     start_central_disk         : WORD;
     num_entries_this_disk      : WORD;
     num_entries                : WORD;
     size_central               : LongInt;
     offset_central             : LongInt;
     zip_comment_length         : WORD;
  end;

  end_of_centralPtr = ^end_of_central;

  TEndCentral = class(TPersistent)   {********************TEndCentral******************}
  { This class contains all information contained in the end of central record
    for a zip file, plus some other pertinent information }
  private
     Fecrec:           end_of_central;
     FZipComment:      PChar;
     FZipCommentPos:   LongInt;
     FModified:        Boolean;

     procedure AssignTo(Dest: TPersistent); override;
  protected
     function GetZipHasComment: Boolean;
     function GetZipComment(S: TStream): PChar;
     function GetEndCentralSize: LongInt;
     property ecrec: end_of_central read Fecrec write Fecrec;
  public
     Constructor Create;
     Destructor  Destroy; override;

     procedure   SetNewZipComment( NewComment: String );

     procedure Assign(Source: TPersistent); override;
     procedure SetFromEndCentral( crec: end_of_centralPtr );

     procedure Clear;
     procedure SaveToStream( S: TStream );
     function ReadFromStream( S: TStream ): Boolean;

     property ID: LongInt read Fecrec.ID write Fecrec.ID;
     property this_disk: WORD read Fecrec.this_disk write Fecrec.this_disk;
     property start_central_disk: WORD read Fecrec.start_central_disk
                                       write Fecrec.start_central_disk;
     property num_entries_this_disk: WORD read Fecrec.num_entries_this_disk
                                          write Fecrec.num_entries_this_disk;
     property num_entries: WORD read Fecrec.num_entries write Fecrec.num_entries;
     property size_central: LongInt read Fecrec.size_central write Fecrec.size_central;
     property offset_central: LongInt read Fecrec.offset_central write Fecrec.offset_central;
     property zip_comment_length: WORD read Fecrec.zip_comment_length
                                       write Fecrec.zip_comment_length;
     property ZipHasComment: Boolean read GetZipHasComment;
     property ZipCommentPos: LongInt read FZipCommentPos write FZipCommentPos;
     property ZipComment: PChar read FZipComment write FZipComment ;
     property Modified: Boolean read FModified write FModified default False;
     property EndCentralSize: LongInt read GetEndCentralSize;
  end;

{*******************************  ZIP SORTING  ***************************************}

  TZipSortMode = (ByName, ByFileName, ByDirectoryName, ByDate, ByCompressedSize,
                  ByUnCompressedSize, ByRate, ByNone);

  TSortedZip = class(TSortedObjectList)
  { This class holds a sorted collection of TZipHeaderInfo objects }
  private
     FSortMode: TZipSortMode;
     FFilesDate: TDateTime;
  public
		Constructor Create( WithDuplicates: TDuplicates );
     function  Compare(Key1, Key2:Pointer):integer;override;
     property SortMode: TZipSortMode read FSortMode write FSortMode default ByNone;
     property filesdate: TDateTime read FFilesDate write FFilesDate;
  end;

function DRun: Boolean;

implementation   {//////////////////////////////////////////////////////////////////////}


{*****************  TZipHeaderInfo Methods *********************}
Constructor TZipHeaderInfo.Create;
begin
  inherited Create;
  Clear;
end;

Destructor TZipHeaderInfo.Destroy;
begin
  If (FFileComment <> nil) then
     StrDispose( FFileComment );
end;

procedure TZipHeaderInfo.AssignTo(Dest: TPersistent);
var
  finfo: TZipHeaderInfo;
begin
	If Dest is TZipHeaderInfo then
   begin
     finfo := TZipHeaderInfo(Dest);
     finfo.version_made_by := version_made_by;
     finfo.version_needed_to_extract := version_needed_to_extract;
     finfo.general_purpose_bit_flag := general_purpose_bit_flag;
     finfo.compression_method := compression_method;
    	finfo.last_mod_file_date_time := last_mod_file_date_time;
     finfo.crc32 := crc32;
     finfo.compressed_size := compressed_size;
     finfo.uncompressed_size := uncompressed_size;
     finfo.filename_length := filename_length;
     finfo.extra_field_length := extra_field_length;
     finfo.file_comment_length := file_comment_length;
     finfo.disk_number_start := disk_number_start;
     finfo.internal_file_attributes := internal_file_attributes;
     finfo.external_file_attributes := external_file_attributes;
     finfo.relative_offset := relative_offset;
     finfo.central_offset := central_offset;
     finfo.filename := filename;
     finfo.directory := directory;
     If (file_comment_length > 0) and (filecomment <> nil) then
      begin
        If finfo.filecomment <> nil then
           StrDispose( finfo.filecomment );
        finfo.filecomment := StrAlloc(file_comment_length+1);
        StrCopy(finfo.filecomment,filecomment);
      end;
     finfo.MatchFlag := MatchFlag;
   end
  else inherited AssignTo(Dest);
end;

procedure TZipHeaderInfo.Assign(Source: TPersistent);
var
  finfo: TZipHeaderInfo;
begin
	If Source is TZipHeaderInfo then
   begin
     finfo := TZipHeaderInfo(Source);
     Fversion_made_by := finfo.version_made_by;
     Fversion_needed_to_extract := finfo.version_needed_to_extract;
     Fgeneral_purpose_bit_flag := finfo.general_purpose_bit_flag;
     Fcompression_method := finfo.compression_method;
    	Flast_mod_file_date_time := finfo.last_mod_file_date_time;
     Fcrc32 := finfo.crc32;
     Fcompressed_size := finfo.compressed_size;
     Funcompressed_size := finfo.uncompressed_size;
     Ffilename_length := finfo.filename_length;
     Fextra_field_length := finfo.extra_field_length;
     Ffile_comment_length := finfo.file_comment_length;
     Fdisk_number_start := finfo.disk_number_start;
     Finternal_file_attributes := finfo.internal_file_attributes;
     Fexternal_file_attributes := finfo.external_file_attributes;
     Frelative_offset := finfo.relative_offset;
     Fcentral_offset := finfo.central_offset;
     filename := finfo.filename;
     directory := finfo.directory;
     If (finfo.file_comment_length > 0) and (finfo.filecomment <> nil) then
      begin
        If Ffilecomment <> nil then
           StrDispose( Ffilecomment );
        Ffilecomment := StrAlloc(file_comment_length+1);
        StrCopy(Ffilecomment,finfo.filecomment);
      end;
     MatchFlag := finfo.MatchFlag;
   end
  else inherited AssignTo(Source);
end;

Constructor  TZipHeaderInfo.InitWithCentral( crec: centralPtr; FName: String );
begin
  inherited Create;
  SetFromCentral( crec, FName );
end;

Constructor TZipHeaderInfo.InitWithLocal( lrec: localPtr; FName: String );
begin
  inherited Create;
  SetFromLocal( lrec, FName );
end;

procedure TZipHeaderInfo.SetFromCentral( crec: centralPtr; FName: String );
begin
   Fversion_made_by := crec^.version_made_by;
   Fversion_needed_to_extract := crec^.version_needed_to_extract;
   Fgeneral_purpose_bit_flag := crec^.general_purpose_bit_flag;
   Fcompression_method := crec^.compression_method;
   Flast_mod_file_date_time := crec^.last_mod_file_date_time;
   Fcrc32 := crec^.crc32;
   Fcompressed_size := crec^.compressed_size;
   Funcompressed_size := crec^.uncompressed_size;
   Ffilename_length := crec^.filename_length;
   Fextra_field_length := crec^.extra_field_length;
   Ffile_comment_length := crec^.file_comment_length;
   Fdisk_number_start := crec^.disk_number_start;
   Finternal_file_attributes := crec^.internal_file_attributes;
   Fexternal_file_attributes := crec^.external_file_attributes;
   Frelative_offset := crec^.relative_offset;
   Fcentral_offset := 0;
   filename := ExtractFilename(FName);
   directory := ExtractFilePath(FName);
   Ffilecomment := nil;
   FMatchFlag := False;
end;

procedure TZipHeaderInfo.SetFromLocal( lrec: localPtr; FName: String );
begin
   Fversion_made_by := 0;
   Fversion_needed_to_extract := lrec^.version_needed_to_extract;
   Fgeneral_purpose_bit_flag := lrec^.general_purpose_bit_flag;
   Fcompression_method := lrec^.compression_method;
   Flast_mod_file_date_time := lrec^.last_mod_file_date_time;
   Fcrc32 := lrec^.crc32;
   Fcompressed_size := lrec^.compressed_size;
   Funcompressed_size := lrec^.uncompressed_size;
   Ffilename_length := lrec^.filename_length;
   Fextra_field_length := lrec^.extra_field_length;
   Ffile_comment_length := 0;
   Fdisk_number_start := 0;
   Finternal_file_attributes := 0;
   Fexternal_file_attributes := 0;
   Frelative_offset := 0;
   Fcentral_offset := 0;
   If FName <> '' then
    begin
     filename := ExtractFilename(FName);
     directory := ExtractFilePath(FName);
    end
   Else
    begin
     filename := '';
     directory := '';
    end;
   Ffilecomment := nil;
   FMatchFlag := False;
end;

procedure TZipHeaderInfo.Clear;
begin
  { Set up default values }
   Fversion_made_by := 20;
   Fversion_needed_to_extract := 20;
   Fgeneral_purpose_bit_flag := 0;
   Fcompression_method := 8;
   Flast_mod_file_date_time := 0;
   Fcrc32 := $FFFFFFFF;;
   Fcompressed_size := 0;
   Funcompressed_size := 0;
   Ffilename_length := 0;
   Fextra_field_length := 0;
   Ffile_comment_length := 0;
   Fdisk_number_start := 0;
   Finternal_file_attributes := 1;
   Fexternal_file_attributes := 32;
   Frelative_offset := 0;
   Fcentral_offset := 0;
   Ffilename := '';
   Fdirectory := '';
   Ffilecomment := nil;
   FMatchFlag := False;
end;

procedure TZipHeaderInfo.SaveCentralToStream( S: TStream );
var
  fname: String;
  SIG: LongInt;
begin
  SIG := $02014b50;
  S.Write( SIG, SizeOf(LongInt) );
  S.Write( Fversion_made_by, SizeOf(Fversion_made_by) );
  S.Write( Fversion_needed_to_extract, SizeOf(Fversion_needed_to_extract) );
  S.Write( Fgeneral_purpose_bit_flag, SizeOf(Fgeneral_purpose_bit_flag) );
  S.Write( Fcompression_method, SizeOf(Fcompression_method) );
  S.Write( Flast_mod_file_date_time, SizeOf(Flast_mod_file_date_time) );
  S.Write( Fcrc32, SizeOf(Fcrc32) );
  S.Write( Fcompressed_size, SizeOf(Fcompressed_size) );
  S.Write( Funcompressed_size, SizeOf(Funcompressed_size) );
  S.Write( Ffilename_length, SizeOf(Ffilename_length) );
  S.Write( Fextra_field_length, SizeOf(Fextra_field_length) );
  S.Write( Ffile_comment_length, SizeOf(Ffile_comment_length) );
  S.Write( Fdisk_number_start, SizeOf(Fdisk_number_start) );
  S.Write( Finternal_file_attributes, SizeOf(Finternal_file_attributes) );
  S.Write( Fexternal_file_attributes, SizeOf(Fexternal_file_attributes) );
  S.Write( Frelative_offset, SizeOf(Frelative_offset) );
  If Ffilename_length > 0 then
   begin
     fname := Fdirectory+Ffilename;
		DOSToUnixFilename( StringAsPChar(fname) );
		{$IFDEF WIN32}
		CharToOem(@fname[1], @fname[1]);
		{$ELSE}
		AnsiToOem( StringAsPChar(fname),StringAsPChar(fname) );
		{$ENDIF}
		S.Write( fname[1], Ffilename_length );
   end;
  If (Ffile_comment_length > 0) and (Ffilecomment <> nil) then
     S.Write( Ffilecomment^, Ffile_comment_length );
end;

procedure TZipHeaderInfo.SaveLocalToStream( S: TStream );
var
  fname: String;
  SIG: LongInt;
begin
  SIG := $04034b50;
  Frelative_offset := S.Position;  {2/1/98 Needed for mulitpart archives}
  S.Write( SIG, SizeOf(LongInt) );
  S.Write( Fversion_needed_to_extract, SizeOf(Fversion_needed_to_extract) );
  S.Write( Fgeneral_purpose_bit_flag, SizeOf(Fgeneral_purpose_bit_flag) );
  S.Write( Fcompression_method, SizeOf(Fcompression_method) );
  S.Write( Flast_mod_file_date_time, SizeOf(Flast_mod_file_date_time) );
  S.Write( Fcrc32, SizeOf(Fcrc32) );
  S.Write( Fcompressed_size, SizeOf(Fcompressed_size) );
  S.Write( Funcompressed_size, SizeOf(Funcompressed_size) );
  S.Write( Ffilename_length, SizeOf(Ffilename_length) );
  S.Write( Fextra_field_length, SizeOf(Fextra_field_length) );
  If Ffilename_length > 0 then
   begin
     fname := Fdirectory+Ffilename;
     DOSToUnixFilename( StringAsPChar(fname) );
		{$IFDEF WIN32}
		CharToOem(@fname[1], @fname[1]);
		{$ELSE}
		AnsiToOem( StringAsPChar(fname),StringAsPChar(fname) );
		{$ENDIF}
		S.Write( fname[1], Ffilename_length );
   end;
end;

function TZipHeaderInfo.ReadCentralFromStream( S: TStream; NewDiskEvent: TNewDiskEvent ): Boolean;
const
  CSIG = $02014b50;
var
  fname: String;
  AmtRead: LongInt;
  crec: central_file_header;
  save_offset: LongInt;
begin
  {$IFDEF KPDEMO}
     DR := DRun;
  {$ENDIF}
  Result := False;
  save_offset := S.Seek(0, soFromCurrent);
  AmtRead := S.Read( crec, SizeOf( central_file_header ) );
  If (AmtRead = 0) or
     ((AmtRead <> SizeOf(central_file_header)) and (crec.Signature.Sig = CSIG)) then
     If Assigned(NewDiskEvent) then
      begin
        NewDiskEvent( Self, S );
        Inc(AmtRead,S.Read(crec, SizeOf(central_file_header)-AmtRead));
      end;
  If (AmtRead <> SizeOf(central_file_header)) or (crec.Signature.Sig <> CSIG) then
   begin
     S.Seek( save_offset, soFromBeginning );
     exit;
   end;
  If crec.filename_length > 0 then
   begin
     SetLength(fname,crec.filename_length);
     AmtRead := S.Read( fname[1], crec.filename_length );
     If AmtRead <> crec.filename_length then
      begin
        S.Seek( save_offset, soFromBeginning );
        exit;
      end;
     UnixToDOSFilename(StringAsPChar(fname));
		{$IFDEF WIN32}
		OemToChar(@fname[1], @fname[1]);
		{$ELSE}
		OemToAnsi( StringAsPChar(fname),StringAsPChar(fname) );
		{$ENDIF}
	 end;
  {$IFDEF KPDEMO}
     If not DR then
        fname := '';
  {$ENDIF}
  S.Seek( crec.extra_field_length + crec.file_comment_length, soFromCurrent );
  SetFromCentral( @crec, fname );
  Fcentral_offset := save_offset;
  Result := True;
end;

function TZipHeaderInfo.ReadLocalFromStream( S: TStream ): Boolean;
const
  LSIG = $04034b50;
var
  fname: String;
  lrec: local_file_header;
  save_offset: LongInt;
  AmtRead: LongInt;
begin
  Result := False;
  save_offset := S.Seek(0, soFromCurrent);
  AmtRead := S.Read(lrec, SizeOf(local_file_header));
  If (AmtRead <> SizeOf(local_file_header)) or (lrec.Signature.Sig <> LSIG) then
   begin
     S.Seek( save_offset, soFromBeginning );
     exit;
   end;
  If lrec.filename_length > 0 then
   begin
     SetLength(fname, lrec.filename_length);
     AmtRead := S.Read(fname[1], lrec.filename_length);
     If AmtRead <> lrec.filename_length then
      begin
        S.Seek( save_offset, soFromBeginning );
        exit;
      end;
     UnixToDOSFilename(StringAsPChar(fname));
		{$IFDEF WIN32}
		OemToChar(@fname[1], @fname[1]);
		{$ELSE}
		OemToAnsi( StringAsPChar(fname),StringAsPChar(fname) );
		{$ENDIF}
	 end;
  SetFromLocal( @lrec, fname );
  Frelative_offset := save_offset;
  Result := True;
end;

function TZipHeaderInfo.GetHasComment: Boolean;
begin
  Result := Ffile_comment_length > 0;
end;


procedure TZipHeaderInfo.SetFileComment( FComment: PChar );
begin
  If Ffilecomment <> nil then
     StrDispose(Ffilecomment);
  If FComment <> nil then
   begin
     FfileComment := StrAlloc(StrLen(FComment)+1);
     StrCopy(FfileComment,FComment);
     Ffile_comment_length := StrLen(FComment);
   end
  Else
   begin
     FfileComment := nil;
     Ffile_comment_length := 0;
   end;
end;

procedure TZipHeaderInfo.SetNewFileComment( NewComment: String );
begin
  SetFileComment( StrToPChar(NewComment) );
end;

function TZipHeaderInfo.Getfilecomment( S: TStream ): PChar;
var
  crec: central_file_header;
begin
  Result := nil;
  If HasComment then
   begin
     S.Seek(central_offset, soFromBeginning	);
     S.Read(crec, SizeOf(central_file_header));
     With crec do
      begin
        S.Seek( filename_length+extra_field_length, soFromCurrent);
        Result := StrAlloc( Ffile_comment_length+1 );
        S.Read( Result^, Ffile_comment_length );
        Result[Ffile_comment_length] := #0;
      end;
   end;
end;

function TZipHeaderInfo.GetIsEncrypted: Boolean;
begin
  Result := (general_purpose_bit_flag and 1) <> 0;
end;

function TZipHeaderInfo.GetHasDescriptor: Boolean;
begin
  Result := (general_purpose_bit_flag and 8) <> 0;
end;

function TZipHeaderInfo.GetLocalSize: Integer;
begin
  Result := SizeOf(local_file_header)+ Ffilename_length + Fextra_field_length;
end;

function TZipHeaderInfo.GetCentralSize: Integer;
begin
  Result := SizeOf(central_file_header) + FFilename_length + Fextra_field_length +
              Ffile_comment_length;
end;

procedure TZipHeaderInfo.Setfilename( FName: String );
begin
  If FName <> Ffilename then
   begin
     Ffilename := FName;
     Ffilename_length := Length(Fdirectory) + Length(Ffilename);
   end;
end;

procedure TZipHeaderInfo.Setdirectory( Directory: String );
var
  tmpDirectory: String;
begin
  If (Directory <> '') and (RightStr(Directory,1) <> '\') then
     tmpDirectory := Directory + '\'
  Else
     tmpDirectory := Directory;
  If tmpDirectory <> Fdirectory then
   begin
     Fdirectory := tmpDirectory;
     Ffilename_length := Length(Fdirectory) + Length(Ffilename);
   end;
end;

procedure TZipHeaderInfo.SetDateTime( DateTime: TDateTime );
begin
  Flast_mod_file_date_time := DateTimeToFileDate(DateTime);
end;

{*****************  TEndCentral Methods *********************}
Constructor TEndCentral.Create;
begin
  inherited Create;
  Clear;
end;

Destructor TEndCentral.Destroy;
begin
  If (FZipComment <> nil) then
     StrDispose(FZipComment);
  inherited Destroy;
end;

procedure TEndCentral.AssignTo(Dest: TPersistent);
var
  finfo: TEndCentral;
begin
	If Dest is TEndCentral then
   begin
     finfo := TEndCentral(Dest);
     finfo.ecrec := Fecrec;
     If (Fecrec.zip_comment_length > 0) and (FZipComment <> nil) then
      begin
        If finfo.ZipComment <> nil then
           StrDispose( finfo.ZipComment );
        finfo.ZipComment := StrAlloc( StrLen(FZipComment)+1 );
        StrCopy( finfo.ZipComment, FZipComment );
        finfo.zip_comment_length := StrLen(finfo.ZipComment);
      end;
     finfo.ZipCommentPos := FZipCommentPos;
   end
  else inherited AssignTo(Dest);
end;

procedure TEndCentral.Assign(Source: TPersistent);
var
  finfo: TEndCentral;
begin
	If Source is TEndCentral then
   begin
   	finfo := TEndCentral(Source);
     Fecrec := finfo.ecrec;
     If (finfo.zip_comment_length > 0) and (finfo.ZipComment <> nil) then
      begin
        If FZipComment <> nil then
           StrDispose(FZipComment);
        FZipComment := StrAlloc( StrLen(finfo.ZipComment)+1 );
        StrCopy( FZipComment, finfo.ZipComment );
        Fecrec.zip_comment_length := StrLen(FZipComment);
      end;
     FZipCommentPos := finfo.ZipCommentPos;
	 end
	else inherited Assign(Source);
end;

procedure TEndCentral.SetFromEndCentral( crec: end_of_centralPtr );
begin
  Fecrec := crec^;
	FZipCommentPos := 0;
  If FZipComment <> nil then
     StrDispose(FZipComment);
  FZipComment := nil;
end;

procedure TEndCentral.Clear;
begin
  With Fecrec do
   begin
     ID := $06054b50;
     this_disk := 0;
     start_central_disk := 0;
     num_entries_this_disk := 0;
     num_entries := 0;
     size_central := 0;
     offset_central := 0;
     zip_comment_length := 0;
   end;
   If (FZipComment <> nil) then
     StrDispose(FZipComment);
   FZipComment := nil;
   FZipCommentPos := 0;
   FModified := False;
end;

procedure TEndCentral.SaveToStream( S: TStream );
begin
  S.Write( Fecrec, SizeOf(Fecrec) );
  If (Fecrec.zip_comment_length > 0)  and (FZipComment <> nil) then
     S.Write( FZipComment^, StrLen(FZipComment) );
end;

function TEndCentral.ReadFromStream( S: TStream ): Boolean;
var
  tmpBuff: PChar;
  tmpBuffsize: WORD;
  peoc: end_of_centralPtr;
  j: LongInt;
  AmtRead: LongInt;
begin
   Result := False;
   If S.Size < sizeof(end_of_central) then
     exit;  { 1/28/98 v2.00+}
   tmpBuffsize := min(S.Size,$FFF8);
   S.Seek( -tmpBuffsize, soFromEnd	);
	 GetMem( tmpBuff, tmpBuffsize );
   try
   	AmtRead := S.Read( tmpBuff^, tmpBuffsize );
     If AmtRead <> tmpBuffsize then
        exit;
   	j := tmpBuffsize - (sizeof(end_of_central));
   	peoc := nil;
   	while (j >= 0) and (peoc = nil) do
    	 begin
   		while (j >= 0) and (Byte(tmpBuff[j]) <> $50) do
   			Dec(j);
        If (j < 0) then
           break;
    		peoc := @tmpBuff[j];
     	If peoc^.ID <> $06054b50 then
      	 begin
      		Dec(j);
     		peoc := nil;
      	 end;
    	 end;
   	If peoc = nil then
        exit;
     With Fecrec do
      begin
   		this_disk := peoc^.this_disk;
   		start_central_disk := peoc^.start_central_disk;
   		num_entries_this_disk := peoc^.num_entries_this_disk;
   		num_entries := peoc^.num_entries;
   		size_central := peoc^.size_central;
   		offset_central := peoc^.offset_central;
   		zip_comment_length := peoc^.zip_comment_length;
   		{FZipHasComment := ecrec.zip_comment_length > 0;}
   		ZipCommentPos := S.Size -  Fecrec.zip_comment_length;
      end;
     Result := True;
   finally
		FreeMem(tmpBuff, tmpBuffsize);
   end;
end;

function TEndCentral.GetZipHasComment: Boolean;
begin
  Result := (zip_comment_length > 0);
end;

procedure TEndCentral.SetNewZipComment( NewComment: String );
begin
  If FZipComment <> nil then
     StrDispose(FZipComment);
  FZipComment := StrToPChar( NewComment );
  Fecrec.zip_comment_length := Length(NewComment);
end;

function TEndCentral.GetZipComment( S: TStream ): PChar;
begin
	If Fecrec.zip_comment_length = 0 then
  	Result := nil
  Else If FZipComment <> nil then
     Result := FZipComment
  Else
   With Fecrec do
    begin
      	S.Seek( FZipCommentPos, soFromBeginning );
        Result := StrAlloc( zip_comment_length+1 );
        S.Read( Result^, zip_comment_length );
        Result[zip_comment_length] := #0;
    end;
end;

function TEndCentral.GetEndCentralSize: LongInt;
begin
  Result := SizeOf(end_of_central) + Fecrec.zip_comment_length;
end;

{*****************  TSortedZip Methods *******************}

Constructor TSortedZip.Create( WithDuplicates: TDuplicates );
begin
  Inherited Create( WithDuplicates );
  SortMode := ByNone;
end;

function TSortedZip.Compare(Key1, Key2:Pointer):Integer;
var
	K1 : TZipHeaderInfo absolute Key1;
	K2 : TZipHeaderInfo absolute Key2;
	tmpDateTime1, tmpDateTime2: TDateTime;
  tmpSize: LongInt;
begin
  Case FSortMode of
     ByName:
        Result := CompareText( K1.directory+K1.filename, K2.directory+K2.filename );
     ByFileName:
			Result := CompareText( K1.filename, K2.filename );
     ByDirectoryName:
        Result := CompareText( K1.Directory, K2.directory );
     ByDate:
        begin
           try
              tmpDateTime1 := FileDateToDateTime( K1.last_mod_file_date_time );
           except
              tmpDateTime1 := 0;
           end;
           try
              tmpDateTime2 := FileDateToDateTime( K2.last_mod_file_date_time );
           except
              tmpDateTime2 := 0;
           end;
           If (tmpDateTime2 > tmpDateTime1) then
              Result := 1
           else
              Result := -1;
        end;
     ByCompressedSize:
        begin
           tmpSize := K2.compressed_size - K1.compressed_size;
           If (tmpSize > 0) then
              Result := 1
           else
              Result := -1;
        end;
     ByUnCompressedSize:
        begin
           tmpSize := K2.uncompressed_size - K1.uncompressed_size;
           If (tmpSize > 0) then
              Result := 1
           else
              Result := -1;
        end;
     ByRate:
        Result := CRate(K2.uncompressed_size,K2.compressed_size) -
                  CRate(K1.uncompressed_size,K1.compressed_size);
     ByNone:
        begin
           Result := K1.disk_number_start - K2.disk_number_start;
           If Result = 0 then { modified 3/8/98 for 2.03 }
            begin             { this fixed the duplicate object bug }
              If K1.relative_offset > K2.relative_offset then
                 Result := 1
              Else if K1.relative_offset = K2.relative_offset then
                 Result := 0
              Else Result := -1;
            end;
        end;
     else Result := -1;
  end;
{
	If Result = 0 then
		Result := -1;
}
end;

function DRun: Boolean;
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

end.
