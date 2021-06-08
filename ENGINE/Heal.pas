unit Heal;

interface
uses windows, sysutils, classes, NewPE, BoyerMoore, RC4Unit, Wildcards, dialogs;


function NShield_Heal_Smellsme(const FileName: string): boolean;
function NShield_Heal_Mumawow(const FileName: string): boolean;
function NShield_Heal_Ramnit_B(const FileName: string): boolean;
function NShield_Heal_Runouce(const FileName: string): boolean;
function NShield_Heal_Annie_HTML(const FileName: string; const offsetVX: integer): boolean;
function NShield_Heal_Dorifel(const FileName: string; Offset: integer; const Key: string): boolean;

function NShield_HexStrToStr(HexStr : string): string;
function NShield_Hex2Dec(data: string): byte;
function NShield_FileToString(const FileName: string; const Length : Integer = -1): AnsiString;

    //Base on ImageBase, rutin dari UntPeFile tidak sesuai yg diinginkan
    function  _RvaToVa(const PE : TPeFile; const RVA: Cardinal): Cardinal;
    function  _VaToRva(const PE : TPeFile; const VA: Cardinal): Cardinal;
    function  _VaToFileOffset(const PE : TPeFile; const VA: Cardinal): Cardinal;
    function  HexToInt(const HexStr: string): longint;
    function  StrToHex(a: array of char): string;

const SmellsMePattern = '---DEVILSTILLSMELLSME---MZ';

implementation


procedure StringToFile(String2BeSaved, FileName: string);
var
  MyStream: TMemoryStream;
begin
  if String2BeSaved = '' then exit;
  MyStream := TMemoryStream.Create;
  try
    MyStream.WriteBuffer(Pointer(String2BeSaved)^, Length(String2BeSaved));
    MyStream.SaveToFile(FileName);
  finally
    MyStream.Free;
  end;
end;

function NShield_Hex2Dec(data: string): byte;
var
  nH1, nH2: byte;
begin
  if data[1] in ['0'..'9'] then nh1 := strtoint(data[1])
  else nh1 := 9 + ord(data[1]) - 64;
  if data[2] in ['0'..'9'] then nh2 := strtoint(data[2])
  else nh2 := 9 + ord(data[2]) - 64;
  result := nh1 * 16 + nh2;
end;

//Konversi hexadecimal string ke string
function NShield_HexStrToStr(HexStr : string): string;
var
  BufStr : string;
  LenHex : integer;
  x,y : integer;
begin
  LenHex := Length(HexStr) div 2;
  x := 1;
  y := 0;
  while y <> LenHex do
  begin
    inc(y);
    BufStr := BufStr + Chr(NShield_Hex2Dec(HexStr[x] + HexStr[x+1]));
    inc(x, 2);
  end;
  result := BufStr;
end;

function NShield_FileToString(const FileName: string; const Length : Integer = -1): AnsiString;
var
  fs: TFileStream;
  Len: Integer;
begin
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    if FS = nil then exit;
    //jika inputan length = -1 atau inputan length melebihi ukuran file sebenarnya maka
    //atur length sepanjang ukuran file tersebut
    if (Length < 0) or (Length > FS.Size) then
      Len := FS.Size
    else
      Len := Length;
    SetLength(Result, Len);
    //PCMAV 1.3. Error EReadError saat ReadBuffer. Maka ditambahkan error exception.
    try
      if Len > 0 then
        fs.ReadBuffer(Result[1], Len);
    except
      on E: EReadError do Result := '';
    end;
  finally
    fs.Free;
  end;
end;

function _RvaToVa(const PE : TPeFile; const RVA: Cardinal): Cardinal;
begin
  Result := RVA + PE.ImageBase;
end;

//Remember: RVA = VA - ImageBase
function _VaToRva(const PE : TPeFile; const VA: Cardinal): Cardinal;
begin
  Result := VA - PE.ImageBase;
end;

function _VaToFileOffset(const PE : TPeFile; const VA: Cardinal): Cardinal;
var
  RVA : Cardinal;
begin
  RVA := (VA - PE.ImageBase);
  Result := (RVA) - (PE.ImageSections[PE.RvaToSection(RVA)].VirtualAddress) + (PE.ImageSections[PE.RvaToSection(RVA)].PointerToRawData);
end;

function HexToInt(const HexStr: string): longint;
var
  iNdx: integer;
  cTmp: Char;
begin
  result := 0;
  for iNdx := 1 to Length(HexStr) do
  begin
    cTmp := HexStr[iNdx];
    case cTmp of
      '0'..'9': Result := 16 * Result + (Ord(cTmp) - $30);
      'A'..'F': Result := 16 * Result + (Ord(cTmp) - $37);
      'a'..'f': Result := 16 * Result + (Ord(cTmp) - $57);
    else
      raise EConvertError.Create('There''s an error char!');
    end;
  end;
end;


function StrToHex(a: array of char): string;
var
  i,j: byte;
  s: string;
begin
  j := length(a) - 1;
  for i := 0 to j do
  begin
    s := s + inttohex(ord(a[i]), 2);
  end;
  StrToHex := s;
end;

//==============================================================================
//Cleaning Dorifel
//==============================================================================
function NShield_Heal_Dorifel(const FileName: string; Offset: integer; const Key: string): boolean;
const

  ExtLength = 5;       //'.exe' atau '.scr' atau '.docx'

  function StringToHex(S: String): String;
  var I: Integer;
  begin
    Result:= '';
    for I := 1 to length (S) do
      Result:= Result+IntToHex(ord(S[i]),2);
  end;

  function ExtractFilePathWithoutExt(const Path: string): string;
  var
    I: Integer;
  begin
    I := LastDelimiter(':.' + '\', Path);
    if (I > 0) and (Path[I] = '.') then
      Result := Copy(Path, 1, I - 1)
    else
      Result := Path;
  end;

  function GetExtension(const DecryptedDoc: ansistring; var newFilename: string): string;
  var
    FileExt    : string;
    HeaderFile : string;
    tmpfilename: string;

  begin

     FileExt := '';
     tmpfilename := copy(newfilename, length(newfilename)-7,4);
     tmpfilename := StringToHex( tmpfilename );

     //jika 4 karakter terakhir nama file: #$202E'cod
     if tmpfilename = '202E636F64' then
     begin
       newfilename := copy(newfilename, 1, length(newfilename)-8);
       FileExt := '.doc';
     end;

     //jika 4 karakter terakhir nama file: #$202E'slx
     if tmpfilename = '202E736C78' then
     begin
       newfilename := copy(newfilename, 1, length(newfilename)-8);
       FileExt := '.xls';
     end;

     HeaderFile := copy( DecryptedDoc, 1, 2 );
     HeaderFile := StringToHex( HeaderFile );

     if HeaderFile = '4D5A' then // exe
     begin
       FileExt := '.exe';
     end;

     if HeaderFile = 'D0CF' then // mungkin doc/xls
     begin
       // Word.Document
       if (PatternMatchingStr(DecryptedDoc, '576F72642E446F63756D656E742E', 14) > -1) then
       begin
         FileExt := '.doc';
       end

       // Microsoft Office Excel
       // Pattern: 0908100000060500 di offset 0x200 atau 512 decimal (ini adalah subheader)
       else if (PatternMatchingStr(DecryptedDoc,'0908100000060500', 8) = 512) then
       begin
         FileExt := '.xls';
       end;
     end;

     //Word 2007
     if HeaderFile = '504B' then
     begin
        //word/document
        if (PatternMatchingStr(DecryptedDoc, '776F72642F646F63756D656E74', 13) > -1) then
        begin
          FileExt := '.docx';
        end
        //xl/workbook.xml
        else if (PatternMatchingStr(DecryptedDoc, '786C2F776F726B626F6F6B2E786D6C', 15) > -1) then
        begin
          FileExt := '.xlsx';
        end;

     end;

     Result := FileExt;
  end;

var
  FS           : TFileStream;
  FileSize,
  DocumentSize : Int64;
  Document     : ansistring;
  DecryptedDoc : ansistring;
  DocumentName : string;
  Ext          : String[ExtLength];
  OriginalFileDateTime, OriginalFileAttribute : integer;
  newFilename  : string;

begin
  Result := False;
  if FileExists(FileName) then
  begin

    //backup datetime file
    OriginalFileDateTime  := FileAge(FileName);
    //backup attributes file
    OriginalFileAttribute := GetFileAttributes(PChar(FileName));
    //ubah attribut file menjadi normal
    SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_NORMAL);
    //Buka file untuk dibaca
    FS  := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    //Dapatkan file size
    FileSize := FS.Size;

    try
      Ext := LowerCase(ExtractFileExt(FileName));
      if (Ext = '.scr') or (Ext = '.exe') then
      begin
        //Dokumen size = ukuran file - ukuran tubuh virus saat menginfeksi
        DocumentSize := FileSize - Offset; // - Offset Marker_Virus;
        //Set pointer ke offset awal dokumen yang akan di extract
        FS.Seek(Offset, soFromBeginning);
        //Set ukuran buffer sebesar ukuran file dokumen yang akan di-extract
        SetLength(Document, DocumentSize);
        //Dokumen size > 0? Artinya apakah ada data yang akan disimpan di buffer?
        if DocumentSize > 0 then
        begin
          //Baca byte-per-byte sebanyak ukuran dokumen yg akan di-extract, simpan di Buffer!
          FS.Read(Document[1], DocumentSize);
        end
        else exit;
      end
      else
      begin
        Result := False;
        exit;
      end;
    finally
      FS.Free;
    end;
    try
      //decrypt RC4
      DecryptedDoc := RC4( Document, NShield_HexStrToStr(uppercase( Key )) );

      //Dapatkan ext yang sebenarnya
      newFilename := Filename;
      Ext := GetExtension(DecryptedDoc, newFilename);

      //hapus 7 byte terakhir
      DecryptedDoc := copy( DecryptedDoc, 1, length( DecryptedDoc ) - 7 );

      DocumentName := ExtractFilePathWithoutExt(newFilename) + Ext;
      //Sudah ada nama file (sama seperti nama file yg akan di-extract) di direktori tersebut
      //Dan jika nama dokumen yang akan di-extract tidak sama dengan nama file yg sedang diperiksa maka
      if (FileExists(DocumentName) and (LowerCase(DocumentName) <> LowerCase(FileName))) then
      begin
        SetFileAttributes(PChar(DocumentName), FILE_ATTRIBUTE_NORMAL);
        //cek hashing, kalo sama overwrite
        //if FileMD5Digest(DocumentName) <> StringMD5Digest(Document) then
          //DocumentName := ExtractFilePathWithoutExt(newFilename) + '~' + Ext;
      end;
      //Save dari buffer ke file
      StringToFile(DecryptedDoc, DocumentName);
      //Restore tanggal file asli
      FileSetDate(DocumentName, OriginalFileDateTime); //restore datetime
      //Restore attribute file asli
      SetFileAttributes(PChar(DocumentName), OriginalFileAttribute); //restore attributes
      if (LowerCase(DocumentName) <> LowerCase(FileName)) then DeleteFile(FileName);
      //Everthing is Ok!
      Result := True;
    except
      //Kalau ada masalah, then RESULT := FALSE!
      Result := False;
    end;
  end;
end;

function NShield_Heal_Ramnit_B(const FileName: string): boolean;
const
  ID = 'FFD0FFB5BDAD0120FF958EAE01208B8581AC01202B8589AC01208944241C61';
  ID_LENGTH = 31;
  Offset_OEP = $770;  //posisi OEP dari file offset body virus

  function ScanFile(const FileName : string): boolean;
  var
    buf : AnsiString;
  begin
    result := false;
    buf := NShield_FileToString(FileName);
    if NShield_BM_SearchString(NShield_HexStrToStr(ID), Buf, 1) > 0 then
      result := true;
    buf := '';
  end;

var
  FS  : TFileStream;
  OutputZero   : boolean; //Kalau dia tidak menginfeksi exe lainnya, tapi hanya tubuhnya saja
  FileSize,
  OutputBeginOffset,
  OutputSize   : Int64;
  OutputBuf    : AnsiString;
  OriginalFileDateTime, OriginalFileAttribute : integer;

   //Handle dan Buffer
  PE            : TPeFile;

  //Variable penyimpan nilai penting dari file
  VirusBodySize          : Cardinal;
  vxPESizeOfImage        : Cardinal;
  NewRawSize             : Cardinal;
  NewVirtualSize         : Cardinal;
  vxPos                  : Dword; //Alamat RAW virus
  vxSectionNum           : Word; // section tempat virus berdiam
  EPFileOffset           : Cardinal;
  EPSign                 : array[0..7] of char; // untuk baca 7 bytes di awal EntryPoint
  EP_RVA                 : Integer;
  EP_RAW                 : Integer;
  TotalSection           : dword; //Jumlah section. Funlove ada di section terakhir.
  Pattern_EP_Real        : array[1..4] of char;
  Pattern_EP_Real_Temp   : array[1..4] of char;
  Real_SizeOfLastSection : Integer;
  VariantSize            : Cardinal;
  Temp                   : Cardinal;

  function TryFileOpen(Const FileName: String): Boolean;
  var
    fhandle: Integer;
  begin
    Result := False;
    try
      fhandle := FileOpen(FileName, fmShareDenyWrite);
      if fhandle > 0 then
      begin
        Result := True;
        FileClose(fhandle);
      end;
    except
      Result := False
    end;
  end;

begin
  Result := False;
  OutputZero := False;
  // KillExeByPath(FileName);
  OriginalFileDateTime  := FileAge(FileName); //backup datetime
  OriginalFileAttribute := GetFileAttributes(PChar(FileName)); //backup attributes
  //ubah attribut file menjadi normal
  SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_NORMAL);

  repeat
    if FileExists(FileName) then
    begin
      PE := TPeFile.Create;
      try
         if PE.LoadFromFile(FileName) then
         begin
           // EPFileOffset := PE.RvaToFileOffset(PE.AddressOfEntryPoint);
           try
           EPFileOffset := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           PE.CopyMemoryFromBuffer(EPFileOffset + Offset_OEP, @(EPSign), SizeOf(EPSign));
           except
              exit;
           end;
           if (EPFileOffset = 0) then exit;

           Pattern_EP_Real[1] := EPSign[4];
           Pattern_EP_Real[2] := EPSign[3];
           Pattern_EP_Real[3] := EPSign[2];
           Pattern_EP_Real[4] := EPSign[1];

           // tentukan offset awal virus
           vxPos := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           vxSectionNum := PE.FileOffsetToSection(vxPos);
           vxPESizeOfImage := PE.ImageNtHeaders.OptionalHeader.SizeOfImage;

           // hapus overlay virus
           PE.DeleteBytes(PE.ImageSections[High(PE.ImageSections)].PointerToRawData,PE.FileSize - (PE.ImageSections[High(PE.ImageSections)].PointerToRawData + PE.ImageSections[High(PE.ImageSections)].SizeOfRawData));

           // hapus section virus
           VirusBodySize := PE.ImageSections[vxSectionNum].SizeOfRawData;
           PE.DeleteSection(vxSectionNum, false, false);
           PE.ImageNtHeaders.OptionalHeader.SizeOfImage := PE.Align(vxPESizeOfImage - PE.Align(VirusBodySize, PE.SectionAlign), PE.SectionAlign);

           // kembalikan OEP
           PE.AddressOfEntryPoint := PE.AddressOfEntryPoint - HexToInt(StrToHex(Pattern_EP_Real));

           if NOT PE.SaveToFile(FileName) then
              exit;

           Result := True;
         end;
      finally
         PE.Free;
      end;
    end;

  until (not FileExists(FileName)) or (ScanFile(FileName) = False);
  if FileExists(FileName) then
  begin
    FileSetDate(FileName, OriginalFileDateTime); //restore datetime
    SetFileAttributes(PChar(FileName), OriginalFileAttribute); //restore attributes
  end;
end;

//belum fix
function NShield_Heal_Runouce(const FileName: string): boolean;
const
  //17 hexa kalau CMC
  Offset_OEP = $B;  //posisi yang menunjukkan OEP dari file offset EP di body virus


var
  OriginalFileDateTime, OriginalFileAttribute : integer;

   //Handle dan Buffer
  PE            : TPeFile;

  //Variable penyimpan nilai penting dari file
  VirusBodySize          : Cardinal;
  vxPESizeOfImage        : Cardinal;
  vxPos                  : Dword; //Alamat RAW virus
  vxSectionNum           : Word; // section tempat virus berdiam
  EPFileOffset           : Cardinal;
  EPSign                 : array[0..6] of char; // untuk baca 6 bytes di awal EntryPoint
  Pattern_EP_Real        : array[0..6] of char;

begin

  Result := False;

  // KillExeByPath(FileName);
  OriginalFileDateTime  := FileAge(FileName); //backup datetime
  OriginalFileAttribute := GetFileAttributes(PChar(FileName)); //backup attributes
  //ubah attribut file menjadi normal
  SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_NORMAL);

  repeat
    if FileExists(FileName) then
    begin
      PE := TPeFile.Create;
      try
         if PE.LoadFromFile(FileName) then
         begin
           // EPFileOffset := PE.RvaToFileOffset(PE.AddressOfEntryPoint);
           try
           EPFileOffset := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           showmessage(inttostr(EPFileOffset)); //valuenya 775680
           PE.CopyMemoryFromBuffer(EPFileOffset - Offset_OEP, @(EPSign), SizeOf(EPSign));

           except
              exit;
           end;
           if (EPFileOffset = 0) then exit;

           Pattern_EP_Real[1] := EPSign[1];
           Pattern_EP_Real[2] := EPSign[2];
           Pattern_EP_Real[3] := EPSign[3];
           Pattern_EP_Real[4] := EPSign[4];
           Pattern_EP_Real[5] := EPSign[5];
           Pattern_EP_Real[6] := EPSign[6];

           // tentukan offset awal virus
           vxPos := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           showmessage(inttostr(vxpos));
           vxSectionNum := PE.FileOffsetToSection(vxPos);
           vxPESizeOfImage := PE.ImageNtHeaders.OptionalHeader.SizeOfImage;

           // hapus section virus
           //VirusBodySize := PE.ImageSections[vxSectionNum].SizeOfRawData;
           //PE.DeleteSection(vxSectionNum, false, false);
           //PE.ImageNtHeaders.OptionalHeader.SizeOfImage := PE.Align(vxPESizeOfImage - PE.Align(VirusBodySize, PE.SectionAlign), PE.SectionAlign);

           // kembalikan OEP
           showmessage(StrToHex(Pattern_EP_Real));
           PE.AddressOfEntryPoint := HexToInt(StrToHex(Pattern_EP_Real)); // - X;

           if NOT PE.SaveToFile(FileName) then
              exit;

           Result := True;

         end;
      finally
         PE.Free;
      end;
    end;

  until (not FileExists(FileName));// or (ScanFile(FileName) = False);
  if FileExists(FileName) then
  begin
    FileSetDate(FileName, OriginalFileDateTime); //restore datetime
    SetFileAttributes(PChar(FileName), OriginalFileAttribute); //restore attributes
  end;
end;

function NShield_Heal_Mumawow(const FileName: string): boolean;
const
  ID = '433A5C57494E444F57535C73797374656D33325C494D455C737663686F73742E65786500000000000000000000006F63637572656400000073746172746564000000656E6465640000000000000000000000000000000000687474703A2F2F7777772E6A6179792E6F72672F746F702E7478740076666268';
  ID_LENGTH = 60;
  Offset_OEP = $76F;  //posisi yang menunjukkan OEP dari file offset EP di body virus
  //X = $400000;

  function ScanFile(const FileName : string): boolean;
  var
    buf : AnsiString;
  begin
    result := false;
    buf := NShield_FileToString(FileName);
    if NShield_BM_SearchString(NShield_HexStrToStr(ID), Buf, 1) > 0 then
      result := true;
    buf := '';
  end;

var
  OriginalFileDateTime, OriginalFileAttribute : integer;

   //Handle dan Buffer
  PE            : TPeFile;

  //Variable penyimpan nilai penting dari file
  VirusBodySize          : Cardinal;
  vxPESizeOfImage        : Cardinal;
  vxPos                  : Dword; //Alamat RAW virus
  vxSectionNum           : Word; // section tempat virus berdiam
  EPFileOffset           : Cardinal;
  EPSign                 : array[0..7] of char; // untuk baca 7 bytes di awal EntryPoint
  Pattern_EP_Real        : array[1..4] of char;

begin

  //FCureFile := False;
  Result := False;

  OriginalFileDateTime  := FileAge(FileName); //backup datetime
  OriginalFileAttribute := GetFileAttributes(PChar(FileName)); //backup attributes
  //ubah attribut file menjadi normal
  SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_NORMAL);

  repeat
    if FileExists(FileName) then
    begin
      //KillExeByPath(FileName);
      PE := TPeFile.Create;
      try
         if PE.LoadFromFile(FileName) then
         begin
           // EPFileOffset := PE.RvaToFileOffset(PE.AddressOfEntryPoint);
           try
           EPFileOffset := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           PE.CopyMemoryFromBuffer(EPFileOffset - Offset_OEP, @(EPSign), SizeOf(EPSign));
           except
              exit;
           end;
           if (EPFileOffset = 0) then exit;

           Pattern_EP_Real[1] := EPSign[4];
           Pattern_EP_Real[2] := EPSign[3];
           Pattern_EP_Real[3] := EPSign[2];
           Pattern_EP_Real[4] := EPSign[1];

           // tentukan offset awal virus
           vxPos := _VaToFileOffset(PE,  _RvaToVa(PE, PE.AddressOfEntryPoint));
           vxSectionNum := PE.FileOffsetToSection(vxPos);
           vxPESizeOfImage := PE.ImageNtHeaders.OptionalHeader.SizeOfImage;

           // hapus section virus
           VirusBodySize := PE.ImageSections[vxSectionNum].SizeOfRawData;
           PE.DeleteSection(vxSectionNum, false, false);
           PE.ImageNtHeaders.OptionalHeader.SizeOfImage := PE.Align(vxPESizeOfImage - PE.Align(VirusBodySize, PE.SectionAlign), PE.SectionAlign);

           // kembalikan OEP
           //showmessage(StrToHex(Pattern_EP_Real));
           PE.AddressOfEntryPoint := HexToInt(StrToHex(Pattern_EP_Real)); // - X;

           if NOT PE.SaveToFile(FileName) then
              exit;

           Result := True;
           //FCureFile := True;
         end;
      finally
         PE.Free;
      end;
    end;

  until (not FileExists(FileName)) or (ScanFile(FileName) = False);
  if FileExists(FileName) then
  begin
    FileSetDate(FileName, OriginalFileDateTime); //restore datetime
    SetFileAttributes(PChar(FileName), OriginalFileAttribute); //restore attributes
  end;
end;
{
  ScanFile searches for a string in a file and returns the position of the string
  in the file or -1, if not found.
}
function ScanFile(const FileName: string;
  const forString: string;
  caseSensitive: Boolean): Longint;
const
  BufferSize = $8001;  { 32K+1 bytes }
var
  pBuf, pEnd, pScan, pPos: PChar;
  filesize: LongInt;
  bytesRemaining: LongInt;
  bytesToRead: Integer;
  F: file;
  SearchFor: PChar;
  oldMode: Word;
begin
  { assume failure }
  Result := -1;
  if (Length(forString) = 0) or (Length(FileName) = 0) then Exit;
  SearchFor := nil;
  pBuf      := nil;
  { open file as binary, 1 byte recordsize }
  AssignFile(F, FileName);
  oldMode  := FileMode;
  FileMode := 0;    { read-only access }
  Reset(F, 1);
  FileMode := oldMode;
  try { allocate memory for buffer and pchar search string }
    SearchFor := StrAlloc(Length(forString) + 1);
    StrPCopy(SearchFor, forString);
    if not caseSensitive then  { convert to upper case }
      AnsiUpper(SearchFor);
    GetMem(pBuf, BufferSize);
    filesize       := System.Filesize(F);
    bytesRemaining := filesize;
    pPos           := nil;
    while bytesRemaining > 0 do
    begin
      { calc how many bytes to read this round }
      if bytesRemaining >= BufferSize then
        bytesToRead := Pred(BufferSize)
      else
        bytesToRead := bytesRemaining;
      { read a buffer full and zero-terminate the buffer }
      BlockRead(F, pBuf^, bytesToRead, bytesToRead);
      pEnd  := @pBuf[bytesToRead];
      pEnd^ := #0;
      pScan := pBuf;
      while pScan < pEnd do
      begin
        if not caseSensitive then { convert to upper case }
          AnsiUpper(pScan);
        pPos := StrPos(pScan, SearchFor);  { search for substring }
        if pPos <> nil then
        begin { Found it! }
          Result := FileSize - bytesRemaining +
            Longint(pPos) - Longint(pBuf);
          Break;
        end;
        pScan := StrEnd(pScan);
        Inc(pScan);
      end;
      if pPos <> nil then Break;
      bytesRemaining := bytesRemaining - bytesToRead;
      if bytesRemaining > 0 then
      begin
        Seek(F, FilePos(F) - Length(forString));
        bytesRemaining := bytesRemaining + Length(forString);
      end;
    end; { While }
  finally
    CloseFile(F);
    if SearchFor <> nil then StrDispose(SearchFor);
    if pBuf <> nil then FreeMem(pBuf, BufferSize);
  end;
end; { ScanFile }


function ExtractFilePathWithoutExt(const Path: string): string;
  var
    I: Integer;
  begin
    I := LastDelimiter(':.' + '\', Path);
    if (I > 0) and (Path[I] = '.') then
      Result := Copy(Path, 1, I - 1)
    else
      Result := Path;
end;


{fungsi untuk memberisihkan file yang terinfeksi oleh smellsme}
function NShield_Heal_Smellsme(const FileName: string): boolean;
var
  FS  : TFileStream;
  FileSize     : Int64;
  Document     : AnsiString;
  DocumentName : string;
  DocumentSize : Int64;
  vx_offset    : integer;
begin

  // tentukan posisi awal dari MZ
  vx_offset := ScanFile(Filename,SmellsMePattern,True) + length(SmellsMePattern) - 2;

  //Buka file untuk dibaca
  FS  := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  //Dapatkan file size
  FileSize := FS.Size;

  try
      DocumentName := FileName;
      //Dokumen size = ukuran file - posisi marker virus
      DocumentSize := FileSize - vx_offset;
      //Set pointer ke offset awal dokumen yang akan di extract
      FS.Seek(vx_offset, soFromBeginning);
      //Set ukuran buffer sebesar ukuran file dokumen yang akan di-extract
      SetLength(Document, DocumentSize);
      //Dokumen size > 0? Artinya apakah ada data yang akan disimpan di buffer?
      if DocumentSize > 0 then
      begin
        //Baca byte-per-byte sebanyak ukuran dokumen yg akan di-extract, simpan di Buffer!
        FS.Read(Document[1], DocumentSize);
      end;

  finally
    FS.Free;
  end;
  DocumentName := ExtractFilePathWithoutExt(FileName) + '.exe';
  try
    StringToFile(Document, DocumentName);

    //Everthing is Ok!
    Result := True;
  except
    //Kalau ada masalah, then RESULT := FALSE!
    Result := False;
  end;
end;

function NShield_Heal_Annie_HTML(const FileName: string; const offsetVX: integer): boolean;
var
  FS           : TFileStream;
  FileSize,
  DocumentSize : Int64;
  Document     : AnsiString;
  DocumentName : string;
  OriginalFileDateTime, OriginalFileAttribute : integer;
  InfectedBy   : string;
  NewFileName  : string;

begin
  Result := False;
  if FileExists(FileName) then
  begin

    //backup datetime file
    OriginalFileDateTime  := FileAge(FileName);
    //backup attributes file
    OriginalFileAttribute := GetFileAttributes(PChar(FileName));
    //ubah attribut file menjadi normal
    SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_NORMAL);
    //Buka file untuk dibaca

    FS  := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
        //Dapatkan file size
        FileSize := FS.Size;
        DocumentName := Filename;

        //Set pointer ke offset awal dokumen yang akan di extract
        FS.Seek(0, soFromBeginning);
        //Set ukuran buffer sebesar ukuran file dokumen yang akan di-extract
        SetLength(Document, OffsetVX);
        if FileSize > 0 then
        begin
          //Baca byte-per-byte sebanyak ukuran dokumen yg akan di-extract, simpan di Buffer!
          FS.Read(Document[1], OffsetVX);

           // hapus header Annie
          if Copy(Document, 1, 30) = '<!--[ANNIE83E333BF08546819]-->' then
             Delete(Document,1,32);
        end
        else exit;

    finally
      FS.Free;
    end;
    try
      //Sudah ada nama file (sama seperti nama file yg akan di-extract) di direktori tersebut
      //Dan jika nama dokumen yang akan di-extract tidak sama dengan nama file yg sedang diperiksa maka
      //if (FileExists(DocumentName) and (LowerCase(DocumentName) <> LowerCase(FileName))) then
      //begin
      //  SetFileAttributes(PChar(DocumentName), FILE_ATTRIBUTE_NORMAL);
        //cek hashing, kalo sama overwrite, kalo gak simpan dengan nama ex: dokumen.html~
        //if FileMD5Digest(DocumentName) <> StringMD5Digest(Document) then
          //DocumentName := FileName; //+ '~';
     //end;
      //Save dari buffer ke file
      if OffsetVX = 0 then
        // in case file asli yang diinfeksi kosong
        // maka ciptakan file baru yang kosong
        TFileStream.Create(DocumentName,fmCreate)
      else
      StringToFile(Document, DocumentName);
      //Restore tanggal file asli
      FileSetDate(DocumentName, OriginalFileDateTime); //restore datetime
      //Restore attribute file asli
      SetFileAttributes(PChar(DocumentName), OriginalFileAttribute); //restore attributes
      if (LowerCase(DocumentName) <> LowerCase(FileName)) then DeleteFile(FileName);

      //Everthing is Ok!
      Result := True;
    except
      //Kalau ada masalah, then RESULT := FALSE!
      Result := False;
    end;
  end;
end;

end.
