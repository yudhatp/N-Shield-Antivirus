{
  Pe File Unit
  by ErazerZ

  Datum: Dienstag, 17. Juli 2007
  E-Mail: ErazerZ@gmail.com

  Danke geht an ...
    Olli für Resourcen Namen in Strings umwandeln...
    Alan für seine Hilfe mit dem PE-Format... 
    Veritas..

  Musik beim Programmieren...
    50 Cent - Get Rich Or Die Tryin'
    The Game - The Documentary
    The Game - The Documentary Leftover
    T.I. - T.I. vs T.I.P
    Busta Rhymes - The Big Bang
    Clipse - Hell Hath No Fury
    Eminem - The Slim Shady LP
    Eminem - The Marshall Mathers LP
    Eminem - The Eminem Show
    Chamillionaire - The Sound of Revenge
    The Notorious B.I.G - Duets: The Final Chapter
    Crooked I
    Obie Trice - Cheers (yeyyyy)

  Log:
    Sonntag, 24 Juni 2007:
      LoadFromFile
      SaveToFile
      ReadPeHeaders
      Align
      SectionNameToString
      StringToSectionName
      SetAddressOfEntryPoint
      SetImageBase
      RvaToFileOffset
      FileOffsetToRva
      VaToFileOffset
      FileOffsetToVa
      VaToRva
      RvaToVa
      InsertBytes
      DeleteBytes

    Montag, 25 Juni 2007:
      RvaToSection
      FileOffsetToSection
      FindCodeCaves
      AddSection
      DeleteSection
      GetCodeSection
      GetDataSection
      GetResourceSection
      GetImportAddressTable

    Dienstag, 26 Juni 2007:
      GetExportsAddressTable
      GetThreadLocalStorage
      GetResources

    Mittwoch, 27. Juni 2007:
      GetResources erweitert (Languages)

    Freitag, 29. Juni 2007:
      AddSection überarbeitet (Prüft ob Platz vorhanden ist, falls nicht wird neuer eingefügt [FILEALIGN])
      GetDebugDirectory
      GetLoadConfigDirectory
      GetEntryExceptionDirectory

    Sonntag, 1. Juli 2007:
      AddSimpleExeCrypter
      CopyMemoryBuffer

    Dienstag, 10. Juli 2007:
      IAT Auslesen verbessert.
      AddSimpleExeCrypter - Verbessert (wegen eines Stromausfalls musste ich alles neu Programmieren...)

    Donnerstag, 12. Juli 2007:
      DumpSection

    Freitag, 13. Juli 2007:
      RecalcImageSize

    Samstag, 14. Juli 2007:
      CopyMemoryBuffer = CopyMemoryToBuffer (ExeLoader angepasst)
      CopyMemoryFromBuffer
      GetHighestSectionSize
      GetDataFromEOF
      AddSection - jetzt sichert es automatisch die Daten nach dem EOF und hängt diese wieder an.

    Sonntag, 15. Juli 2007:
      CalcChecksum
      RecalcCheckSum
      WriteImageSectionHeader - Schreibt alle ImageSections in die Datei
      SaveToFile - angepasst mit WriteImageSectionHeader
      AddSection - RawSize hinzugefügt,
                   VirtualSize entfernt - wird automatisch von RecalcImageSize berechnet,
                   lpData und dwDataLength hinzugefügt - d.h. man kann Daten an die neue Sektion übergeben, somit wird die Sektion nicht mit 0 Bytes gefüllt
                   ruft jetzt RecalcImageSize und RecalcCheckSum
      DeleteSection - ImageSize wird über RecalcImageSize berechnet,
                      ruft RecalcCheckSum am Ende auf

    Montag, 16. Juli 2007:
      ResizeSection - angefangen

    Dienstag, 16. Juli 2007:
      ResizeSection
      Resources überarbeitet! RVA wurde gefixt! Größe des Entries hinzugefügt!
      Resources Beispiel erweitert und der Pe Unit angepasst! (Dump funktion hinzugefügt!)


  ToDo:
    *) AddSection weiter anpassen! Mit FileAlign 4 funktioniert es nicht!
    *) IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR Parsen.
    *) Imports (einzeln hinzufügen), Exports, Ressourcen im Speicher änderbar machen
    *) weitere folgen ... :)

  Gib mir Credits falls du diese Unit oder Funktionen dieser Unit benutzts!

  -- ErazerZ
}
unit NewPE;

interface

uses Windows;

type
  // Dient der Zwischenspeicherung von Code-Höhlen (Daten die mit 0 Bytes
  // gefüllt sind)
  PCodeCave = ^TCodeCave;
  TCodeCave = packed record
    StartFileOffset: Cardinal;
    StartRVA: Cardinal;
    CaveSize: Cardinal;
  end;

  { IAT }
  PImageImportDescriptor = ^TImageImportDescriptor;
  TImageImportDescriptor = packed record
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  end;
  PImageThunkData = ^TImageThunkData;
  TImageThunkData = packed record
    Name: DWORD;
  end;
  { BOUND IAT }
  PImageBoundImportDescriptor = ^TImageBoundImportDescriptor;
  TImageBoundImportDescriptor = packed record
    TimeDateStamp: DWORD;
    OffsetModuleName: Word;
    NumberOfModuleForwarderRefs: Word;
  end;
  PImageBoundForwarderRef = ^TImageBoundForwarderRef;
  TImageBoundForwarderRef = record
    TimeDateStamp: DWORD;
    OffsetModuleName: Word;
    Reserved: Word;
  end;
  { DELAYED IAT }
  PImgDelayDescr = ^TImgDelayDescr;
  TImgDelayDescr = packed record
    grAttrs: DWORD;
    szName: DWORD;
    phmod: PDWORD;
    pIAT: TImageThunkData;
    pINT: TImageThunkData;
    pBoundIAT: TImageThunkData;
    pUnloadIAT: TImageThunkData;
    dwTimeStamp: DWORD;
  end;

  TImportsType = (itNormal, itBound, itDelay);

  // Dient der Zwischenspeicherung der Imports
  PImportsAPis = ^TImportsAPIs;
  TImportsAPIs = packed record
    ThunkRVA: DWORD;
    ThunkOffset: DWORD;
    ThunkValue: DWORD;
    Hint: Word;
    ApiName: string;
  end;
  PImports = ^TImports;
  TImports = packed record
    LibraryName: string;
    ImportType: TImportsType;
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD; // Offset
    FirstThunk: DWORD;
    IatFunctions: array of TImportsAPIs;
  end;
  PImportsArray = ^TImportsArray;
  TImportsArray = array of TImports;

  // Dient der Zwischenspeicherung der Exports
  PExportAPIs = ^TExportAPIs;
  TExportAPIs = packed record
    Ordinal: Word;
    Rva: DWORD;
    FileOffset: DWORD;
    ApiName: string;
  end;
  PExports = ^TExports;
  TExports = packed record
    LibraryName: string;
    Base: DWORD;
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    NumberOfFunctions: DWORD;
    NumberOfNames: DWORD;
    AddressOfFunctions: DWORD;
    AddressOfNames: DWORD;
    AddressOfNameOrdinals: Word;
    ExportFunctions: array of TExportAPIs;
  end;

  { Thread Local Storage }
  PImageTLSDirectory = ^TImageTLSDirectory;
  TImageTLSDirectory = packed record
    StartAddressOfRawData: DWORD;
    EndAddressOfRawData: DWORD;
    AddressOfIndex: DWORD;
    AddressOfCallBacks: DWORD;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;

  { RESOURCES }
  { Dir Entry }
  PImageResourceDirectoryEntry = ^TImageResourceDirectoryEntry;
  TImageResourceDirectoryEntry = packed record
    Name: DWORD;
    OffsetToData: DWORD;
  end;
  { Data Entry }
  PImageResourceDataEntry = ^TImageResourceDataEntry;
  TImageResourceDataEntry = packed record
    OffsetToData: DWORD;
    Size: DWORD;
    CodePage: DWORD;
    Reserved: DWORD;
  end;
  { Directory }
  PImageResourceDirectory = ^TImageResourceDirectory;
  TImageResourceDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    NumberOfNamedEntries: Word;
    NumberOfIdEntries: Word;
  end;

  // Dient der Zwischenspeicherung der Ressourcen
  {
    TResources
      |--RC_DATA
      |     |-- a01 - 1 -
      |     | - a02 - 2 -
      |--RC_ICON
            |-- MAINICON - 1 -
  }
  TResourceEntries = packed record
    sName: string;
    sLang: string;
    dwDataRVA: DWORD;
    lpData: Pointer;
    dwSize: DWORD;
  end;
  TResourceTyps = packed record
    sTyp: string;
    NameEntries: array of TResourceEntries;
  end;
  TResources = packed record
    Dir: TImageResourceDirectory;
    Entries: array of TResourceTyps;
  end;


  
  TPeFile = class(TObject)
  private
    // Datei
    lpBuffer: Pointer; // Datei im Speicher
    FFileSize: Cardinal;
    FFilename: string;
    // NtHeaders
    FNumberOfSections: Word;
    FAddressOfEntryPoint: Cardinal;
    FImageBase: Cardinal;
    FSectionAlign: Cardinal;
    FFileAlign: Cardinal;
  public
    ImageDosHeader: PImageDosHeader;
    ImageNtHeaders: PImageNtHeaders;
    ImageSections: array of TImageSectionHeader; // alle Sektionen-Header
    constructor Create;
    destructor Destroy; override;
    function LoadFromFile(const sFilename: string): Boolean;
    function SaveToFile(const sFilename: string): Boolean;
    function ValidHeaders: Boolean;
    function ReadPeHeaders: Boolean;
    procedure WriteImageSectionHeader;
    function Align(Value, Align: Cardinal): Cardinal;
    function SectionToString(Section: TImageSectionHeader): string;
    procedure StringToSection(const sSectionName: string; var Section: TImageSectionHeader);
    procedure CopyMemoryToBuffer(CopyToOffset: DWORD; Source: Pointer; Length: DWORD);
    procedure CopyMemoryFromBuffer(CopyFromOffset: DWORD; Destination: Pointer; Length: DWORD);

    // Änderungen
    procedure SetAddressOfEntryPoint(AddressOfEntryPoint: Cardinal);
    procedure SetImageBase(ImageBase: Cardinal);
    // Umrechnungen
    function RvaToFileOffset(dwRVA: Cardinal): Cardinal;
    function FileOffsetToRva(dwFileOffset: Cardinal): Cardinal;
    function VaToFileOffset(dwVA: Cardinal): Cardinal;
    function FileOffsetToVa(dwFileOffset: Cardinal): Cardinal;
    function VaToRva(dwVA: Cardinal): Cardinal;
    function RvaToVa(dwRVA: Cardinal): Cardinal;
    function RvaToSection(dwRVA: Cardinal): Word;
    function FileOffsetToSection(dwFileOffset: Cardinal): Word;
    // Hinzufügen/Entfernen
    function InsertBytes(FromOffset, Count: Cardinal): Cardinal;
    function DeleteBytes(FromOffset, Count: Cardinal): Cardinal;
    function FindCodeCaves(FromOffset, Count: Cardinal): TCodeCave;
    // Sektionen
    function AddSection(const sSectionName: string; RawSize: Cardinal; lpData: Pointer; dwDataLength: Cardinal; dwCharacteristics: Cardinal = IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE): Boolean;
    //function DeleteSection(wSection: Word): Boolean;
    function DeleteSection(wSection: Word; RecalculateImageSize : boolean = TRUE; RecalculateChecksum : boolean = TRUE): Boolean;
    function DumpSection(wSection: Word; sFilename: string): Boolean;
    function GetCharacteristics(dwCharacteristics: DWORD): string;
    function GetCodeSection: Word;
    function GetDataSection: Word;
    function GetResourceSection: Word;
    procedure GetImportAddressTable(var Imports: TImportsArray);
    procedure GetExportsAddressTable(var ExportData: TExports);
    function GetThreadLocalStorage: PImageTLSDirectory;
    procedure GetResources(var Resources: TResources);
    function GetDebugDirectory: PImageDebugDirectory;
    function GetLoadConfigDirectory: PImageLoadConfigDirectory;
    function GetEntryExceptionDirectory: PImageRuntimeFunctionEntry;
    function RecalcImageSize: DWORD;
    function GetHighestSectionSize: DWORD;
    function GetDataFromEOF(var lpData: Pointer; var dwLength: Cardinal): Boolean;
    function CalcCheckSum: DWORD;
    function RecalcCheckSum: DWORD;
    function ResizeSection(wSection: Word; Count: Cardinal): Boolean;


  published
    // Datei
    property FileSize: Cardinal read FFileSize;
    property Filename: string read FFilename;
    // NtHeaders
    property NumberOfSections: Word read FNumberOfSections;
    property AddressOfEntryPoint: Cardinal read FAddressOfEntryPoint write SetAddressOfEntryPoint;
    property ImageBase: Cardinal read FImageBase write SetImageBase;
    property SectionAlign: Cardinal read FSectionAlign;
    property FileAlign: Cardinal read FFileAlign;
    // Noch mehr braucht man eigentlich nicht, man kann ja alles über die
    // ImageNtHeaders erreichen.
  protected

  end;

const
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13;
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
  RT_HTML                              = PChar(23);
  RT_MANIFEST                          = PChar(24);

var
  // by Olli
  ResourceTypeDefaultNames: array[0..20] of record
    ResType: PChar;
    ResTypeName: string;
  end = (
    (ResType: RT_ACCELERATOR; ResTypeName: 'Accelerator'; ),
    (ResType: RT_ANICURSOR; ResTypeName: 'Animated Cursor'; ),
    (ResType: RT_ANIICON; ResTypeName: 'Animated Icon'; ),
    (ResType: RT_BITMAP; ResTypeName: 'Bitmap'; ),
    (ResType: RT_CURSOR; ResTypeName: 'Cursor'; ),
    (ResType: RT_DIALOG; ResTypeName: 'Dialog'; ),
    (ResType: RT_DLGINCLUDE; ResTypeName: 'Dialog Include'; ),
    (ResType: RT_FONT; ResTypeName: 'Font'; ),
    (ResType: RT_FONTDIR; ResTypeName: 'Font Directory'; ),
    (ResType: RT_GROUP_CURSOR; ResTypeName: 'Group Cursor'; ),
    (ResType: RT_GROUP_ICON; ResTypeName: 'Group Icon'; ),
    (ResType: RT_HTML; ResTypeName: 'Html'; ),
    (ResType: RT_ICON; ResTypeName: 'Icon'; ),
    (ResType: RT_MANIFEST; ResTypeName: 'Manifest'; ),
    (ResType: RT_MENU; ResTypeName: 'Menu'; ),
    (ResType: RT_MESSAGETABLE; ResTypeName: 'Messagetable'; ),
    (ResType: RT_PLUGPLAY; ResTypeName: 'Plugplay'; ),
    (ResType: RT_RCDATA; ResTypeName: 'RC Data'; ),
    (ResType: RT_STRING; ResTypeName: 'String'; ),
    (ResType: RT_VERSION; ResTypeName: 'Version'; ),
    (ResType: RT_VXD; ResTypeName: 'VXD'; )
    );

implementation

constructor TPeFile.Create;
begin
  inherited;
end;

destructor TPeFile.Destroy;
begin
  if (lpBuffer <> nil) then
    FreeMem(lpBuffer, FFileSize);
  inherited;
end;

function TPeFile.Align(Value, Align: Cardinal): Cardinal;
begin
  if ((Value mod Align) = 0) then
    Result := Value
  else
    Result := ((Value + Align - 1) div Align) * Align;
end;

function TPeFile.SectionToString(Section: TImageSectionHeader): string;
var
  x: Word;
begin
  Result := '';
  for x := 0 to IMAGE_SIZEOF_SHORT_NAME -1 do
    if (Section.Name[x] <> 0) then
      Result := Result + Chr(Section.Name[x]);
end;

procedure TPeFile.StringToSection(const sSectionName: string; var Section: TImageSectionHeader);
var
  x: Word;
begin
  FillChar(Section.Name, SizeOf(Section.Name), #0);
  if (Length(sSectionName) = 0) then Exit;
  for x := 0 to Length(sSectionName) -1 do
    if (x < IMAGE_SIZEOF_SHORT_NAME) then
      Section.Name[x] := Ord(sSectionName[x +1]);
end;

function TPeFile.ValidHeaders: Boolean;
begin
  Result := False;
  if (ImageDosHeader^.e_magic = IMAGE_DOS_SIGNATURE) then
    if (ImageNtHeaders^.Signature = IMAGE_NT_SIGNATURE) then
      Result := True;
end;

function TPeFile.ReadPeHeaders: Boolean;
var
  x: Word;
begin
  Result := False;
  ImageDosHeader := PImageDosHeader(Integer(lpBuffer));
  if (ImageDosHeader^.e_magic = IMAGE_DOS_SIGNATURE) then
  begin

    ImageNtHeaders := PImageNtHeaders(Integer(lpBuffer) + ImageDosHeader._lfanew);
    if (ImageNtHeaders^.Signature = IMAGE_NT_SIGNATURE) then
    begin
      FNumberOfSections := ImageNtHeaders^.FileHeader.NumberOfSections;
      FAddressOfEntryPoint := ImageNtHeaders^.OptionalHeader.AddressOfEntryPoint;
      FImageBase := ImageNtHeaders^.OptionalHeader.ImageBase;
      FFileAlign := ImageNtHeaders^.OptionalHeader.FileAlignment;
      FSectionAlign := ImageNtHeaders^.OptionalHeader.SectionAlignment;
      SetLength(ImageSections, NumberOfSections);
      for x := Low(ImageSections) to High(ImageSections) do
      begin
        CopyMemory(@ImageSections[x],
          Pointer(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + (x * SizeOf(TImageSectionHeader))),
          SizeOf(TImageSectionHeader));
      end;
      Result := True;
    end;

  end;
end;

procedure TPeFile.WriteImageSectionHeader;
var
  dwTemp: DWORD;
  x: Word;
  bZeroAll: Boolean;
begin
  bZeroAll := True;
  // zuerst prüfen wir mittels dieser kleinen funktion, ob wir irgendwelche
  // brauchbaren daten in den headern haben, falls ja werden diese nicht entfernt
  dwTemp := ImageDosHeader._lfanew + SizeOf(TImageNtHeaders) + (FNumberOfSections * SizeOf(TImageSectionHeader));
  for x := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1 do
  begin
    if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress <> 0) then
    begin
      if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress < ImageNtHeaders^.OptionalHeader.SizeOfHeaders) then
      begin
        bZeroAll := False;
        if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress > dwTemp) then
        begin
          dwTemp := ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress - dwTemp;
          ZeroMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders) + (FNumberOfSections * SizeOf(TImageSectionHeader))), dwTemp);
        end else
          bZeroAll := False;
      end;
    end;
  end;
  if (bZeroAll) then
  begin
    dwTemp := ImageDosHeader._lfanew + SizeOf(TImageNtHeaders);
    ZeroMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders)), ImageSections[Low(ImageSections)].PointerToRawData - dwTemp);
  end;
  ZeroMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders)), FNumberOfSections * SizeOf(TImageSectionHeader));
  CopyMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders)), ImageSections, FNumberOfSections * SizeOf(TImageSectionHeader));
end;

function TPeFile.LoadFromFile(const sFilename: string): Boolean;
var
  hFile: THandle;
  lpNumberOfBytesRead: DWORD;
begin
  Result := False;
  hFile := CreateFile(PChar(sFilename), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if (hFile <> INVALID_HANDLE_VALUE) then
  begin
    FFilename := sFilename;
    FFileSize := GetFileSize(hFile, nil);
    GetMem(lpBuffer, FileSize);
    ReadFile(hFile, lpBuffer^, FileSize, lpNumberOfBytesRead, nil);
    if (FileSize = lpNumberOfBytesRead) then
    begin
      Result := ReadPeHeaders;
    end;
    CloseHandle(hFile);
  end;
end;

function TPeFile.SaveToFile(const sFilename: string): Boolean;
var
  hFile: THandle;
  lpNumberOfBytesWritten: DWORD;
begin
  Result := False;
  hFile := CreateFile(PChar(sFilename), GENERIC_WRITE, FILE_SHARE_WRITE, nil, CREATE_ALWAYS, 0, 0);
  if (hFile <> INVALID_HANDLE_VALUE) then
  begin
    if ValidHeaders then
    begin
      CopyMemory(lpBuffer, ImageDosHeader, SizeOf(TImageDosHeader));
      CopyMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew), ImageNtHeaders, SizeOf(TImageNtHeaders));
      WriteImageSectionHeader;
      SetFilePointer(hFile, 0, nil, FILE_BEGIN);
      WriteFile(hFile, lpBuffer^, FileSize, lpNumberOfBytesWritten, nil);
      if (FileSize = lpNumberOfBytesWritten) then
      begin
        Result := True;
      end;
    end;
    CloseHandle(hFile);
  end;
end;

procedure TPeFile.SetAddressOfEntryPoint(AddressOfEntryPoint: Cardinal);
begin
  ImageNtHeaders^.OptionalHeader.AddressOfEntryPoint := AddressOfEntryPoint;
  FAddressOfEntryPoint := AddressOfEntryPoint;
end;

procedure TPeFile.SetImageBase(ImageBase: Cardinal);
begin
  ImageNtHeaders^.OptionalHeader.ImageBase := ImageBase;
  FImageBase := ImageBase;
end;

function TPeFile.RvaToFileOffset(dwRVA: Cardinal): Cardinal;
var
  x: Word;
begin
  Result := 0;
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    if ((dwRVA >= ImageSections[x].VirtualAddress) and (dwRVA < ImageSections[x].VirtualAddress + ImageSections[x].SizeOfRawData)) then
    begin
      Result := dwRVA - ImageSections[x].VirtualAddress + ImageSections[x].PointerToRawData;
      Break;
    end;
  end;
end;

function TPeFile.FileOffsetToRva(dwFileOffset: Cardinal): Cardinal;
var
  x: Word;
begin
  Result := 0;
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    if ((dwFileOffset >= ImageSections[x].PointerToRawData) and (dwFileOffset < ImageSections[x].PointerToRawData + ImageSections[x].SizeOfRawData)) then
    begin
      Result := dwFileOffset - ImageSections[x].PointerToRawData + ImageSections[x].VirtualAddress;
      Break;
    end;
  end;
end;

function TPeFile.VaToFileOffset(dwVA: Cardinal): Cardinal;
begin
  if (dwVA > Cardinal(lpBuffer)) then
    Result := RvaToFileOffset(dwVA - Cardinal(lpBuffer))
  else
    Result := 0;
end;

function TPeFile.FileOffsetToVa(dwFileOffset: Cardinal): Cardinal;
begin
  Result := FileOffsetToRva(dwFileOffset) + Cardinal(lpBuffer);
end;

function TPeFile.VaToRva(dwVA: Cardinal): Cardinal;
begin
  Result := dwVA - Cardinal(lpBuffer);
end;

function TPeFile.RvaToVa(dwRVA: Cardinal): Cardinal;
begin
  Result := RvaToFileOffset(dwRVA) + Cardinal(lpBuffer);
end;

function TPeFile.RvaToSection(dwRVA: Cardinal): Word;
var
  x: Word;
begin
  Result := High(Word);
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    if ((dwRVA >= ImageSections[x].VirtualAddress) and (dwRVA < ImageSections[x].VirtualAddress + ImageSections[x].SizeOfRawData)) then
    begin
      Result := x;
      Break;
    end;
  end;
end;

function TPeFile.FileOffsetToSection(dwFileOffset: Cardinal): Word;
var
  x: Word;
begin
  Result := High(Word);
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    if ((dwFileOffset >= ImageSections[x].PointerToRawData) and (dwFileOffset < ImageSections[x].PointerToRawData + ImageSections[x].SizeOfRawData)) then
    begin
      Result := x;
      Break;
    end;
  end;
end;

{
  Achtung: Rückgabewert ist 0 falls man die Headers verändert, bzw. diese
  ungültig gemacht werden!
}
function TPeFile.InsertBytes(FromOffset, Count: Cardinal): Cardinal;
var
  dwCopyFrom, dwCopyLength: Cardinal;
  lpTemp: Pointer;
begin
  Result := 0;
  if (FromOffset > FFileSize) then
    dwCopyFrom := FFileSize
  else
    dwCopyFrom := FromOffset;
  dwCopyLength := FFileSize - dwCopyFrom;
  ReallocMem(lpBuffer, FFileSize + Count);
  if (dwCopyLength > 0) then
  begin
    GetMem(lpTemp, dwCopyLength);
    CopyMemory(lpTemp, Pointer(Cardinal(lpBuffer) + dwCopyFrom), dwCopyLength);
    CopyMemory(Pointer(Cardinal(lpBuffer) + dwCopyFrom + Count), lpTemp, dwCopyLength);
    FreeMem(lpTemp);
  end;
  ZeroMemory(Pointer(Cardinal(lpBuffer) + dwCopyFrom), Count);
  if ReadPeHeaders then
  begin
    FFileSize := FFileSize + Count;
    Result := FFileSize;
  end;
end;

{
  Achtung: Rückgabewert ist 0 falls man die Headers verändert, bzw. diese
  ungültig gemacht werden!
}
function TPeFile.DeleteBytes(FromOffset, Count: Cardinal): Cardinal;
var
  dwCopyFrom, dwCopyLength: DWORD;
  lpTemp: Pointer;
begin
  Result := 0;
  if (FFileSize >= (FromOffset + Count)) then
  begin
    dwCopyFrom := FromOffset + Count;
    dwCopyLength := FFileSize - dwCopyFrom;
    if (dwCopyLength > 0) then
    begin
      GetMem(lpTemp, dwCopyLength);
      CopyMemory(lpTemp, Pointer(Cardinal(lpBuffer) + dwCopyFrom), dwCopyLength);
      CopyMemory(Pointer(Cardinal(lpBuffer) + FromOffset), lpTemp, dwCopyLength);
      FreeMem(lpTemp);
    end;
    ReallocMem(lpBuffer, FFileSize - Count);
    if ReadPeHeaders then
    begin
      FFileSize := FFileSize - Count;
      Result := FFileSize;
    end;
  end;
end;

{
  Sucht nach 0 Bytes ab einem bestimmten Offset. Dabei werden 4 bytes
  ignoriert weil diese z.B. zum Code gehören können.
}
function TPeFile.FindCodeCaves(FromOffset, Count: Cardinal): TCodeCave;
var
  x, TempCave: Cardinal;
const
  IGNORE_BYTES = 4;
begin
  ZeroMemory(@Result, SizeOf(TCodeCave));
  if (Count > 0) then
  begin
    TempCave := 0;
    for x := 0 to Count do
    begin
      if (PByte(Cardinal(lpBuffer) + FromOffset + x)^ = 0) then
        Inc(TempCave)
      else
        TempCave := 0;
      if ((TempCave > Result.CaveSize) and (TempCave > IGNORE_BYTES)) then
      begin
        with Result do
        begin
          StartFileOffset := FromOffset + (x - TempCave) + IGNORE_BYTES;
          StartRVA := FileOffsetToRva(StartFileOffset);
          CaveSize := TempCave - IGNORE_BYTES;
        end;
      end;
    end;
  end;
end;

{
  Dieser Code war ursprünglich um die 200 Zeilen. Warum? Ich habe alles
  'per Hand' berechnet, war jedoch nicht nötig. :(

  lpData = Neue Sektion Daten
  dwDataLength = Länge der Daten der neuen Sektion Daten

}
function TPeFile.AddSection(const sSectionName: string; RawSize: Cardinal;
                            lpData: Pointer; dwDataLength: Cardinal;
                            dwCharacteristics: Cardinal = IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE): Boolean;
var
  Section, LastSection: TImageSectionHeader;
  CodeCave: TCodeCave;
  dwTemp, FileAlign, dwEOFDataLength, dwHighestSectionSize: Cardinal;
  x: Word;
  lpDataDir, lpEOFData: Pointer;
begin
  Result := False;
  lpEOFData := nil;
  dwEOFDataLength := 0;
  GetDataFromEOF(lpEOFData, dwEOFDataLength);
  FileAlign := ImageNtHeaders^.OptionalHeader.FileAlignment;
  if (lpData = nil) then
    dwDataLength := 0;
  if ((RawSize = DWORD(-1)) or (RawSize = 0)) then
    Exit;
  if (dwDataLength > RawSize) then
  begin
    repeat
      RawSize := Align(RawSize +1, FileAlign);
    until (Align(RawSize, FileAlign) >= dwDataLength);
  end;
  dwTemp := ImageDosHeader._lfanew + SizeOf(TImageNtHeaders) + (FNumberOfSections * SizeOf(TImageSectionHeader));
  for x := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1 do
  begin
    if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress <> 0) then
    begin
      if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress < ImageNtHeaders^.OptionalHeader.SizeOfHeaders) then
      begin
        if (ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress = dwTemp) then
        begin
          // wir verschieben die daten die unter den sektionen(!) sind, einfach in einer neuen sektion!!!
          GetMem(lpDataDir, ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size);
          CopyMemory(lpDataDir, Pointer(Cardinal(lpBuffer) + dwTemp), ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size);
          ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress := 0;
          AddSection('.bdata', ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size, lpDataDir, ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size);
          ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress := ImageSections[High(ImageSections)].VirtualAddress;
          FreeMem(lpDataDir);
        end;
      end;
    end;
  end;
  if (ImageNtHeaders^.OptionalHeader.SizeOfHeaders > dwTemp) then
    CodeCave := FindCodeCaves(dwTemp, ImageNtHeaders^.OptionalHeader.SizeOfHeaders - dwTemp)
  else
    CodeCave := FindCodeCaves(dwTemp, dwTemp - ImageNtHeaders^.OptionalHeader.SizeOfHeaders);
  if (CodeCave.CaveSize < SizeOf(TImageSectionHeader)) then
  begin
    dwTemp := ImageDosHeader._lfanew + SizeOf(TImageNtHeaders) + (FNumberOfSections * SizeOf(TImageSectionHeader));
    // wir fügen einmal FileAlign-bytes ein dann ist mal ruhe für die nächsten 13 sektionen ..
    if (FileAlign <= SizeOf(TImageSectionHeader)) then
      FileAlign := Align(SizeOf(TImageSectionHeader), FileAlign);
    if (InsertBytes(dwTemp, FileAlign) <> 0) then
    begin
      ImageNtHeaders^.OptionalHeader.SizeOfHeaders := ImageNtHeaders^.OptionalHeader.SizeOfHeaders + FileAlign;
      for x := Low(ImageSections) to High(ImageSections) do
        ImageSections[x].PointerToRawData := ImageSections[x].PointerToRawData + FileAlign;
      CopyMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders)),
        ImageSections, FNumberOfSections * SizeOf(TImageSectionHeader));
    end;
    FileAlign := ImageNtHeaders^.OptionalHeader.FileAlignment;
  end;
  LastSection := ImageSections[High(ImageSections)];
  StringToSection(sSectionName, Section);
  with Section do
  begin
    VirtualAddress := ImageNtHeaders^.OptionalHeader.SizeOfImage;
    SizeOfRawData := Align(RawSize, FileAlign);
    PointerToRawData := LastSection.PointerToRawData + LastSection.SizeOfRawData;
    Characteristics := dwCharacteristics;
  end;
  // ok struktur wurde eingelesen
  Inc(ImageNtHeaders^.FileHeader.NumberOfSections);
  // die größte/letzte sektion herausfinden
  dwHighestSectionSize := GetHighestSectionSize;
  // neue dateigröße
  FFileSize := FFileSize + Section.SizeOfRawData;
  //ImageNtHeaders^.OptionalHeader.SizeOfImage := Align(ImageNtHeaders^.OptionalHeader.SizeOfImage + Section.Misc.VirtualSize, SectionAlign);
  CopyMemory(Pointer(Integer(lpBuffer) + ImageDosHeader._lfanew + SizeOf(TImageNtHeaders) +
    (FNumberOfSections * SizeOf(TImageSectionHeader))), @Section, SizeOf(TImageSectionHeader));
  ReallocMem(lpBuffer, FFileSize);
  Result := ReadPeHeaders;
  // mit 0 bytes füllen
  ZeroMemory(Pointer(Cardinal(lpBuffer) + dwHighestSectionSize), FFileSize - dwHighestSectionSize);
  if ((lpData <> nil) and (dwDataLength > 0)) then
    CopyMemory(Pointer(Cardinal(lpBuffer) + dwHighestSectionSize), lpData, dwDataLength);
  // neue SizeOfImage berechnen und die größen der VirtualSize anpassen
  RecalcImageSize;
  // noch am ende die EOF Daten kopieren
  if ((lpEOFData <> nil) and (dwEOFDataLength <> 0)) then
  begin
    // die größte/letzte sektion herausfinden
    dwHighestSectionSize := GetHighestSectionSize;
    CopyMemory(Pointer(Cardinal(lpBuffer) + dwHighestSectionSize), lpEOFData, dwEOFDataLength);
    FreeMem(lpEOFData, dwEOFDataLength);
  end;
  RecalcCheckSum;
end;

{
function TPeFile.DeleteSection(wSection: Word): Boolean;
var
  dwTempFileSize, dwTemp,
  SectionOffset, SectionSize: Cardinal;
  x: Word;
begin
  Result := False;
  if ((wSection < FNumberOfSections) and (wSection <> High(Word))) then
  begin
    SectionOffset := ImageSections[wSection].PointerToRawData;
    SectionSize := ImageSections[wSection].SizeOfRawData;
    dwTempFileSize := FFileSize;
    DeleteBytes(SectionOffset, SectionSize);
    if (FFileSize = dwTempFileSize - SectionSize) then
    begin
      if (wSection > 0) then
      begin
        for x := Low(ImageSections) to wSection -1 do
        begin
          CopyMemory(
            Pointer(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + (x * SizeOf(TImageSectionHeader))),
            @ImageSections[x],
            SizeOf(TImageSectionHeader));
        end;
      end;
      for x := wSection +1 to FNumberOfSections -1 do
      begin
        CopyMemory(
          Pointer(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + ((x -1) * SizeOf(TImageSectionHeader))),
           @ImageSections[x],
           SizeOf(TImageSectionHeader));
      end;
      for x := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1 do
      begin
        if ((ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress <> 0) and (ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size <> 0)) then
        begin
          dwTemp := RvaToFileOffset(ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress);
          if (dwTemp = 0) then
            dwTemp := ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress;
          if (dwTemp = SectionOffset) then
          begin
            ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress := 0;
            ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size := 0;
          end;
        end;
      end;
      Dec(ImageNtHeaders^.FileHeader.NumberOfSections);
      Dec(FNumberOfSections);
      Result := ReadPeHeaders;
      // SizeOfImage of berechnen
      RecalcImageSize;
      RecalcCheckSum;
    end;
  end;
end;
}

function TPeFile.DeleteSection(wSection: Word; RecalculateImageSize : boolean = TRUE; RecalculateChecksum : boolean = TRUE): Boolean;
var
  dwTempFileSize, dwTemp,
  SectionOffset, SectionSize: Cardinal;
  x: Word;
begin
  Result := False;
  if ((wSection < FNumberOfSections) and (wSection <> High(Word))) then
  begin
    SectionOffset := ImageSections[wSection].PointerToRawData;
    SectionSize := ImageSections[wSection].SizeOfRawData;
    dwTempFileSize := FFileSize;
    DeleteBytes(SectionOffset, SectionSize);
    if (FFileSize = dwTempFileSize - SectionSize) then
    begin
      if (wSection > 0) then
      begin
        for x := Low(ImageSections) to wSection -1 do
        begin
          CopyMemory(
            Pointer(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + (x * SizeOf(TImageSectionHeader))),
            @ImageSections[x],
            SizeOf(TImageSectionHeader));
        end;
      end;
      for x := wSection +1 to FNumberOfSections -1 do
      begin
        CopyMemory(
          Pointer(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + ((x -1) * SizeOf(TImageSectionHeader))),
           @ImageSections[x],
           SizeOf(TImageSectionHeader));
      end;
      for x := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1 do
      begin
        if ((ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress <> 0) and (ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size <> 0)) then
        begin
          dwTemp := RvaToFileOffset(ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress);
          if (dwTemp = 0) then
            dwTemp := ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress;
          if (dwTemp = SectionOffset) then
          begin
            ImageNtHeaders^.OptionalHeader.DataDirectory[x].VirtualAddress := 0;
            ImageNtHeaders^.OptionalHeader.DataDirectory[x].Size := 0;
          end;
        end;
      end;
      Dec(ImageNtHeaders^.FileHeader.NumberOfSections);
      Dec(FNumberOfSections);
      Result := ReadPeHeaders;
      // SizeOfImage of berechnen
      if RecalculateImageSize then RecalcImageSize;
      if RecalculateChecksum then RecalcCheckSum;
    end;
  end;
end;


function TPeFile.GetCharacteristics(dwCharacteristics: DWORD): string;
type
  TCharacteristics = packed record
    Mask: DWORD;
    InfoChar: Char;
  end;
const
  Info: array[0..8] of TCharacteristics = (
    (Mask: IMAGE_SCN_CNT_CODE; InfoChar: 'C'),
    (Mask: IMAGE_SCN_MEM_EXECUTE; InfoChar: 'E'),
    (Mask: IMAGE_SCN_MEM_READ; InfoChar: 'R'),
    (Mask: IMAGE_SCN_MEM_WRITE; InfoChar: 'W'),
    (Mask: IMAGE_SCN_MEM_NOT_PAGED; InfoChar: 'P'),
    (Mask: IMAGE_SCN_CNT_INITIALIZED_DATA; InfoChar: 'I'),
    (Mask: IMAGE_SCN_CNT_UNINITIALIZED_DATA; InfoChar: 'U'),
    (Mask: IMAGE_SCN_MEM_SHARED; InfoChar: 'S'),
    (Mask: IMAGE_SCN_MEM_DISCARDABLE; InfoChar: 'D'));
var
  x: Word;
begin
  for x := Low(Info) to High(Info) do
  begin
    if ((dwCharacteristics and Info[x].Mask) = Info[x].Mask) then
      Result := Result + Info[x].InfoChar;
  end;
end;

function TPeFile.GetCodeSection: Word;
begin
  Result := RvaToSection(ImageNtHeaders^.OptionalHeader.BaseOfCode);
end;

function TPeFile.GetDataSection: Word;
begin
  Result := RvaToSection(ImageNtHeaders^.OptionalHeader.BaseOfData);
end;

function TPeFile.GetResourceSection: Word;
var
  dwTemp: Cardinal;
begin
  Result := High(Word);
  dwTemp := ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
  if (dwTemp <> 0) then
    Result := RvaToSection(dwTemp);
end;

procedure TPeFile.GetImportAddressTable(var Imports: TImportsArray);
var
  x, y: Cardinal;
  ImportDescriptor: PImageImportDescriptor;
  DelayDescriptor: PImgDelayDescr;
  BoundImportDescriptor: PImageBoundImportDescriptor;
  lpszLibraryName: PChar;
  ImageThunk: PImageThunkData;
  lpszAPIName: PChar;
  { Is Import By Ordinal? }
  function IsImportByOrdinal(ImportDescriptor: DWORD): Boolean;
  begin
    Result := (ImportDescriptor and $80000000) <> 0;
  end;
begin
  x := 0;
  SetLength(Imports, 1);
  ZeroMemory(Imports, SizeOf(Imports) * High(Imports));
  // NORMALE IAT
  if ((ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress <> 0) and
      (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size <> 0)) then
  begin
    ImportDescriptor := PImageImportDescriptor(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
    while (ImportDescriptor^.Name <> 0) do
    begin
      SetLength(Imports, x +1);
      lpszLibraryName := PChar(RvaToVa(ImportDescriptor^.Name));
      Imports[x].LibraryName := lpszLibraryName;
      Imports[x].ImportType := itNormal;
      Imports[x].OriginalFirstThunk := ImportDescriptor^.OriginalFirstThunk;
      Imports[x].TimeDateStamp := ImportDescriptor^.TimeDateStamp;
      Imports[x].ForwarderChain := ImportDescriptor^.ForwarderChain;
      Imports[x].Name := ImportDescriptor^.Name;
      Imports[x].FirstThunk := ImportDescriptor^.FirstThunk;
      if (ImportDescriptor^.OriginalFirstThunk <> 0) then
        ImageThunk := PImageThunkData(RvaToVa(ImportDescriptor^.OriginalFirstThunk))
      else
        ImageThunk := PImageThunkData(RvaToVa(ImportDescriptor^.FirstThunk));
      y := 0;
      while (ImageThunk^.Name <> 0) do
      begin
        SetLength(Imports[x].IatFunctions, y +1);
        if IsImportByOrdinal(ImageThunk^.Name) then
        begin
          lpszAPIName := '(by ordinal)';
          Imports[x].IatFunctions[y].Hint := ImageThunk^.Name and $ffff;
        end else
        begin
          lpszAPIName := PChar(RvaToVa(ImageThunk^.Name + SizeOf(Word)));
          Imports[x].IatFunctions[y].Hint := 0;
        end;
        Imports[x].IatFunctions[y].ThunkOffset := Cardinal(ImageThunk) - Cardinal(lpBuffer);
        if (ImportDescriptor^.OriginalFirstThunk <> 0) then
          Imports[x].IatFunctions[y].ThunkRVA := ImportDescriptor^.OriginalFirstThunk + DWORD(y * SizeOf(DWORD))
        else
          Imports[x].IatFunctions[y].ThunkRVA := ImportDescriptor^.FirstThunk + DWORD(y * SizeOf(DWORD));
        Imports[x].IatFunctions[y].ThunkValue := ImageThunk^.Name;
        Imports[x].IatFunctions[y].ApiName := lpszAPIName;
        Inc(y);
        Inc(ImageThunk);
      end;
      Inc(x);
      Inc(ImportDescriptor);
    end;
  end;
  // DELAYED IAT
  if ((ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress <> 0) and
      (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size <> 0)) then
  begin
    DelayDescriptor := PImgDelayDescr(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));
    while (DelayDescriptor^.szName <> 0) do
    begin
      SetLength(Imports, x +1);
      lpszLibraryName := PChar(RvaToVa(DelayDescriptor^.szName));
      Imports[x].LibraryName := lpszLibraryName;
      Imports[x].OriginalFirstThunk := DelayDescriptor^.pINT.Name;
      Imports[x].ImportType := itDelay;
      Imports[x].TimeDateStamp := DelayDescriptor^.dwTimeStamp;
      Imports[x].FirstThunk := PImageImportDescriptor(DelayDescriptor)^.FirstThunk;
      ImageThunk := PImageThunkData(RvaToVa(DelayDescriptor^.pINT.Name));
      y := 0;
      while (ImageThunk^.Name <> 0) do
      begin
        SetLength(Imports[x].IatFunctions, y +1);
        if IsImportByOrdinal(ImageThunk^.Name) then
        begin
          lpszAPIName := '(by ordinal)';
          Imports[x].IatFunctions[y].Hint := ImageThunk^.Name and $ffff;
        end else
        begin
          lpszAPIName := PChar(RvaToVa(ImageThunk^.Name + SizeOf(Word)));
          Imports[x].IatFunctions[y].Hint := 0;
        end;
        Imports[x].IatFunctions[y].ThunkOffset := Cardinal(ImageThunk) - Cardinal(lpBuffer);
        Imports[x].IatFunctions[y].ThunkRVA := DelayDescriptor^.pINT.Name + DWORD(y * SizeOf(DWORD));
        Imports[x].IatFunctions[y].ThunkValue := ImageThunk^.Name;
        Imports[x].IatFunctions[y].ApiName := lpszAPIName;
        Inc(y);
        Inc(ImageThunk);
      end;
      Inc(x);
      Inc(DelayDescriptor);
    end;
  end;
  // BOUND IAT
  if ((ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress <> 0) and
      (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size <> 0)) then
  begin
    BoundImportDescriptor := PImageBoundImportDescriptor(Cardinal(lpBuffer) + ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
    while (BoundImportDescriptor^.OffsetModuleName <> 0) do
    begin
      SetLength(Imports, x +1);
      lpszLibraryName := PChar(Integer(lpBuffer) + ImageDosHeader^._lfanew + SizeOf(TImageNtHeaders) + (FNumberOfSections * SizeOf(TImageSectionHeader)) + BoundImportDescriptor^.OffsetModuleName);
      Imports[x].TimeDateStamp := BoundImportDescriptor.TimeDateStamp;
      Imports[x].LibraryName := lpszLibraryName;
      Imports[x].ImportType := itBound;
      Imports[x].Name := BoundImportDescriptor^.OffsetModuleName;
      if (BoundImportDescriptor^.NumberOfModuleForwarderRefs > 0) then
      begin
        for y := 0 to BoundImportDescriptor^.NumberOfModuleForwarderRefs -1 do
        begin
          Inc(PImageBoundForwarderRef(BoundImportDescriptor));
        end;
      end;
      Inc(x);
      Inc(BoundImportDescriptor);
    end;
  end;
  // ToDo: COM IAT
end;

procedure TPeFile.GetExportsAddressTable(var ExportData: TExports);
type
  PDWORDArray = ^TDWORDArray;
  TDWORDArray = array[Word] of DWORD;
  PWordArray = ^TWordArray;
  TWordArray = array[Word] of Word;
var
  ExportDirectory: PImageExportDirectory;
  Functions: PDWORDArray;
  Ordinals: PWordArray;
  Names: PDWORDArray;
  CounterFunctions, CounterOrdinals: DWORD;
  VA: DWORD;
  sName: string;
  x: Integer;
begin
  SetLength(ExportData.ExportFunctions, 1);
  if ((ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress <> 0) and
      (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <> 0)) then
  begin
    ExportDirectory := PImageExportDirectory(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    Functions := Pointer(RvaToVa(Cardinal(ExportDirectory^.AddressOfFunctions)));
    Ordinals := Pointer(RvaToVa(Cardinal(ExportDirectory^.AddressOfNameOrdinals)));
    Names := Pointer(RvaToVa(Cardinal(ExportDirectory^.AddressOfNames)));
    with ExportData do
    begin
      LibraryName := PChar(RvaToVa(ExportDirectory^.Name));
      Base := ExportDirectory^.Base;
      Characteristics := ExportDirectory^.Characteristics;
      TimeDateStamp := ExportDirectory^.TimeDateStamp;
      MajorVersion := ExportDirectory^.MajorVersion;
      MinorVersion := ExportDirectory^.MinorVersion;
      NumberOfFunctions := ExportDirectory^.NumberOfFunctions;
      NumberOfNames := ExportDirectory^.NumberOfNames;
      AddressOfFunctions := DWORD(ExportDirectory^.AddressOfFunctions);
      AddressOfNames := DWORD(ExportDirectory^.AddressOfNames);
      AddressOfNameOrdinals := Word(ExportDirectory^.AddressOfNameOrdinals);
    end;
    if (Functions <> nil) then
    begin
      x := 0;
      for CounterFunctions := 0 to ExportDirectory^.NumberOfFunctions -1 do
      begin
        sName := '';
        if (Functions[CounterFunctions] = 0) then
          continue;
        SetLength(ExportData.ExportFunctions, x +1);
        ExportData.ExportFunctions[x].Ordinal := CounterFunctions + ExportDirectory^.Base;
        if (Ordinals <> nil) and (Names <> nil) then
        begin
          for CounterOrdinals := 0 to ExportDirectory^.NumberOfNames -1 do
          begin
            if (Ordinals[CounterOrdinals] = CounterFunctions) then
            begin
              sName := PChar(RvaToVa(Names[CounterOrdinals]));
              Break;
            end;
          end;
        end;
        VA := Functions[CounterFunctions];
        if DWORD(VA - ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) <
                  ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size then
        begin
          sName := PChar(RvaToVa(Va));
          VA := 0;
        end;
        ExportData.ExportFunctions[x].Rva := VA;
        ExportData.ExportFunctions[x].FileOffset := RvaToFileOffset(VA);
        ExportData.ExportFunctions[x].ApiName := sName;
        Inc(x);
      end;
    end;
  end;
end;

function TPeFile.GetThreadLocalStorage: PImageTLSDirectory;
begin
  Result := nil;
  if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress <> 0) then
  begin
    Result := PImageTLSDirectory(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
  end;
end;

procedure TPeFile.GetResources(var Resources: TResources);
var
  Table: PImageResourceDirectory;
  VA: DWORD;
  TypCount, NameCountPublic: Integer;

  function WideCharToMultiByteEx(var lp: PWideChar): string;
  var
    len: Word;
  begin
    len := Word(lp^);
    SetLength(Result, len);
    Inc(lp);
    WideCharToMultiByte(CP_ACP, 0, lp, Len, PChar(Result), Len +1, nil, nil);
    Inc(lp, len);
    Result := PChar(Result);
  end;

  function GetResourceStr(IsResID: Boolean; IsType: Boolean; Addr: DWORD): string;
  var
    lpTmp: PWideChar;
    x: Word;
  begin
    if IsResID then
    begin
      if IsType then
      begin
        for x := 0 to Length(ResourceTypeDefaultNames) -1 do
        begin
          if (MAKEINTRESOURCE(Addr) = MAKEINTRESOURCE(ResourceTypeDefaultNames[x].ResType)) then
          begin
            Result := ResourceTypeDefaultNames[x].ResTypeName;
            Exit;
          end;
        end;
      end;
      Str(Addr, Result);
    end else
    begin
      lpTmp := PWideChar(RvaToVa(VA + (Addr and $7fffffff)));
      Result := WideCharToMultiByteEx(lpTmp);
    end;
  end;

  procedure ParseResources(Offset: DWORD; Level: Byte);
  var
    Table: PImageResourceDirectory;
    Entry: PImageResourceDirectoryEntry;
    EntryData: PImageResourceDataEntry;
    i, Count: Integer;
    IsResID: Boolean;
    NameCount, LangsCount: Integer;
  begin
    NameCount := 0;
    LangsCount := 0;
    Table := Pointer(RvaToVa(VA + Offset));
    Count := Table^.NumberOfNamedEntries + Table^.NumberOfIdEntries;
    Entry := Pointer(RvaToVa(VA + Offset + SizeOf(TImageResourceDirectory)));
    for i := 0 to Count -1 do
    begin
      IsResID := i >= Table^.NumberOfNamedEntries;
      case Level of
        0:
          begin
            // Typen
            NameCountPublic := 0;
            SetLength(Resources.Entries, TypCount +1);
            Resources.Entries[TypCount].sTyp := GetResourceStr(IsResId, True, Entry^.Name);
            Inc(TypCount);
          end;
        1:
          begin
            // Namen
            SetLength(Resources.Entries[TypCount -1].NameEntries, NameCount +1);
            Resources.Entries[TypCount -1].NameEntries[NameCount].sName := GetResourceStr(IsResId, False, Entry^.Name);
            Inc(NameCount);
            Inc(NameCountPublic);
          end;
        2:
          begin
            // Langs
            EntryData := PImageResourceDataEntry(RvaToVa(VA + Entry^.OffsetToData));
            Resources.Entries[TypCount -1].NameEntries[(NameCountPublic-1) + LangsCount].sLang := GetResourceStr(IsResId, False, Entry^.Name);
            Resources.Entries[TypCount -1].NameEntries[(NameCountPublic-1) + LangsCount].lpData := Pointer(RvaToVa(EntryData^.OffsetToData));
            Resources.Entries[TypCount -1].NameEntries[(NameCountPublic-1) + LangsCount].dwDataRVA := EntryData^.OffsetToData;
            Resources.Entries[TypCount -1].NameEntries[(NameCountPublic-1) + LangsCount].dwSize := EntryData^.Size;
            Inc(LangsCount);
          end;
      end;
      if (Entry^.OffsetToData and $80000000) > 0 then
        ParseResources(Entry^.OffsetToData and $7fffffff, Level +1);
      Inc(Entry);
    end;
  end;
begin
  if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress <> 0) then
  begin
    TypCount := 0;
    VA := ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    FillChar(Resources, SizeOf(TResources), #0);
    Table := Pointer(RvaToVa(VA));
    with Resources.Dir do
    begin
      Characteristics := Table^.Characteristics;
      TimeDateStamp := Table^.TimeDateStamp;
      MajorVersion := Table^.MajorVersion;
      MinorVersion := Table^.MinorVersion;
      NumberOfNamedEntries := Table^.NumberOfNamedEntries;
      NumberOfIdEntries := Table^.NumberOfIdEntries;
    end;
    ParseResources(0, 0);
  end;
end;

function TPeFile.GetDebugDirectory: PImageDebugDirectory;
begin
  Result := nil;
  if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress <> 0) then
  begin
    Result := PImageDebugDirectory(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
  end;
end;

function TPeFile.GetLoadConfigDirectory: PImageLoadConfigDirectory;
begin
  Result := nil;
  if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress <> 0) then
  begin
    Result := PImageLoadConfigDirectory(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress));
  end;
end;

function TPeFile.GetEntryExceptionDirectory: PImageRuntimeFunctionEntry;
begin
  Result := nil;
  if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress <> 0) then
  begin
    Result := PImageRuntimeFunctionEntry(RvaToVa(ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
  end;
end;

procedure TPeFile.CopyMemoryToBuffer(CopyToOffset: DWORD; Source: Pointer; Length: DWORD);
begin
  CopyMemory(Pointer(Cardinal(lpBuffer) + CopyToOffset), Source, Length);
end;

procedure TPeFile.CopyMemoryFromBuffer(CopyFromOffset: DWORD; Destination: Pointer; Length: DWORD);
begin
  CopyMemory(Destination, Pointer(Cardinal(lpBuffer) + CopyFromOffset), Length);
end;

function TPeFile.DumpSection(wSection: Word; sFilename: string): Boolean;
var
  hFile: THandle;
  lpNumberOfBytesWritten: DWORD;
  lpBuff: Pointer;
begin
  Result := False;
  if (wSection <> High(Word)) then
  begin
    hFile := CreateFile(PChar(sFilename), GENERIC_WRITE, FILE_SHARE_WRITE, nil, CREATE_ALWAYS, 0, 0);
    if (hFile <> INVALID_HANDLE_VALUE) then
    begin
      lpBuff := Pointer(Cardinal(lpBuffer) + ImageSections[wSection].PointerToRawData);
      WriteFile(hFile, lpBuff^, ImageSections[wSection].SizeOfRawData, lpNumberOfBytesWritten, nil);
      Result := lpNumberOfBytesWritten = ImageSections[wSection].SizeOfRawData;
      CloseHandle(hFile);
    end;
  end;
end;

function TPeFile.RecalcImageSize: DWORD;
var
  x: Word;
  ImageSize: DWORD;
begin
  // prüfen obs mit der niedrigsten sektion übereinstimmt..
  if (ImageSections[Low(ImageSections)].PointerToRawData <> ImageNtHeaders^.OptionalHeader.SizeOfHeaders) then
    ImageNtHeaders^.OptionalHeader.SizeOfHeaders := ImageSections[Low(ImageSections)].PointerToRawData;
  if (ImageNtHeaders^.OptionalHeader.SizeOfHeaders mod SectionAlign = 0) then
    ImageSize := ImageNtHeaders^.OptionalHeader.SizeOfHeaders
  else
    ImageSize := Align(ImageNtHeaders^.OptionalHeader.SizeOfHeaders, SectionAlign);
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    // die größen fixen
    if (x < NumberOfSections -1) then
      ImageSections[x].Misc.VirtualSize := ImageSections[x +1].VirtualAddress - ImageSections[x].VirtualAddress
    else
      ImageSections[x].Misc.VirtualSize := ImageSections[x].SizeOfRawData;
    if (ImageSections[x].Misc.VirtualSize mod SectionAlign = 0) then
      ImageSize := ImageSize + ImageSections[x].Misc.VirtualSize
    else
      ImageSize := ImageSize + Align(ImageSections[x].Misc.VirtualSize, SectionAlign);
  end;
  ImageNtHeaders^.OptionalHeader.SizeOfImage := ImageSize;
  WriteImageSectionHeader;
  Result := ImageSize;
end;

function TPeFile.GetHighestSectionSize: DWORD;
var
  x: Word;
begin
  Result := 0;
  for x := Low(ImageSections) to High(ImageSections) do
  begin
    if (ImageSections[x].PointerToRawData + ImageSections[x].SizeOfRawData > Result) then
      Result := ImageSections[x].PointerToRawData + ImageSections[x].SizeOfRawData;
  end;
end;

function TPeFile.GetDataFromEOF(var lpData: Pointer; var dwLength: Cardinal): Boolean;
var
  dwHighestSize: DWORD;
begin
  Result := False;
  dwHighestSize := GetHighestSectionSize;
  if (dwHighestSize <> 0) then
  begin
    dwLength := FFileSize - dwHighestSize;
    Result := (dwLength <> 0);
    if Result then
    begin
      GetMem(lpData, dwLength);
      CopyMemory(lpData, Pointer(Cardinal(lpBuffer) + dwHighestSize), dwLength);
      // nicht vergessen später muss er freigegeben werden
    end;
  end;
end;

function TPeFile.CalcCheckSum: DWORD;
  function CalcCheckSumWord: Word;
  var
    WordCount, Sum, x: DWORD;
    Ptr: PWord;
  begin
    Sum := 0;
    Ptr := PWord(Cardinal(lpBuffer));
    WordCount := (FFileSize + 1) div SizeOf(Word);
    for x := 0 to WordCount -1 do
    begin
      Sum := Sum + Word(Ptr^);
      if (HiWord(Sum) <> 0) then
        Sum := LoWord(Sum) + HiWord(Sum);
      Inc(Ptr);
    end;
    Result := Word(LoWord(Sum) + HiWord(Sum));
  end;
var
  CalcSum, HeaderSum: DWORD;
begin
  CalcSum := CalcCheckSumWord;
  HeaderSum := ImageNtHeaders^.OptionalHeader.CheckSum;
  // fixe den low-wert der checksum
  if (LoWord(CalcSum) >= LoWord(HeaderSum)) then
    CalcSum := CalcSum - LoWord(HeaderSum)
  else
    CalcSum := ((LoWord(CalcSum) - LoWord(HeaderSum)) and $ffff) -1;
  // fixe den highwert der checksum
  if (LoWord(CalcSum) >= HiWord(HeaderSum)) then
    CalcSum := CalcSum - HiWord(HeaderSum)
  else
    CalcSum := ((LoWord(CalcSum) - HiWord(HeaderSum)) and $ffff) -1;
  CalcSum := CalcSum + FFileSize;
  Result := CalcSum;
end;

function TPeFile.RecalcCheckSum: DWORD;
begin
  ImageNtHeaders^.OptionalHeader.CheckSum := CalcCheckSum;
  Result := ImageNtHeaders^.OptionalHeader.CheckSum;
end;

{
  Achtung:
    Man darf nicht einfach so eine Sektion vergrößern. Wenn man zum Beispiel
    die Code-Sektion vergrößern will und da gibt es zufälligerweise Befehle wie
    JMP DWORD PTR DS:[402004], dann darf man die Code-Sektion nicht vergrößern
    sonst zeigen die JMP's und CALL's auf falsche Addressen und das Programm stürzt
    einfach ab!
}
function TPeFile.ResizeSection(wSection: Word; Count: Cardinal): Boolean;
var
  x , y: Word;
  SectionOffset, SectionSize, FileAlign, SectionAlign, dwTemp: Cardinal;
  lpDirectoryEntries: array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1] of Byte;
  lpEOFData: Pointer;
  dwEOFDataLength: DWORD;
  {
    Diese prozedur ändert den OffsetToData in Ressourcen, damit die Ressourcen
    immer noch lesbar sind.
  }
  procedure RecalcResourceSection(VA, Add: DWORD);
    procedure ParseResources(Offset: DWORD; Level: Byte);
    var
      Table: PImageResourceDirectory;
      Entry: PImageResourceDirectoryEntry;
      EntryData: PImageResourceDataEntry;
      i, Count: Integer;
    begin
      Table := Pointer(RvaToVa(VA  + Offset));
      Count := Table^.NumberOfNamedEntries + Table^.NumberOfIdEntries;
      Entry := Pointer(RvaToVa(VA + Offset + SizeOf(TImageResourceDirectory)));
      for i := 0 to Count -1 do
      begin
        case Level of
          { Langs }
          2:
            begin
              EntryData := PImageResourceDataEntry(RvaToVa(VA + Entry^.OffsetToData));
              EntryData^.OffsetToData := EntryData^.OffsetToData + Add;
            end;
        end;
        if (Entry^.OffsetToData and $80000000) > 0 then
          ParseResources(Entry^.OffsetToData and $7fffffff, Level +1);
        Inc(Entry);
      end;
    end;
  begin
    if (ImageNtHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress <> 0) then
    begin
      ParseResources(0, 0);
    end;
  end;
begin
  Result := False;
  FillChar(lpDirectoryEntries, SizeOf(lpDirectoryEntries), #0);
  if ((wSection < FNumberOfSections) and (wSection <> High(Word)) and (Count > 0)) then
  begin
    lpEOFData := nil;
    dwEOFDataLength := 0;
    GetDataFromEOF(lpEOFData, dwEOFDataLength);
    SectionOffset := ImageSections[wSection].PointerToRawData;
    SectionSize := ImageSections[wSection].SizeOfRawData;
    FileAlign := ImageNtHeaders^.OptionalHeader.FileAlignment;
    SectionAlign := ImageNtHeaders^.OptionalHeader.SectionAlignment;
    Count := Align(Count, FileAlign);
    // einfügen
    InsertBytes(SectionOffset + SectionSize, Count);
    // die größe der aktuellen sektion vergrößern
    ImageSections[wSection].SizeOfRawData := ImageSections[wSection].SizeOfRawData + Count;
    // wenn virtualsize kleiner ist als sizeofrawdata dann passen wir die größe natürlich an :)
    if (ImageSections[wSection].Misc.VirtualSize < ImageSections[wSection].SizeOfRawData) then
    begin
      ImageSections[wSection].Misc.VirtualSize := Align(ImageSections[wSection].SizeOfRawData, SectionAlign);
    end;
    // wenns unter der vorletzten sektion ist dann gehts los
    if (wSection < FNumberOfSections -1) then
    begin
      for x := wSection +1 to High(ImageSections) do
      begin
        // virtuelle addressen und größen anpassen!
        ImageSections[x].PointerToRawData := ImageSections[x].PointerToRawData + Count;
        ImageSections[x].Misc.VirtualSize := Align(ImageSections[x].Misc.VirtualSize + Count, SectionAlign);
      end;
      // virtuelle addresse von datadirectories ändern
      for x := wSection to High(ImageSections) do
      begin
        if (x < FNumberOfSections) then
        begin
          if ((ImageSections[x].VirtualAddress + ImageSections[x].Misc.VirtualSize) > ImageSections[x +1].VirtualAddress) then
          begin
            // alle directories durchlaufen und prüfen ob wir schon geupdatet haben
            // falls ja wird auf der "selben stelle" im array lpdirectoryentries ein <nonzero> wert stehen
            for y := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES -1 do
            begin
              if ((ImageNtHeaders^.OptionalHeader.DataDirectory[y].VirtualAddress <> 0) and
                  (ImageNtHeaders^.OptionalHeader.DataDirectory[y].Size <> 0)) then
              begin
                dwTemp := ImageNtHeaders^.OptionalHeader.DataDirectory[y].VirtualAddress;
                if (dwTemp = ImageSections[x +1].VirtualAddress) then
                begin
                  if (lpDirectoryEntries[y] = 0) then
                  begin
                    ImageNtHeaders^.OptionalHeader.DataDirectory[y].VirtualAddress := Align(ImageSections[x].VirtualAddress + ImageSections[x].Misc.VirtualSize, SectionAlign);
                    lpDirectoryEntries[y] := y +1;
                    if (y = IMAGE_DIRECTORY_ENTRY_RESOURCE) then
                    begin
                      // die OffsetToData bei den Resourcen ändern!
                      RecalcResourceSection(dwTemp, ImageNtHeaders^.OptionalHeader.DataDirectory[y].VirtualAddress - dwTemp);
                    end;
                    Break;
                  end;
                end;
              end;
            end;
            // startaddresse der nächsten sektion ändern!
            ImageSections[x +1].VirtualAddress := Align(ImageSections[x].VirtualAddress + ImageSections[x].Misc.VirtualSize, SectionAlign);
          end;
        end; 
      end;
    end;
    RecalcImageSize;
    // noch am ende die EOF Daten kopieren
    if ((lpEOFData <> nil) and (dwEOFDataLength <> 0)) then
    begin
      // die größte/letzte sektion herausfinden
      CopyMemory(Pointer(Cardinal(lpBuffer) + GetHighestSectionSize), lpEOFData, dwEOFDataLength);
      FreeMem(lpEOFData, dwEOFDataLength);
    end;
    RecalcCheckSum;
  end;
end;

end.
