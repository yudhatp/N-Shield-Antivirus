unit UnicodeFiles;

//begin_license
//(c) Trieu Tran Duc 2002-2007
//Author's email: trieutranduc@gmail.com
//Original File Name: UnicodeFiles.pas
//License updated on: 08/10/07 9:56:23 PM
//This file follows a dual licensing model:
//	Either you forllow GPL version 2 and open your source code
//	or Get permissions from the author to keep your source closed.
//end_license


interface
Uses Windows, Sysutils;

Type
  TSearchRecW = record
    Time: Integer;
    Size: Integer;
    Attr: Integer;
    Name: TFileName;
    ExcludeAttr: Integer;
    FindHandle: THandle;
    FindData: TWin32FindDataW;
  end;

function FileAgeW(FileName: Widestring): Integer;
function fileexistsW(FileName: Widestring): boolean;
function FolderexistsUTF8(Directory:string):integer;
function fileexistsUTF8(FileName:string):integer;
function makeUniqueTempFile: string;
function FindMatchingFileW(var F: TSearchRecW): Integer;
function FindFirstW(const Path: widestring; Attr: Integer;  var  F: TSearchRecW): Integer;
function FindNextW(var F: TSearchRecW): Integer;
function isUnicodeSystem: boolean;
procedure FindCloseW(var F: TSearchRecW);
function RenameFileUTF8(f1,f2:string):boolean;
function DeleteFileUTF8(FileName:string):boolean;
function DeleteFileNextBootUTF8(FileName:string):boolean;
function MoveFileExUTF8(FileName,NewFileName:string; dwFlags: DWORD):boolean;

implementation

function FileAgeW(FileName: Widestring): Integer;
var
  Handle: THandle;
  FindData: TWin32FindDataW;
  LocalFileTime: TFileTime;
begin
  Handle := FindFirstFileW(PWideChar(FileName), FindData);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(Handle);
    if (FindData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
    begin
      FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
      if FileTimeToDosDateTime(LocalFileTime, LongRec(Result).Hi,
        LongRec(Result).Lo) then Exit;
    end;
  end;
  Result := -1;
end;

function fileexistsW(FileName: Widestring): boolean;
begin
  Result := FileAgeW(FileName) <> -1;
end;

function FolderexistsUTF8(Directory:string):integer;
var
  Code: Integer;
  DW: widestring;
begin
  result:=0;
  Code := GetFileAttributes(PChar(Directory));
  if (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0) then
   begin result:=1; exit end; //ansi exists

  dw:=UTF8Decode(Directory);
  Code:=GetFileAttributesW(PWideChar(DW));
  if (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0) then
   begin result:=2; exit end; //ansi exists
end;

function fileexistsUTF8(FileName:string):integer;
var sw: widestring;
    s: string;
begin
 result:=0; //not exists
 if FileExists(FileName) then result:=1 //exists ansi
 else
 begin
  sw:=UTF8Decode(FileName);
  if fileexistsW(sw) then result:=2; //exists wide
 end
end;

function makeUniqueTempFile: string;
begin
 result:='C:\Winnt\Temp\'+inttohex(gettickcount+random(255),10)+'.tmp';
end;

function FindMatchingFileW(var F: TSearchRecW): Integer;
var
  LocalFileTime: TFileTime;
begin
  with F do
  begin
    while FindData.dwFileAttributes and ExcludeAttr <> 0 do
      if not FindNextFileW(FindHandle, FindData) then
      begin
        Result := GetLastError;
        Exit;
      end;
    FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
    FileTimeToDosDateTime(LocalFileTime, LongRec(Time).Hi,
      LongRec(Time).Lo);
    Size := FindData.nFileSizeLow;
    Attr := FindData.dwFileAttributes;
    Name := UTF8Encode(FindData.cFileName);
  end;
  Result := 0;
end;

procedure FindCloseW(var F: TSearchRecW);
begin
  if F.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(F.FindHandle);
    F.FindHandle := INVALID_HANDLE_VALUE;
  end;
end;

function FindFirstW(const Path: widestring; Attr: Integer;  var  F: TSearchRecW): Integer;
const
  faSpecial = faHidden or faSysFile or faVolumeID or faDirectory;
begin
  F.ExcludeAttr := not Attr and faSpecial;
  F.FindHandle := FindFirstFilew(PWideChar(Path), F.FindData);
  if F.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    Result := FindMatchingFileW(F);
    if Result <> 0 then FindCloseW(F);
  end else
    Result := GetLastError;
end;

function FindNextW(var F: TSearchRecW): Integer;
begin
  if FindNextFileW(F.FindHandle, F.FindData) then
    Result := FindMatchingFileW(F) else
    Result := GetLastError;
end;

function isUnicodeSystem: boolean;
begin
//tntunicode use (Win32Platform = VER_PLATFORM_WIN32_NT)
 result := GetVersion and $80000000 = 0;
end;

function RenameFileUTF8(f1,f2:string):boolean;
var fw1,fw2: widestring;
begin
 if isUnicodeSystem then
  begin
   fw1:=UTF8Decode(f1); fw2:=UTF8Decode(f2);
   result:=MoveFileW(pwidechar(fw1),pwidechar(fw2))
  end
 else result:=MoveFile(pchar(f1),pchar(f2));
end;

function DeleteFileUTF8(FileName:string):boolean;
begin
 if isUnicodeSystem then
 begin
  SetFileAttributesW(pwidechar(UTF8Decode(FileName)),FILE_ATTRIBUTE_NORMAL); //fix, delete access denied
  result:=windows.DeleteFileW(pwidechar(UTF8Decode(FileName)))
 end 
 else
 begin  
  SetFileAttributes(pchar(FileName),FILE_ATTRIBUTE_NORMAL); //fix, delete access denied 
  Result := Windows.DeleteFile(PChar(FileName));
 end 
end;

function MoveFileExUTF8(FileName,NewFileName:string; dwFlags: DWORD):boolean;
begin
 if isUnicodeSystem then
  result:=MoveFileExW(pwidechar(UTF8Decode(FileName)),pwidechar(UTF8Decode(NewFilename)),dwFlags)
 else
  result:=windows.MoveFileEx(pchar(FileName),pchar(NewFileName),dwFlags);
end;

function DeleteFileNextBootUTF8(FileName:string):boolean;
begin
 if isUnicodeSystem then
  result:=MoveFileExW(pwidechar(UTF8Decode(FileName)),nil,MOVEFILE_DELAY_UNTIL_REBOOT)
 else
  result:=MoveFileEx(pchar(FileName),nil,MOVEFILE_DELAY_UNTIL_REBOOT)
end;

end.
