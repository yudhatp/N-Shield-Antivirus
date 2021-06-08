unit Arsip;  

interface

uses SysUtils, Windows, EHeader, UnZip, UnRarLib;

procedure unpackarsip(engine: nshield_engine; ftype : dword; archivefile, unpackpath: string; var resultarch: boolean);

var
  RARHeaderData : TRARHeaderData;
  ArcStruct: TRAROpenArchiveData;
  CmtBuffer : array[0..1023] of char;
  
implementation
(* -------------------------------------------------------------------------- *)
function OpenRARArchive(FileName : string) : THandle;
begin
    ZeroMemory(@ArcStruct, sizeof(ArcStruct));
    ArcStruct.OpenMode := RAR_OM_EXTRACT;
    ArcStruct.ArcName  := pchar(FileName);
    ArcStruct.CmtBuf   := CmtBuffer;
    ArcStruct.CmtBufSize := sizeof(CmtBuffer);
    Result := RAROpenArchive(ArcStruct);
end;

function UnRarFile(RarFileName : string; Directory : string = '') : boolean;
var
    hRAR           : THandle;
    hReadHeader    : integer;
    hProcessHeader : integer;
begin
    Result := false;
    try
        UniqueString(RarFileName);
        RarFileName := ExpandFileName(RarFileName);
        UniqueString(Directory);
        if length(Directory) = 0 then
            Directory := ChangeFileExt(RarFileName, '')
        else Directory := ExpandFileName(Directory);
            CharToOem(pchar(Directory), pchar(Directory));
        hRAR := OpenRARArchive(RarFileName);
        if hRAR = 0 then begin
            Result := false;
            Exit;
        end;
        hReadHeader := 0;
        hProcessHeader := 0;
    REPEAT
        hReadHeader := RARReadHeader(hRar, RARHeaderData);
        if hReadHeader = 18
        then begin
            Break;
            Result := False;
        end;

        if hReadHeader = ERAR_END_ARCHIVE
        then begin
            Break;
            Result := False;
        end;

        if (RARHeaderData.Flags and 4)=4 then
        begin
            Result := False;
            Break;
        end;

        OemToChar(RARHeaderData.FileName, RARHeaderData.FileName);
        if hReadHeader = RAR_SUCCESS then begin
            hProcessHeader := RARProcessFile(hRar, RAR_EXTRACT, PChar(Directory), nil);
            Result := true;
        end;
    UNTIL (hProcessHeader <> RAR_SUCCESS);
    RARCloseArchive(hRAR)
    except
        RARCloseArchive(hRAR);
        Result := false;
    end;
end;

(* -------------------------------------------------------------------------- *)
function UnZipFile(ZipFileName : string; Directory : string = '') : boolean;
var
    zp: TVCLUnZip;
begin
    Result := False;
    try
        zp := TVCLUnZip.Create(nil);
        zp.DestDir := Directory;
        zp.RootDir := Directory;
        zp.ZipName := ZipFileName;
        zp.RecreateDirs := true;
        zp.DoAll   := true;
        zp.ReadZip;
        if zp.UnZip > 0 then Result := True;
    finally
        zp.Free;
    end;
end;
(* -------------------------------------------------------------------------- *)
procedure unpackarsip(engine: nshield_engine; ftype : dword; archivefile, unpackpath: string; var resultarch: boolean);
begin
    try
        ResultArch := False;
        CreateDirectory(PChar(UnpackPath),0);
        if ftype = NSHIELD_TYPERAR then begin
            ResultArch := UnRarFile(ArchiveFile, UnpackPath);
        end;
        if ftype = NSHIELD_TYPEZIP then begin
            ResultArch := UnZipFile(ArchiveFile, UnpackPath);
        end;
    except
        resultarch := false;
    end;
end;

end.
