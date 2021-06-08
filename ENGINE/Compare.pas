{N-Shield AntiVirus Engine
last update = 22 maret 2014
Untuk proses scanning file}

unit Compare;

interface
  uses windows, sysutils, classes, Strings, EHeader, PE, Normalisasi,
       PatternMatch, Hashing, MD5, Arsip, DBkode, WhiteList,
       ntech, FileHeader, Heuristic;


function validatesign(const offset: nav_offset; fileoff: integer; info: nav_fileinfo) : boolean;

function NShield_Match_File(engine: nshield_engine; filename: pchar; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug; progress: boolean = false): integer;
function scanfile(engine: nshield_engine; filename: string; ftype: integer; info: nav_fileinfo; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug; progress: boolean = false): integer;

function NShield_Scan_Buffer(engine: nshield_engine; buffer: my_buffer; ftype: dword; var virname: pchar): boolean;

//function databasedate(engine: nshield_engine): pchar;
function Nshield_Get_VirusCount(engine: nshield_engine): integer;
function NShield_Get_VirusName: pchar;
function NShield_Get_Engine_Version: pchar;
function NShield_CheckEncrypted(FilePath:string):Boolean;
function NShield_CheckOverlay(FilePath:string):Boolean;
function hapusfile(FileName: pchar) : boolean;

procedure nshielddebug_msg(debug: pesan_debug; msg: dword; const args: array of const);

implementation

{function ReadUnicodeTextFile(aFName: string): WideString;
var
  buf: array[0..1024] of WideChar;
  f: file;
  dwRest, dwRead: DWORD;
begin
  result := '';
  Assign(f, aFName);
  Reset(f, 1);
  dwRest := FileSize(f);
  Assert((dwRest mod SizeOf(widechar)) = 0); //Unicode chars always 2 bytes
  while dwRest > 1do
  begin
    BlockRead(f, buf, sizeof(buf), dwRead);
    if dwRest > dwRead then
      Dec(dwRest, dwRead)
    else
      dwRest := 0;
    buf[dwRead mod 2] := WideChar(#0);
    result := result + PWideString(buf);
  end;
end;     }

//function databasedate(engine: nshield_engine): pchar stdcall;
//begin
//    result := pchar(engine^.lastdate);
//end;
function CalcEntropyForBuffer(Buffer:Pointer; BufferSize:DWORD):Double;
const
  DbLog:   Double = 1.4426950408889634073599246810023;
var
  Entropy:  Double;
  Entries:  array[0..255] of DWORD;
  i:        DWORD;
  Temp:     Double;
begin
  Entropy := 0.00;
  ZeroMemory(@Entries, SizeOf(Entries));
  for i := 0 to (BufferSize - 1) do
    Inc(Entries[PByte(DWORD(Buffer) + i)^]);
  for i := 0 to 255 do
  begin
    Temp := Entries[i] / BufferSize;
    if ( Temp > 0 ) then
      Entropy := Entropy +- Temp * (Ln(Temp) * DbLog);
  end;
  Result := Entropy;
end;

{function CalcEntropyForFile(FilePath:string):Double;
var
  hFile:        DWORD;
  dwFileSize:   DWORD;
  dwBytesRead:  DWORD;
  pBuffer:      Pointer;
begin
  Result := 0.00;
  hFile := CreateFileA(PChar(FilePath), GENERIC_READ, 0, nil, OPEN_EXISTING, 0, 0);
  if not ( hFile = INVALID_HANDLE_VALUE ) then
  begin
    dwFileSize := GetFileSize(hFile, nil);
    if not ( dwFileSize = 0 ) then
    begin
      pBuffer := VirtualAlloc(nil, dwFileSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
      if ( Assigned(pBuffer) ) then
      begin
        ReadFile(hFile, pBuffer^, dwFileSize, dwBytesRead, nil);
        if ( dwBytesRead = dwFileSize ) then
          Result := CalcEntropyForBuffer(pBuffer, dwFileSize);
        VirtualFree(pBuffer, 0, MEM_RELEASE);
      end;
    end;
    CloseHandle(hFile);
  end;
end; }

function NShield_CheckEncrypted(FilePath:string):Boolean;
var
  pFile:          Pointer;
  dwFileSize:     DWORD;
  IDH:            PImageDosHeader;
  INH:            PImageNtHeaders;
  ISH:            PImageSectionHeader;
  TempEntropy:    Double;
  szSectionName:  array[0..7] of Char;
  i:              WORD;
  dwOverlaySize:  DWORD;
  desc: tfilestream;
  sizenya : int64;
begin
  Result := FALSE;
  try
      desc := tfilestream.create(filepath, fmShareDenyNone);
          except
          exit;
    end;

  sizenya := desc.size;
  if sizenya > 900000 then result :=false; //900kb

  if ( FileToPtr(FilePath, pFile, dwFileSize) ) then
  begin

    end;
    IDH := pFile;
    if ( IDH^.e_magic = IMAGE_DOS_SIGNATURE ) then
    begin
      INH := Pointer(DWORD(pFile) + IDH^._lfanew);
      if ( INH^.Signature = IMAGE_NT_SIGNATURE )  then
      begin
        ISH := Pointer(DWORD(INH) + SizeOf(DWORD) + SizeOf(TImageFileHeader) + INH^.FileHeader.SizeOfOptionalHeader);
        for i := 0 to INH^.FileHeader.NumberOfSections - 1 do
        begin
          CopyMemory(@szSectionName[0], ISH, 8);
          TempEntropy := 0.00;
          if ( ISH^.SizeOfRawData > 0 )  then
            TempEntropy := CalcEntropyForBuffer(Pointer(DWORD(pFile) + ISH^.PointerToRawData), ISH^.SizeOfRawData);
          begin
            //Caption := szSectionName;
            if szSectionName = '.text' then result := false;
            //SubItems.Add(IntToHex(INH^.OptionalHeader.ImageBase + ISH^.VirtualAddress, 8));
            //SubItems.Add(IntToHex(ISH^.Misc.VirtualSize, 8));
            //sebelumnya 6.70, 7.00, 7.87 , rawan false alarm
            if ( TempEntropy > 7.95 ) then //and ( TempEntropy <= 8.00 ) ) then
            //if (TempEntropy = 8.00) then
            //VirtualFree(pFile, 0, MEM_RELEASE);
              result:= true;
          end;
          Inc(ISH);
        end;
        //Dec(ISH);
        //overlay
        //dwOverlaySize := dwFileSize - (ISH^.PointerToRawData + ISH^.SizeOfRawData);
        //if ( dwOverlaySize > 0 ) then
        //begin
         //TempEntropy := CalcEntropyForBuffer(Pointer(DWORD(pFile) + ISH^.PointerToRawData + ISH^.SizeOfRawData), dwOverlaySize);

         //begin
          //if (TempEntropy = 8.00) then
          //VirtualFree(pFile, 0, MEM_RELEASE);
           // result := true;
         //end;
      //end; yudha
    end;
    Finalize(TempEntropy);  //yudha ,ga ngaruh x_x tetap berat
    ZeroMemory(@szSectionName, SizeOf(szSectionName)); //yudha ,ga ngaruh x_x tetap berat
    VirtualFree(pFile, 0, MEM_RELEASE);
  end;
end;

function NShield_CheckOverlay(FilePath:string):Boolean;
var
  pFile:          Pointer;
  dwFileSize:     DWORD;
  IDH:            PImageDosHeader;
  INH:            PImageNtHeaders;
  ISH:            PImageSectionHeader;
  TempEntropy:    Double;
  //szSectionName:  array[0..7] of Char;
  i:              WORD;
  dwOverlaySize:  DWORD;
begin
  Result := FALSE;
  if ( FileToPtr(FilePath, pFile, dwFileSize) ) then
  begin

    end;
    IDH := pFile;

        dwOverlaySize := dwFileSize - (ISH^.PointerToRawData + ISH^.SizeOfRawData);
        if ( dwOverlaySize > 0 ) then
        begin
         //TempEntropy := CalcEntropyForBuffer(Pointer(DWORD(pFile) + ISH^.PointerToRawData + ISH^.SizeOfRawData), dwOverlaySize);

         begin
          //Caption := 'Overlay';
         // SubItems.Add(STR_NA);
          //SubItems.Add(STR_NA);
          //SubItems.Add(Format('%n', [TempEntropy]));
          //if ( TempEntropy < 6.50 ) then
          //  SubItems.Add(STR_NOT_PACKED)
          //else if ( ( TempEntropy > 6.50 ) and ( TempEntropy < 6.70 ) ) then
          //  SubItems.Add(STR_MAYBE_PACKED)
          //else
          if ( ( TempEntropy > 7.00 ) and ( TempEntropy <= 8.00 ) ) then
          VirtualFree(pFile, 0, MEM_RELEASE);
            result := true;
         end;
    //end;
    VirtualFree(pFile, 0, MEM_RELEASE);
  end;
end;

function Nshield_Get_VirusCount(engine: nshield_engine): integer stdcall;
begin
    result := engine^.sigloaded;
end;

function NShield_Get_VirusName: pchar stdcall;
begin
    result := ENGINENAME;
end;

function NShield_Get_Engine_Version: pchar stdcall;
begin
    result := ENGINEVERSION;
end;

procedure nshielddebug_msg(debug: pesan_debug; msg: dword; const args: array of const);
begin
    try
        debug(msg, args);
    except
    end;
end;

function NShield_Scan_Buffer(engine: nshield_engine; buffer: my_buffer; ftype: dword; var virname: pchar): boolean stdcall;
var
    partcnt, partoff: nav_acclc;
    fileinfo: nav_fileinfo;
    mdhash: nshield_mdbuff;
    i: integer;
begin
    setlength(partcnt, engine^.wild_partsigs+1);
    setlength(partoff, engine^.wild_partsigs+1);

    for i := 0 to engine^.wild_partsigs do begin
        partcnt[i] := 0;
        partoff[i] := 0;
    end;

    fileinfo.PE := false;
    fileinfo.filesize := length(buffer)-1;

    try

        result := norm_scanbuff(engine, buffer, fileinfo, ftype, 0, length(buffer)-1, virname);
        if not result then
            result := wild_scanbuff(engine, buffer, partcnt, partoff, fileinfo, ftype, 0, length(buffer)-1, virname);
        if not (result) then begin
            pchar2mdbuffer(mdhash,pchar(nshieldMD5digest2str(nshieldMD5buffer(buffer,length(buffer)))));
            result := hash_scanbuff(engine^.hash_suffix, engine^.hash_shift, mdhash,fileinfo.filesize,virname);
            if not result then
                result := hash_scanbuff(engine^.sect_suffix, engine^.sect_shift, mdhash, fileinfo.wSectionNfo[i].rSize, virname);
        end;

        if (result) and (inbadsigs(engine, virname)) then result := false;

    finally
        finalize(partcnt);
        finalize(partoff);
    end;
end;

function hapusfile(FileName: pchar) : boolean stdcall;
var
    Flags : Cardinal;
begin
    try
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

        if not DeleteFile(FileName) then
        begin
            Result := false;
            Exit;
        end;
        try
            Result := DeleteFile(FileName);
        except
        end;

    finally
        if not FileExists(FileName) then
            Result := true
        else
            Result := false;
    end;
end;

procedure nshieldremovedir(sdir : string);
var
    iIndex : Integer;
    SearchRec : TSearchRec;
    sFileName : String;
begin
    sDir := sDir + '\*.*';
    iIndex := FindFirst(sDir, faAnyFile, SearchRec);
    while iIndex = 0 do
    begin
        sFileName := ExtractFileDir(sDir)+'\'+SearchRec.Name;
        if (SearchRec.Attr = faDirectory) or (DirectoryExists(ExtractFileDir(sDir)+'\'+SearchRec.Name+'\')) then
        begin
            if (SearchRec.Name <> '' ) and (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then nshieldremovedir(sFileName);
        end
        else
        begin
            if SearchRec.Attr <> faArchive then FileSetAttr(sFileName, faArchive);
            hapusfile(pchar(sFileName));
        end;
        iIndex := FindNext(SearchRec);
    end;
    SysUtils.FindClose(SearchRec);
    RemoveDir(ExtractFileDir(sDir));    
end;

function unpackname : string;
begin
    result := (inttohex(random(255),2))+(inttohex(random(255),2))+(inttohex(random(255),2))+
              (inttohex(random(255),2))+(inttohex(random(255),2))+(inttohex(random(255),2))+
              (inttohex(random(255),2))+(inttohex(random(255),2))+(inttohex(random(255),2))+
              (inttohex(random(255),2))+(inttohex(random(255),2))+(inttohex(random(255),2));
end;

function scanarch(engine: nshield_engine; undir: string; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug): integer;
var
    SR        : TSearchRec;
    FindRes,i : Integer;
begin
    FindRes:=FindFirst(undir+'*.*',faAnyFile,SR);
    While FindRes=0 do begin

        if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then
        begin
            FindRes:=FindNext(SR);
            Continue;
        end;

        if ((SR.Attr and faDirectory)=faDirectory) then
        begin
            Result := 0;
            result := scanarch(engine ,undir+sr.name+'\', virname, progresscall, debugcall);
            if result = BERVIRUS then begin
                SysUtils.FindClose(SR);
                exit;
            end;

            FindRes:=FindNext(SR);
            Continue;
        end;

        if FileExists(undir+sr.name) then
        begin
            try
                (* *)
                result := BERSIH;
                nshielddebug_msg(debugcall, NSHIELD_UNARCH_FILE, [ sr.name ]);
                result := NShield_Match_File(engine, pchar(undir+sr.name), virname, progresscall, debugcall, true);
                if result = BERVIRUS then begin
                    SysUtils.FindClose(SR);
                    exit;
                end else result := BERSIH;
                (* *)
            except
            end;
        end;
        FindRes:=FindNext(SR);
    end;
    SysUtils.FindClose(SR);
end;

function scanarchive(engine: nshield_engine; ftype: dword; filename: string; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug): integer;
var
    unarch : boolean;
    undir, dir, temp : string;
begin
    result := BERSIH;  
    unarch := false;
    temp   := engine^.options.tempdir;
    temp   := ExtractFilePath(ExpandFileName(temp+'TEMP.$$$'));
    dir    := temp + unpackname+'\';
    progresscall(-1);
    try

        if not directoryexists(temp) then
            createdir(temp);
        if not directoryexists(dir) then
            createdir(dir);

        undir := nshieldshortfilename(dir);

        if dir = '' then exit;
        
        unpackarsip(engine, ftype, filename, undir, unarch);
    except
        unarch := false;
    end;
    if not unarch then begin
        result := BERSIH;
        progresscall(100);
        exit;
    end else begin
        result := BERSIH;
        result := scanarch(engine, undir, virname, progresscall, debugcall);
        nshieldremovedir(undir);
    end;
    progresscall(100);
end;

{function scanhtml(engine: nshield_engine; ftype: dword; filename: string; info: nav_fileinfo; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug): integer;
var
    expath: string;
begin
    result := BERSIH;
    expath := engine^.options.tempdir + unpackname+'\';
    try

        if not directoryexists(engine^.options.tempdir) then
            createdir(engine^.options.tempdir);
        if not directoryexists(expath) then
            createdir(expath);

        expath := nshieldshortfilename(expath);

        if expath = '' then exit;
        
        if not fixhtml(pchar(filename), pchar(expath)) then exit;
    except
        nshieldremovedir(expath);
        exit;
    end;

    result := scanfile(engine, pchar(filename), ftype, info, virname, progresscall, debugcall);
    if result <> BERVIRUS then
        result := scanfile(engine, pchar(expath+navhtmlnokomen), ftype, info, virname, progresscall, debugcall);
    if result <> BERVIRUS then
        result := scanfile(engine, pchar(expath+navhtmlnotag), ftype, info, virname, progresscall, debugcall);

        //jika result tidak sama maka result bersih
    if result <> BERVIRUS then result := BERSIH;

    nshieldremovedir(expath);
    progresscall(100);
end; }

{fungsi untuk scan file berdasarkan pattern dan hash MD5}
function scanfile(engine: nshield_engine; filename: string; ftype: integer; info: nav_fileinfo; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug; progress: boolean = false): integer stdcall;
var
    desc: tfilestream;
    buff: my_buffer;
    size: int64;
    mdhash, sechash: nshield_mdbuff;
    partcnt, partoff: nav_acclc;
    sectdigest, filedigest: TMD5Digest;
    readed, readsize, realoff, i, raw, ssize, percent, error: integer;
begin
    error := 0;
    virname := '';
    result := BERSIH;
    try
        try
            desc := tfilestream.create(filename, fmShareDenyNone);
        except
            error := -1;
            result := DIBACA;
            exit;
        end;

        //jika file tidak bisa dihandle [open,read] maka keluar saja =))
        if (desc.handle = INVALID_HANDLE_VALUE) or (desc.handle < 0) then begin
            exit;
        end;

        //jika ukuran file kosong, keluar juga :D
        size := desc.size;
        if size = 0 then begin
            result := KOSONG;
            exit;
        end;

        //jika ukuran file melebihi batas maksimal file, keluar juga :D
        if size > engine^.options.maxfsize then begin
            result := UKURAN;
            exit;
        end;
        (* *)
        setlength(partcnt, engine^.wild_partsigs+1);
        setlength(partoff, engine^.wild_partsigs+1);
        for i := 0 to engine^.wild_partsigs do begin
            partcnt[i] := 0;
            partoff[i] := 0;
        end;

        percent := -1;

        if size < BUFFER_READ then
            readsize := size
            else begin
                readsize := BUFFER_READ;
                percent := size div 100;
            end;

        setlength(buff, readsize);
        realoff := 0;
        readed := 1;
        (* getting md5 *)
        filedigest := nshieldMD5streamex(desc, 0, size);
        pchar2mdbuffer(mdhash,pchar(nshieldMD5digest2str( filedigest )));
        (* navforce sys *)
        if (pindai_force in engine^.options.scanners) then
            if inforcesigs(engine, mdhash, size) then begin
                result := BERSIH;
                exit;
            end;

        {scan dengan hash md5 pada whitelist}
        if inwhitesigs(engine, mdhash, size, virname) then
            if not inbadsigs(engine, virname) then begin
                result := BERSIH;
                exit;
            end;

        {scan dgn hash MD5}
        if result = BERSIH then
            if hash_scanbuff(engine^.hash_suffix, engine^.hash_shift, mdhash, size, virname) then begin
                result := BERVIRUS;
                exit;
            end;

        {scan dengan pattern, dengan wildcard atau tanpa wildcard/normal}
        while readed <> 0 do begin
            readed := desc.read(buff[0], readsize);
            try
                if norm_scanbuff(engine, buff, info, ftype, realoff, readed, virname) then
                    result := BERVIRUS
                    else
                if wild_scanbuff(engine, buff, partcnt, partoff, info, ftype, realoff, readed, virname) then
                    result := BERVIRUS;
                    //yudha wumanber
                //if NShield_CheckEncrypted(filename) then
                    //result := BERVIRUS;
            except
            end;
            inc(realoff, readed);
            desc.seek(realoff - engine^.maxpatlen, sofrombeginning);

            if (percent > 0) and (progress) then
                progresscall(realoff div percent);

            if (result = BERVIRUS) then break;
        end;

        {scan dengan hash MD5 file}
        //dipindahkan ke atas
        {if result = BERSIH then
            if hash_scanbuff(engine^.hash_suffix, engine^.hash_shift, mdhash, size, virname) then begin
                result := BERVIRUS;
                exit;
            end; } //sebelumnya -> end
            {else
            //* scan pe sections md5 *
            if result = BERSIH then
                if (ftype = NSHIELD_TYPEPE) then begin
                    for i := 0 to info.Sections - 1 do begin
                        raw := info.wSectionNfo[i].rOffset;
                        ssize := info.wSectionNfo[i].rSize;
                        if ssize = 0 then continue;
                        sectdigest := nshieldMD5streamex(desc, raw, raw + ssize);
                        pchar2mdbuffer(sechash,pchar(nshieldMD5digest2str( sectdigest )));
                        if hash_scanbuff(engine^.sect_suffix, engine^.sect_shift, sechash, ssize, virname) then begin
                            result := BERVIRUS;
                            exit;
                        end;
                    end;
                end;}
        (* *)
        if (pindai_force in engine^.options.scanners) and (result = BERSIH) then
            addforcesigs(engine, mdhash, size);
        (* *)
    finally
        if (result = BERVIRUS) and
           (inbadsigs(engine, virname)) then begin
                virname := '';
                result := BERSIH;
            end;

        if error = 0 then begin
            desc.free;
            finalize(partcnt);
            finalize(partoff);
            finalize(buff);
        end;
    end;
end;

function NShield_Match_File(engine: nshield_engine; filename: pchar; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug; progress: boolean = false): integer stdcall;
var
    ftype: integer;
    size: int64;
    peinfo: nav_fileinfo;
    shortname: string;
begin
    (* *)
    result    := BERSIH;
    shortname := nshieldshortfilename(filename);
    ftype     := nshieldgetfiletype(pchar(shortname), peinfo, virname);
    size      := peinfo.filesize;
    (* *)
    case ftype of
        NSHIELD_ALGOS        : begin
                              if  (progress) then
                                  progresscall(100);
                              result  := BERVIRUS;
                              exit;
                          end;
        NSHIELD_TYPENOTHING : begin
                              if  (progress) then
                                  progresscall(100);
                              exit;
                          end;
        //NSHIELD_TYPEDATA    : begin
                     //         if  (progress) then
                     //             progresscall(100);
                      //        exit;
                     //     end;
        NSHIELD_TYPEARCHIVE : begin
                              if  (progress) then
                                  progresscall(100);
                              exit;
                          end;
        NSHIELD_TYPEOTHER   : if not (pindai_lainnya   in engine^.options.scanners) then exit;
        NSHIELD_TYPEPE      : if not (pindai_pe      in engine^.options.scanners) then exit;
        NSHIELD_TYPEGRAPHIC : if not (pindai_gambar in engine^.options.scanners) then exit;
        NSHIELD_TYPEPDF     : if not (pindai_pdf     in engine^.options.scanners) then exit;
        //NSHIELD_TYPEHTML    : if not (pindai_html    in engine^.options.scanners) then exit;
        NSHIELD_TYPERAR     : if not (pindai_rar   in engine^.options.scanners) then exit;
        NSHIELD_TYPEZIP     : if not (pindai_zip   in engine^.options.scanners) then exit;
    end;
    (* archives *)
    if (ftype = NSHIELD_TYPERAR) or (ftype = NSHIELD_TYPEZIP) then begin
        if size > engine^.options.maxasize then exit;
        result := scanarchive(engine, ftype, shortname, virname, progresscall, debugcall);
        exit;
    end;
    (* html *)
    //header file HTML di unit FileHeader perlu diperbaiki [?]
    {if ftype = NSHIELD_TYPEHTML then begin
        if size > engine^.options.maxfsize then exit;
        result := scanhtml(engine, ftype, filename, peinfo, virname, progresscall, debugcall);
        exit;
    end;  }
    (* *)
    result := scanfile(engine, shortname, ftype, peinfo, virname, progresscall, debugcall, progress);
    (* *)
    if (progress) then
        progresscall(100);
end;

function validatesign(const offset: nav_offset; fileoff: integer; info: nav_fileinfo) : boolean;
begin
    result := false;

    case offset.otype of
        nav_entrypoint       : begin
                          if not info.PE then exit;
                          if info.EntryPoint + offset.offcn <> fileoff then exit;
                          result := true;
                          exit;
                      end;
        nav_section     : begin
                          if not info.PE then exit;
                          if info.wSectionNfo[offset.osect].rOffset + offset.offcn <> fileoff then exit;
                          result := true;
                          exit;
                      end;
        nav_eof      : begin
                          if info.filesize + offset.offcn <> fileoff then exit;
                          result := true;
                          exit;
                      end;
        nav_stable   : begin
                          if offset.offcn <> fileoff then exit;
                          result := true;
                          exit;
                      end;
        nav_all      : begin
                          result := true;
                          exit;
                      end;
        nav_lastsection : begin
                          if not info.PE then exit;
                          if info.wSectionNfo[info.Sections - 1].rOffset + offset.offcn <> fileoff then exit;
                          result := true;
                          exit;
                      end;
    end;
end;

end.
 