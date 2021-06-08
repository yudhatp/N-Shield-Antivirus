unit PE;

interface
  uses windows, sysutils, classes, MD5, EHeader;

function nshieldgetfileinfo(hFile: cardinal) : nav_fileinfo;
function nshieldPEinfo(filename: WideString; var peinfo: nshield_infope): boolean;

implementation

function nshieldPEinfo(filename: WideString; var peinfo: nshield_infope): boolean stdcall;
var
    desc: tfilestream;
    i, raw, size: integer;
    info: nav_fileinfo;
    dig: TMD5Digest;
    err: integer;
begin
    result := false;
    size := 0;
    err := 0;

    try
        peinfo.pe_entrypoint := 0;
        peinfo.pe_seccount   := 0;
        peinfo.pe_size       := 0;
        peinfo.pe_linker     := '';
        peinfo.pe_epsection  := '';
        peinfo.pe_subsys     := '';
    except
    end;
    if not fileexists(filename) then exit;
    (* *)
    try
        try
            desc := tfilestream.Create(filename, fmShareDenyNone);
        except
            err := 1;
            exit;
        end;
        (* *)
        info := nshieldgetfileinfo(desc.Handle);

        if not info.PE then exit;

        result := true;

        peinfo.pe_size       := desc.size;
        peinfo.pe_entrypoint := info.entrypoint;
        peinfo.pe_seccount   := info.sections;

        peinfo.pe_linker     := info.linker;
        peinfo.pe_epsection  := info.epsection;
        peinfo.pe_subsys     := info.subsystem;

        peinfo.pe_firstbytes[1] := info.firstbytes[1];
        peinfo.pe_firstbytes[2] := info.firstbytes[2];
        peinfo.pe_firstbytes[3] := info.firstbytes[3];
        peinfo.pe_firstbytes[4] := info.firstbytes[4];

        (* *)
        //setlength(peinfo.pe_sections,info.sections+1);
        for i := 0 to info.sections - 1 do begin
            raw  := info.wSectionNfo[i].rOffset;
            size := info.wSectionNfo[i].rSize;
            dig  := nshieldMD5streamex(desc, raw, raw + size);

            peinfo.pe_sections[i].sec_md5  := nshieldMD5digest2str(dig);
            peinfo.pe_sections[i].sec_name := info.wSectionNfo[i].rName;

            peinfo.pe_sections[i].sec_raw_size   := size;
            peinfo.pe_sections[i].sec_raw_offset := raw;
            peinfo.pe_sections[i].sec_vir_size   := info.wSectionNfo[i].vSize;
            peinfo.pe_sections[i].sec_vir_offset := info.wSectionNfo[i].vOffset;
            peinfo.pe_sections[i].sec_flag       := info.wSectionNfo[i].flags;
        end;
        (* *)
    finally

        if err = 0 then
            desc.free;

    end;
    (* *)
end;
(******************************************************************************)
function nshieldgetfileinfo(hFile: cardinal) : nav_fileinfo;
type
   PIMAGE_DOS_HEADER=^IMAGE_DOS_HEADER;
   PIMAGE_NT_HEADERS=^IMAGE_NT_HEADERS;
   PIMAGE_SECTION_HEADER=^IMAGE_SECTION_HEADER;
var
    DosHead:IMAGE_DOS_HEADER;
    imgsection:IMAGE_SECTION_HEADER;
    i:integer;
    dop:cardinal;
    numbers:word;
    buf,EPSection:array[0..512] of char;
    EntryPoint,FileOffset:integer;
    FirstBytes:array[1..4] of char;
    hFileMapping:cardinal;
    p,a:PBYTE;
    bytesread:dword;
    hImg:DWORD;
    pc:pchar;
    PEHead:IMAGE_NT_HEADERS;
    sSize : int64;
begin
    Result.PE := False;
    Result.EntryPoint := 0;

    for i := 0 to 32 do
        Result.wSections[i] := 0;

    try
        sSize := GetFileSize(hFile,nil);
        result.filesize := sSize;
    except
        exit;
    end;
    
    try
        if (hFile = INVALID_HANDLE_VALUE) then CloseHandle(hFile) else
      	begin
            hFileMapping:=CreateFileMapping(hFile, nil, PAGE_READONLY, 0, 0, pchar('nav_peheader'+inttohex(random(255),2)));
            if hFileMapping<>0 then begin
                p := nil;
                p := MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);
                a := p;
                doshead:=PIMAGE_DOS_HEADER(p)^;
                if p <> nil then
                if doshead.e_magic=IMAGE_DOS_SIGNATURE then
          		  begin
                    p:=pointer(integer(p)+doshead._lfanew);
                    try
                        pehead:=PIMAGE_NT_HEADERS(p)^;
                    except
                        UnMapViewOfFile(a);
                        CloseHandle(hFileMapping);
                        exit;
                    end;
                    EntryPoint := PEHead.OptionalHeader.AddressOfEntryPoint;
                    FileOffset := EntryPoint-imgsection.VirtualAddress+imgsection.PointerToRawData;
                    (* *)
                    result.linker := inttostr(PEHead.OptionalHeader.MajorLinkerVersion)+'.'+inttostr(PEHead.OptionalHeader.MinorLinkerVersion);
                    case pehead.OptionalHeader.Subsystem of
                        0: result.subsystem   :='Unknown';
                        1: result.subsystem   :='Native';
                        2: result.subsystem   :='Win32 GUI';
                        3: result.subsystem   :='Win32 Console';
                        else result.subsystem :='Unknown';
                    end;
                    (* *)
                    numbers := PEHead.FileHeader.NumberOfSections;
                    (* *)
                    if numbers > 32 then begin
                        UnMapViewOfFile(a);
                        CloseHandle(hFileMapping);
                        exit;
                    end;
                    Result.Sections := numbers;
                    p := pointer(integer(p)+sizeof(IMAGE_NT_HEADERS));
                    Result.PE := true;

                    for i:=1 to numbers do
                    begin
                        imgsection:=PIMAGE_SECTION_HEADER(p)^;
                        lstrcpyn(@buf,@imgsection.name,8);
                        (* *)
                        Result.wSections[i-1] := imgsection.PointerToRawData;
                        (* *)
                        Result.wSectionNfo[i-1].rName   := buf;
                        Result.wSectionNfo[i-1].flags   := imgsection.Characteristics;
                        Result.wSectionNfo[i-1].rSize   := imgsection.SizeOfRawData;
                        Result.wSectionNfo[i-1].rOffset := imgsection.PointerToRawData;
                        Result.wSectionNfo[i-1].vSize   := imgsection.Misc.VirtualSize;
                        Result.wSectionNfo[i-1].vOffset := imgsection.VirtualAddress;
                        (* *)
                        if (EntryPoint>=imgsection.VirtualAddress)and(EntryPoint<=imgsection.VirtualAddress+imgsection.Misc.VirtualSize) then
                        begin
                            EPSection  := buf;
                            FileOffset := EntryPoint-imgsection.VirtualAddress+imgsection.PointerToRawData;

                            Result.epsection := EPSection;
                        end;
                        p := pointer(integer(p)+sizeof(IMAGE_SECTION_HEADER));
                    end;
                    (* *)
                    SetFilePointer(hFile,fileoffset,nil,FILE_BEGIN);
                    ReadFile(hFile,Result.firstbytes,4,bytesread,nil);
                    SetFilePointer(hFile,0,nil,FILE_BEGIN);

                    Result.EntryPoint := FileOffset;
                end;
            end;
        UnMapViewOfFile(a);
        CloseHandle(hFileMapping);
        //CloseHandle(hFile);
        end;
    except
    end;
end;
(******************************************************************************)
end.
