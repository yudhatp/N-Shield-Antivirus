unit Database;

interface
  uses windows, sysutils, Strings, EHeader, Normalisasi, PatternMatch, Hashing
      ,WhiteList, DBkode, zLib, classes, MD5, ntech;

procedure NShield_Start_Engine(var engine: nshield_engine; debug: pesan_debug);
procedure NShield_Stop_Engine(var engine: nshield_engine);
procedure NShield_Virus_Signature(root: nshield_engine; const sign: pchar);

procedure NShield_Load_Database(root: nshield_engine; filename: pchar);
procedure loadvdb(root: nshield_engine; filename: pchar);

procedure NShield_Encrypt(dbfile: pchar; dbdate: pchar; license: pchar);
procedure NShield_Decyrpt(filename: pchar);
procedure NShield_Get_VBD_Dir(engine: nshield_engine; dir: pchar; loadfilevdb: boolean);
procedure NShield_Config(engine: nshield_engine; scanners: myscan_options; maxfsize, maxasize: int64; tempdir: pchar);

implementation
uses
    compare;

{function ConvertToDate(date: String): String;
begin
    result := date;
    insert('.', result, 3);
    insert('.', result, 6);
end;  }

{function GetLastDBDate(date: string) : string;
begin
    result := ConvertToDate(date);
end;

function CompareTooDates(d1,d2: string): integer;
var
    dt1,dt2: TDateTime;
begin
    try
        if d2 = '000000' then begin
            result := 1;
            exit;
        end;
        dt1 := strtodate(converttodate(d1));
        dt2 := strtodate(converttodate(d2));
        if dt1 > dt2 then
            result := 1
        else
            result := 2;
    except
        result := 0;
    end;
end;  }

procedure NShield_Stop_Engine(var engine: nshield_engine) stdcall;
var
    i : integer;
begin
    try
        free_wild(engine^.wild_node);
        free_norm(engine^.norm_suffix, engine^.norm_shift);

        if engine^.badsigs <> nil then
            freebadsigs(engine^.badsigs^);  //xc_freebadsigs

            engine^.badsigs := nil;

        if engine^.whitesigs <> nil then
            freewhitesigs(engine^.whitesigs^);

            engine^.whitesigs := nil;

        if engine^.navforce <> nil then
            nshieldfreeforce(engine^.navforce^);

            engine^.navforce := nil;

        free_hash(engine^.hash_shift, engine^.hash_suffix);
        free_hash(engine^.sect_shift, engine^.sect_suffix);

        for i := 0 to MAX_HASH_SIZE do begin
            engine^.norm_shift[i] := 0;
            engine^.hash_shift[i] := 0;
            engine^.sect_shift[i] := 0;
        end;

        Finalize(engine^.norm_b1b3);
        Finalize(engine^.norm_b1b2);
        Finalize(engine^.norm_b2b3);

        Freemem(engine^.debug);
        engine^.debug := nil;

        //engine^.lastdate := '';

        engine^.wild_partsigs := 0;
        engine^.sigloaded := 0;

        freemem(engine);
        engine := nil;
    except

    end;
end;

procedure NShield_Start_Engine(var engine: nshield_engine; debug: pesan_debug) stdcall;
var
    i, j, stady : integer;
begin
    (* *)
    stady := 0;
    new(engine);
  try
    (* *)
    new(engine^.debug);
    engine^.debug^ := debug;
    inc(stady);

    (* set default options *)

    engine^.options.scanners := [];
    engine^.options.scanners := [pindai_pdf, pindai_gambar, pindai_pe, pindai_lainnya, pindai_rar, pindai_zip];
    engine^.options.maxfsize := MAXFILESIZE;
    engine^.options.maxasize := MAXARCHSIZE;
    engine^.options.tempdir  := pchar(extractfilepath(paramstr(0))+ENGINETEMP);

    inc(stady);
    (* *)
    engine^.lastdate := '000000';

    engine^.wild_partsigs := 0;
    engine^.sigloaded := 0;
    engine^.maxpatlen := 0;
    engine^.minpatlen := 255;
    inc(stady);

    freemem(engine^.badsigs);
    engine^.badsigs := nil;
    freemem(engine^.whitesigs);
    engine^.whitesigs := nil;
    freemem(engine^.navforce);
    engine^.navforce := nil;

    for i := 0 to MAX_HASH_SIZE do begin
        engine^.norm_shift[i]  := -1;
        freemem(engine^.norm_suffix[i]);
        engine^.norm_suffix[i] := nil;

        engine^.hash_shift[i]  := -1;
        freemem(engine^.hash_suffix[i]);
        engine^.hash_suffix[i] := nil;

        engine^.sect_shift[i]  := -1;
        freemem(engine^.sect_suffix[i]);
        engine^.sect_suffix[i] := nil;
    end;
    inc(stady);
    
    for i := 0 to 255 do
        for j := 0 to 255 do begin
            engine^.wild_node[chr(i),chr(j)] := nil;

            engine^.norm_b1b2[chr(i),chr(j)] := false;
            engine^.norm_b1b3[chr(i),chr(j)] := false;
            engine^.norm_b2b3[chr(i),chr(j)] := false;
        end;
    inc(stady); 
    (* *)
    nshielddebug_msg(engine^.debug^, NSHIELD_INIT,[ ENGINEVERSION ]);
    (* *)
  except
  (* *)
  nshielddebug_msg(engine^.debug^, NSHIELD_INITERROR,[ stady ]);
  (* *)
  end;
end;

procedure NShield_Config(engine: nshield_engine; scanners: myscan_options; maxfsize, maxasize: int64; tempdir: pchar) stdcall;
begin
    engine^.options.scanners := scanners;
    engine^.options.maxfsize := maxfsize;
    engine^.options.maxasize := maxasize;
    engine^.options.tempdir  := tempdir;
end;

procedure nshieldparse_add(var root: nshield_engine; virname, hexsig: pchar; offset: pchar; ftype: dword);
var
    i, j, len : integer;
    parts, asterisk : integer;
    mindist ,maxdist : integer;
    start, pt, hexcpy, n : pchar;
    error : integer;
begin
    error := 0; parts := 0;
    mindist := -1; maxdist := -1;

    if pos('}',hexsig) <> 0 then begin

        mindist := -1; maxdist := -1;

        inc(root^.wild_partsigs);
        len := strlen(hexsig);

        for i := 0 to len do
            if (hexsig[i] = '{') or (hexsig[i] = '*') then
                asm inc parts end;

        asm inc parts end;

        hexcpy := hexsig;
        pt     := hexsig;
        start  := hexsig;

        for i := 1 to parts do begin
            pt := '';
            if i <> parts then
                for j := 0 to (strlen(start)) do begin
                    if start[j] = '{' then begin
                        asterisk := 0;
                        pt := start + j + 1;
                        start := pchar(strget(pchar(start), j, '{'));
                        break;
                    end else
                    if start[j] = '*' then begin
                        asterisk := 1;
                        pt := start + j + 1;
                        start := pchar(strget(pchar(start), j, '*'));
                        break;
                    end;
                end;

            if not wild_addsig(root, virname, start, root^.wild_partsigs, parts, i, ftype, mindist, maxdist, offset) then
            begin
                error := 1;
                break;
            end;

            if i = parts then break;

            mindist := 0; maxdist := 0;

            if (asterisk <> 0) then begin
                start := pt;
                Continue;
            end;

            start := pt;
            pt    := pchar(copy(pt,1,pos('}',pt)-1));
            start := pchar(copy(start,strlen(pt)+2,strlen(start)));

            if start = '' then begin
                error := 1;
                break;
            end;

            if pt = '' then begin
                error := 1;
                break;
            end;

            if strchr(pt,'-') = '' then begin
                error := 1;
                break;
            end else begin
                n := pchar(strtok(pt,0,'-'));
                if strlen(n) <> 0 then begin
                    mindist := nshieldstr2int(n);
                    if mindist < 0 then begin
                        error := 1;
                        break;
                    end;
                end;
                n := pchar(strtok(pt,1,'-'));
                if strlen(n) <> 0 then begin
                    maxdist := nshieldstr2int(n);
                    if maxdist < 0 then begin
                        error := 1;
                        break;
                    end;
                end;
            end;
        end;
        if error = 1 then begin
            nshielddebug_msg(root^.debug^, NSHIELD_PARSE_ERR,[ virname ]);
            exit;
        end;
    end else if pos('*',hexsig) <> 0 then begin

        inc(root^.wild_partsigs);
        len := strlen(hexsig);

      	for i := 0 to len do
	          if hexsig[i] = '*' then
        	    	asm inc parts end;

       asm inc parts end;

        for i := 1 to parts do begin
            pt := pchar(strtok(hexsig, i-1, '*'));
            if pt = '' then begin
                error := 1;
                exit;
            end;
            if not wild_addsig(root, virname, pt, root^.wild_partsigs, parts, i, ftype, 0, 0, offset) then begin
                nshielddebug_msg(root^.debug^, NSHIELD_PARSE_ERR,[ virname ]);
                exit;
            end;
        end;

    end else
        if (pos('(',hexsig) <> 0) or (pos('?',hexsig) <> 0) then begin
            if not wild_addsig(root, virname, hexsig, 0, 0, 0, ftype, 0, 0, offset) then begin
                nshielddebug_msg(root^.debug^, NSHIELD_PARSE_ERR,[ virname ]);
                exit;
            end;
        end else begin
            if not norm_add_suffix(root,virname,hexsig,offset,ftype) then begin
                nshielddebug_msg(root^.debug^, NSHIELD_PARSE_ERR,[ virname ]);
                exit;
            end;
        end;
end;

//fungsi membaca database virus
procedure NShield_Virus_Signature(root: nshield_engine; const sign: pchar) stdcall;
var
    sigtype: char;
    lp, cf: integer;
    pt: pointer;
    virname, filetype, offset, hexsig, hsize: pchar;
begin
    sigtype := sign[0];
    pt := @sign;
    lp := 0; cf := 0;
    case sigtype of
    //tipe signature ada disini, seperti hexa, MD5
    //tadinya pakai -> : sekarang diganti menjadi -> |
    //untuk tipe signature
    {
    sebelumnya "1" sekarang ganti jadi P , yang berarti PATTERN
    sebelumnya "2" sekarang ganti jadi H, yang berarti HASH / MD5 HASH
    sebelumnya "3" sekarang ganti jadi O, yang berarti OFFSET/ MD5 berdasarkan EP
    sebelumnya "+" sekarang ganti jadi W, yang berarti WHITELIST
    }
        //'0' : begin
        //          virname := pchar(strtoken(pt,1,'|', lp, cf));
        //          hexsig  := pchar(strtoken(pt,2,'|', lp, cf));
        //          if strlen(virname) = 0 then
        //              xc_debug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
        //          else
        //              xc_parse_add(root, virname, hexsig, '*', NSHIELD_TYPEFULL);
        //      end;
        'P' : begin
                  virname  := pchar(strtoken(pt,1,'|', lp, cf));
                  filetype := pchar(strtoken(pt,2,'|', lp, cf));
                  offset   := pchar(strtoken(pt,3,'|', lp, cf));
                  hexsig   := pchar(strtoken(pt,4,'|', lp, cf));
                  
                  if pos(',',offset) <> 0 then
                      exit;

                  if strlen(virname) = 0 then
                      nshielddebug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
                  else
                      nshieldparse_add(root, virname, hexsig, offset, strtoint(filetype));
              end;
        'H' : begin
                  virname := pchar(strtoken(pt,1,'|', lp, cf));
                  hexsig  := pchar(strtoken(pt,2,'|', lp, cf));
                  hsize   := pchar(strtoken(pt,3,'|', lp, cf));

                  if strlen(virname) = 0 then
                      nshielddebug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
                  else
                      hash_add_suffix(root, root^.hash_suffix, root^.hash_shift, virname, hexsig, strtoint(hsize));
              end;
        'O' : begin
                  virname := pchar(strtoken(pt,1,'|', lp, cf));
                  hexsig  := pchar(strtoken(pt,2,'|', lp, cf));
                  hsize   := pchar(strtoken(pt,3,'|', lp, cf));

                  if strlen(virname) = 0 then
                      nshielddebug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
                  else
                      hash_add_suffix(root, root^.sect_suffix, root^.sect_shift, virname, hexsig, strtoint(hsize));
              end;
        //'-' : begin
        //          virname := pchar(strtoken(pt,1,'|', lp, cf));
        //          if strlen(virname) = 0 then
        //              xc_debug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
        //          else
        //              addbadsigs(root, virname);  //xc_addbadsigs
        //      end;
        'W' : begin
                  virname := pchar(strtoken(pt,1,'|', lp, cf));
                  hexsig  := pchar(strtoken(pt,2,'|', lp, cf));
                  hsize   := pchar(strtoken(pt,3,'|', lp, cf));
                  if strlen(virname) = 0 then
                      nshielddebug_msg(root^.debug^, NSHIELD_PARSE_EVN,[ ])
                  else
                      addwhitesigs(root, virname, hexsig, strtoint(hsize));
              end;              
              (* Unknow signature version(type) *)
              else begin
                  nshielddebug_msg(root^.debug^, NSHIELD_PARSE_UST,[ sign[0] ]);
              end;
    end;
    virname  := '';
    filetype := '';
    offset   := '';
    hexsig   := '';
    hsize    := '';
end;

procedure compilevdb(filename: pchar; header: nav_header) stdcall;
var
    outstream: tfilestream;
    instream: tfilestream;
    h: nav_header;
begin
    h := header;
    //h.signature := EVDBSIGN;
    outstream := TFileStream.Create(filename+MAINVDBEXT, fmcreate);
    instream  := TFileStream.Create(filename, fmOpenRead);
    try
    outstream.write(Header,SizeOf(nav_header));
    outstream.seek(SizeOf(Header),soFromBeginning);
    with TCompressionStream.Create(TCompressionLevel( clDefault ), outStream) do
    try
        CopyFrom(inStream, inStream.Size);
        Free;
    except
    end;
    finally
    outstream.free;
    instream.free;
    end;
end;

procedure NShield_Decyrpt(filename: pchar) stdcall;
var
    outstream: tfilestream;
    instream: tfilestream;
    license: tfilestream;
    zstream: TDecompressionStream;
    buffer: array [1..2048] of byte;
    h: nav_header;
    count: integer;
begin
    try
        instream := TFileStream.Create(filename,fmShareDenyRead);
    except
        exit;
    end;
    (* *)
    instream.Seek(0,soFromBeginning);
    instream.Read(h,sizeof(nav_header));
    //if h.signature <> EVDBSIGN then
    //begin
   //     instream.Free;
   //     exit;
   // end;
    (* *)
    try
        outstream := TFileStream.Create(filename+'.txt', fmCreate); //.xdb
        //license := TFileStream.Create(filename+'.nshield', fmCreate);  //.license
        //license.WriteBuffer(h.license, sizeof(h.license));
        (* *)
        inStream.Seek(0,SizeOf(nav_header));
        outStream.Seek(0,soFromBeginning);
        ZStream := TDecompressionStream.Create(instream);
        count := 0;
        while true do
        begin
            Count := ZStream.Read(buffer, sizeof(buffer));
            if Count <> 0 then begin
              outstream.WriteBuffer(buffer, count);
            end else break;
        end;
    finally
        zstream.Free;
        outstream.Free;
        license.free;
        instream.Free;
    end;
end;

//fungsi untuk meng-pack dan enkrip database
//format HEADER |
procedure NShield_Encrypt(dbfile: pchar; dbdate: pchar; license: pchar) stdcall;
var
    header: nav_header;
    i, len: integer;
begin
    zeromemory(@header, sizeof(nav_header));

    //header.signature := EVDBSIGN;
    //header.basedate := dbdate;

    len := strlen(license);
    if len > 7 then len := 7;   //1023

    for i := 0 to len do
        header.license[i] := license[i];

    //kompress file
    compilevdb(dbfile, header);
end;


procedure loadvdb(root: nshield_engine; filename: pchar) stdcall;
var
    header: nav_header;
    count: integer;
    zstream: TDecompressionStream;
    buffer: array [1..2048] of char;
    instream : tfilestream;
    ret, sign, pt: string;
    date: pchar;
    i, cn, error, fn, lp: integer;
begin   
    if not fileexists(filename) then begin
        nshielddebug_msg(root^.debug^, NSHIELD_EOPEN_PDB,[ ExtractFileName(filename) ]);
        exit;
    end;

    try
        instream := TFileStream.Create(filename,fmShareDenyRead);
    except
        nshielddebug_msg(root^.debug^, NSHIELD_EREAD_PDB, []);
        exit;
    end;
    instream.Seek(0,soFromBeginning);
    instream.Read(header,sizeof(nav_header));
    //if header.signature <> EVDBSIGN then
   // begin
   //     instream.Free;
   //     exit;
   // end;

    //nshielddebug_msg(root^.debug^, NSHIELD_BUILD_PDB, [header.basedate]);
    //if CompareTooDates(header.basedate, root^.lastdate) = 1 then begin
    //    root^.lastdate := header.basedate;
    //end;

    inStream.Seek(0,SizeOf(nav_header));
    ZStream:=TDecompressionStream.Create(instream);
    try

    ret := '';

    while true do
    begin
        Count:=ZStream.Read(buffer, sizeof(buffer));
        if Count <> 0 then begin
            (* *)
            cn := 0;

            for i := 1 to Count-1 do
                if (buffer[i] = #13) and (buffer[i+1] = #10) then begin
                    buffer[i] := #0;
                    inc(cn);
                end;

            pt := ret + buffer;
            fn := 0; lp := 1;
            
            for i := 0 to cn + 1 do begin
                if i = cn + 1 then begin
                    ret := sign;
                    break;
                end else
                begin
                    sign := strtoken(@pt,i, #10, fn, lp);
                    if i = cn then continue;
                    nshieldtrimstr(sign);
                    NShield_Virus_Signature(root, pchar(sign));
                end;
            end;

            sign := '';
            ZeroMemory(@buffer, sizeof(buffer));
            (* *)
        end
            else Break;
    end;

    except
        instream.Free;
        zstream.Free;
    end;
    ret := '';
    zstream.Free;
    instream.Free;
    nshielddebug_msg(root^.debug^, NSHIELD_LOAD_PDB, [ ExtractFileName(filename) ]);
end;

//fungsi untuk meload database ke memory
procedure NShield_Load_Database(root: nshield_engine; filename: pchar) stdcall;
var
    desc: tfilestream;
    error: integer;
    i, len, cn, fn, lp: integer;
    readb: cardinal;
    buffer: array [1..2048] of char;
    ppt: pointer;
    ret, pt: string;
    sign: string;
begin
    if not fileexists(filename) then begin
        nshielddebug_msg(root^.debug^, NSHIELD_EOPENDB,[ ExtractFileName(filename) ]);
        exit;
    end;
    
    try
        error := 0;
        try
            desc := tfilestream.Create(filename, fmShareDenyRead);
        except
            nshielddebug_msg(root^.debug^,NSHIELD_EREADDB, []);
            error := 1;
            exit;
        end;

        if desc.size = 0 then begin
            desc.free;
            exit;
        end;

        readb := 1;
        ret := '';
        try
        while readb > 0 do begin
        (* *)
            cn := 0;

            readb :=  desc.read(buffer,sizeof(buffer));

            for i := 1 to readb-1 do
                if (buffer[i] = #13) and (buffer[i+1] = #10) then begin
                    buffer[i] := #0;
                    inc(cn);
                end;

            pt := ret + buffer;
            fn := 0; lp := 1;

            for i := 0 to cn + 1 do begin
                if i = cn + 1 then begin
                    ret := sign;
                    break;
                end else
                begin
                    sign := strtoken(@pt,i, #10, fn, lp);

                    if i = cn then continue;
                    nshieldtrimstr(sign);
                    NShield_Virus_Signature(root, pchar(sign));
                end;
            end;

            sign := '';
            ZeroMemory(@buffer, sizeof(buffer));
        (* *)
        end;
        except
        end;
    finally
        if error = 0 then begin
            ret := '';
            finalize(buffer);
            desc.free;
        end;
    end;
    nshielddebug_msg(root^.debug^, NSHIELD_LOADDB,[ ExtractFileName(filename) ]);
end;

//fungsi untuk membaca path database
procedure NShield_Get_VBD_Dir(engine: nshield_engine; dir: pchar; loadfilevdb: boolean) stdcall;
var
    sr : TSearchRec;
    findres,i : Integer;
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

        if FileExists(Dir+SR.Name) then
        begin
           if nshieldlowercase(ExtractFileExt(sr.name)) = MAINVDBEXT then
                loadvdb(engine, pchar(dir+sr.name));

            if nshieldlowercase(ExtractFileExt(sr.name)) = UPDVDBEXT then
                if loadfilevdb then
                    NShield_Load_Database(engine, pchar(dir+sr.name));
       end;

        FindRes:=FindNext(SR);

    end;
    SysUtils.FindClose(SR);
end;

end.
