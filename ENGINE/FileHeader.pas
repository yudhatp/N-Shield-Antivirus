unit FileHeader;

interface
  uses windows, sysutils, classes, EHeader, PE, Strings;

    type
    nav_magics = record
        offset : integer;
        magic  : pchar;
        length : dword;
        ftype  : integer;
    end;

    const
    (* Viruses *)
    //string parite = GetProcAddress.
    PARITE        : array [0..14]  of char    = (#$47,#$65,#$74,#$50,#$72,#$6f,#$63,#$41,#$64,#$64,#$72,#$65,#$73,#$73,#$00);
    //MAGISTR_A     : array [0..4]   of char    = (#$e8,#$2c,#$61,#$00,#$00);
    //MAGISTR_B     : array [0..4]   of char    = (#$e8,#$04,#$72,#$00,#$00);

    //KLEZ          : array [1..42]  of integer = ($55,$8B,$EC,$6A,$FF,$68,$40,$D2,$40,NSHIELD_IGN,$68,$04,$AC,$40,NSHIELD_IGN,$64,$A1,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,$50,$64,$89,$25,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,$83,$EC,$58,$53,$56,$57,$89,$65,$E8,$FF,$15,$BC,$D0);
    //HYBRIS        : array [1..32]  of integer = ($EB,$16,$A8,$54,NSHIELD_IGN,NSHIELD_IGN,$47,$41,$42,$4C,$4B,$43,$47,$43,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,NSHIELD_IGN,$52,$49,$53,-1,$FC,$68,$4C,$70,$40,NSHIELD_IGN,$FF,$15);
    //BUGLE         : array [1..255] of integer = ($6A,$00,$E8,$95,$01,$00,$00,$E8,$9F,$E6,$FF,$FF,$83,$3D,$03,$50,$40,$00,$00,$75,$14,$68,$C8,$AF,$00,$00,$E8,$01,$E1,$FF,$FF,$05,$88,$13,$00,$00,$A3,$03,$50,$40,$00,$68,$5C,$57,$40,$00,$68,$F6,$30,$40
    //                                            ,$00,$FF,$35,$03,$50,$40,$00,$E8,$B0,$EA,$FF,$FF,$E8,$3A,$FC,$FF,$FF,$83,$3D,$54,$57,$40,$00,$00,$74,$05,$E8,$F3,$FA,$FF,$FF,$68,$E8,$03,$00,$00,$E8,$B1,$00,$00,$00,$EB,$F4,$CC,$FF,$25,$A4,$40,$40,$00
    //                                            ,$FF,$25,$B8,$40,$40,$00,$FF,$25,$B4,$40,$40,$00,$FF,$25,$B0,$40,$40,$00,$FF,$25,$AC,$40,$40,$00,$FF,$25,$9C,$40,$40,$00,$FF,$25,$A0,$40,$40,$00,$FF,$25,$A8,$40,$40,$00,$FF,$25,$24,$40,$40,$00,$FF,$25
    //                                            ,$28,$40,$40,$00,$FF,$25,$2C,$40,$40,$00,$FF,$25,$30,$40,$40,$00,$FF,$25,$34,$40,$40,$00,$FF,$25,$38,$40,$40,$00,$FF,$25,$3C,$40,$40,$00,$FF,$25,$40,$40,$40,$00,$FF,$25,$44,$40,$40,$00,$FF,$25,$48,$40
    //                                            ,$40,$00,$FF,$25,$4C,$40,$40,$00,$FF,$25,$50,$40,$40,$00,$FF,$25,$54,$40,$40,$00,$FF,$25,$58,$40,$40,$00,$FF,$25,$5C,$40,$40,$00,$FF,$25,$60,$40,$40,$00,$FF,$25,$BC,$40,$40,$00,$FF,$25,$64,$40,$40,$00
    //                                            ,$FF,$25,$68,$40,$40);

    (* Files types *)
    nav_magic : array [0..23] of nav_magics = (  //88
    (* Windows PE *)
    (offset: 0;  magic: 'MZ';                         length: 2; ftype: NSHIELD_TYPEPE),
    (offset: 0;  magic: 'ZM';                         length: 2; ftype: NSHIELD_TYPEPE),

    //tipe file yang diabaikan
    {
    (offset: 0;  magic: 'OggS';                       length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: 'ID3';                        length: 3;  ftype: NSHIELD_TYPEDATA),
    (offset: 8;  magic: 'AVI';                        length: 3;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: '%!PS-Adobe-';                length: 11; ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: '.RMF';                       length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: #377#373#220;                 length: 3;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: #060#046#262#165#216#146#317; length: 7;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: #000#000#001#263;             length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: #000#000#001#272;             length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 8;  magic: 'WAVE';                       length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 0;  magic: #48#38#178#117#142 ;          length: 5;  ftype: NSHIELD_TYPEDATA),
    (offset: 12; magic: 'OS/2';                       length: 4;  ftype: NSHIELD_TYPEDATA),
    (offset: 4;  magic: 'ftyp3gp';                    length: 7;  ftype: NSHIELD_TYPEDATA), // 3GP Video Format
    (offset: 0;  magic: #010#005#001#008;             length: 4;  ftype: NSHIELD_TYPEDATA), // MMP Graphic
    (offset: 0;  magic: 'ÐÏ';                         length: 2;  ftype: NSHIELD_TYPEDATA), // Red Alert Game Save File
    (offset: 0;  magic: 'MSFT';                       length: 4;  ftype: NSHIELD_TYPEDATA), // Red Alert Game Data
    (offset: 0;  magic: 'MPQ';                        length: 3;  ftype: NSHIELD_TYPEDATA), // WarCraft 3 Game Data
    (offset: 0;  magic: #000#000#002#000#000;         length: 5;  ftype: NSHIELD_TYPEDATA), // TGA Picture
    (offset: 1;  magic: 'DMP';                        length: 3;  ftype: NSHIELD_TYPEDATA), // Games Data Models Pack
    (offset: 0;  magic: 'KASF';                       length: 4;  ftype: NSHIELD_TYPEDATA), // Cossacks Game Save File
    (offset: 0;  magic: 'VFS';                        length: 3;  ftype: NSHIELD_TYPEDATA), // Games Data Archive
    (offset: 2;  magic: 'BSL';                        length: 3;  ftype: NSHIELD_TYPEDATA), // PhotoShop Brush Style File
    (offset: 1;  magic: 'BGR';                        length: 4;  ftype: NSHIELD_TYPEDATA), // PhotoShop Colorize File
    (offset: 5;  magic: 'BIM';                        length: 3;  ftype: NSHIELD_TYPEDATA), // PhotoShop Pens File
    (offset: 1;  magic: 'BPS';                        length: 3;  ftype: NSHIELD_TYPEDATA), // PhotoShop Picture
    (offset: 0;  magic: #000#000#001#000;             length: 4;  ftype: NSHIELD_TYPEDATA), // Unknow Data File  CPT
    (offset: 0;  magic: 'CPT';                        length: 3;  ftype: NSHIELD_TYPEDATA), // CoreDraw Photo Paint File
    (offset: 0;  magic: 'MThd';                       length: 4;  ftype: NSHIELD_TYPEDATA), // midi sound
    (offset: 0;  magic: 'DDS';                        length: 3;  ftype: NSHIELD_TYPEDATA), // DDS Graphick
    (offset: 1;  magic: 'JNG';                        length: 3;  ftype: NSHIELD_TYPEDATA), // DDS Graphick
    (offset: 0;  magic: #000#000#001#186;             length: 4;  ftype: NSHIELD_TYPEDATA), // Unknow Data
    (offset:-1;  magic: 'LAME';                       length: 4;  ftype: NSHIELD_TYPEDATA), // mp3
    (offset: 0;  magic: #48#38#178;                   length: 3;  ftype: NSHIELD_TYPEDATA), // Some wma
    (offset: 0;  magic: #255#251#48;                  length: 3;  ftype: NSHIELD_TYPEDATA), // mp3
    (offset: 0;  magic: 'MO3';                        length: 3;  ftype: NSHIELD_TYPEDATA), // mo3 sound
    (offset: 2;  magic: 'Disk';                       length: 4;  ftype: NSHIELD_TYPEDATA), // vmware virtual disk }

    //tipe file gambar
    (offset: 0;  magic: 'BM';                         length: 2; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 0;  magic: 'GIF';                        length: 3; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 6;  magic: 'Exif';                       length: 4; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 6;  magic: 'JFIF';                       length: 4; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 0;  magic: #377#330#377;                 length: 3; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 0;  magic: #137+'PNG';                   length: 4; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 0;  magic: 'RIFF';                       length: 4; ftype: NSHIELD_TYPEGRAPHIC),
    (offset: 0;  magic: 'RIFX';                       length: 4; ftype: NSHIELD_TYPEGRAPHIC),

    //tipe file PDF
    (offset: 0;  magic: '%PDF-';                      length: 5; ftype: NSHIELD_TYPEPDF),

    //tipe file lainnya
    (offset: 0;  magic: '<!--[ANNIE';                 length: 10; ftype: NSHIELD_TYPEOTHER), //Annie.HTML
    (offset: 2;  magic: 'Data';                       length: 4; ftype: NSHIELD_TYPEOTHER),  //Xtc VBS
    (offset: 0;  magic: 'L';                          length: 1; ftype: NSHIELD_TYPEOTHER),  //Ramnit Shortcut
    (offset: 2;  magic: 'VBS';                        length: 3; ftype: NSHIELD_TYPEOTHER), //Flazz VBS
    (offset: 0;  magic: '{\\rtf';                     length: 5; ftype: NSHIELD_TYPEOTHER),

    //tipe file arsip
    (offset: 0;  magic: 'BZh';                        length: 3;  ftype: NSHIELD_TYPEARCHIVE),
    (offset: 0;  magic: 'MSCF';                       length: 4;  ftype: NSHIELD_TYPEARCHIVE),
    (offset: 0;  magic: '#@~^';                       length: 4;  ftype: NSHIELD_TYPEARCHIVE),
    (offset: 0;  magic: 'ITSF';                       length: 4;  ftype: NSHIELD_TYPEARCHIVE),
    (offset: 0;  magic: '7z';                         length: 2;  ftype: NSHIELD_TYPEARCHIVE),
    (offset: 0;  magic: 'Rar!';                       length: 4;  ftype: NSHIELD_TYPERAR),
    (offset: 0;  magic: 'PK';                         length: 2;  ftype: NSHIELD_TYPEZIP),
    (offset: 0;  magic: 'PK00PK';                     length: 6;  ftype: NSHIELD_TYPEZIP)
    //(offset: 0;  magic: '(This file must be converted with BinHex 4.0)';
                                                     // length: 45; ftype: NSHIELD_TYPEBINHEX),

    (* html *)
     {
    (offset:-1;  magic: '<head>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<Head>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<HEAD>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<body>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<Body>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<BODY>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<title>';                    length: 7;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<Title>';                    length: 7;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<TITLE>';                    length: 7;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<html>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<Html>';                     length: 6;  ftype: NSHIELD_TYPEHTML),
    (offset:-1;  magic: '<HTML>';                     length: 6;  ftype: NSHIELD_TYPEHTML),}
    );

    function nshieldgetfiletype(filename: pchar; var peinfo: nav_fileinfo; var virname: pchar): integer;

implementation

{
------------------------------------------------------------
fungsi cek magic header dari file untuk menentukan tipe file
result dimasukkan ke variabel magic.ftype
------------------------------------------------------------
}
function nshieldcheckmagic(buff: my_buffer; magic: nav_magics): integer;
var
    i,j: integer;
begin
    result := NSHIELD_TYPENOTHING;

    if magic.offset <> -1 then begin
        for i := 0 to magic.length - 1 do
            if buff[magic.offset + i] <> magic.magic[i] then begin
                exit;
            end else
            if i = magic.length - 1 then begin
                result := magic.ftype;
                exit;
            end;
    end else begin
        for i := 0 to length(buff) - magic.length do begin
            if buff[i] = magic.magic[0] then
                for j := 0 to magic.length - 1 do
                    if buff[i+j] <> magic.magic[j] then
                        break
                    else
                    if j = magic.length - 1 then begin
                        result := magic.ftype;
                        exit;
                    end;
        end;
    end;
end;

{
fungsi untuk mendapatkan filter tipe file dari fungsi cek magic header untuk di scan
jika tipe file tidak ada yang sama, maka result dikembalikan ke variabel NSHIELD_TYPEOTHER
atau tipe file lainnya juga di scan
}
function nshieldgetfiletype(filename: pchar; var peinfo: nav_fileinfo; var virname: pchar): integer;
var
    desc      : tfilestream;
    buff      : my_buffer;
    len, i, j : integer;
    size      : int64;
    pt        : integer;
    ftype     : integer;
    dam, bw   : integer;
    rs, vs    : integer;
begin
    ftype     := NSHIELD_TYPEOTHER;
    peinfo.pe := false;

    if not FileExists(filename) then begin
        ftype := NSHIELD_TYPEOTHER;
        exit;
    end;
    try
        desc := tfilestream.create(filename, fmShareDenyNone);
    except
        ftype := NSHIELD_TYPEOTHER;
        exit;
    end;
    try
        size := desc.size;

        if size < FTYPEBUFF then len := size else len := FTYPEBUFF;
        setlength(buff, len);

        if size = 0 then begin
            ftype := NSHIELD_TYPEOTHER;
            exit;
        end;

        desc.read(buff[0], len);

        //mulai pengecekkan
        for i := 0 to length(nav_magic) - 1 do begin
            if nshieldcheckmagic(buff, nav_magic[i]) <> NSHIELD_TYPENOTHING then begin
                ftype := nav_magic[i].ftype;
                (* *)
                if ftype = NSHIELD_TYPEPE then
                    peinfo := nshieldgetfileinfo(desc.handle);

                if (ftype = NSHIELD_TYPEPE) and (not peinfo.pe) then
                    ftype := NSHIELD_TYPEOTHER;

                //cek virus parite polymorphic
                //cek apakah EP tidak berada pada section pertama??
                if peinfo.entrypoint = peinfo.wSectionNfo[peinfo.Sections - 1].rOffset then begin

                        pt := nshieldoutstack(buff, 4040, PARITE, length(PARITE) - 1);
                        pt := pt + 15;

                        if pt <> -1 then
                            if (( nshieldreadint32(buff, pt)      xor nshieldreadint32(buff, pt + 4) )  = $505a4f) and //PZO
                               (( nshieldreadint32(buff, pt + 8)  xor nshieldreadint32(buff, pt + 12) ) = $ffffb)  and   //ÿÿ
                               (( nshieldreadint32(buff, pt + 16) xor nshieldreadint32(buff, pt + 20) ) = $b8)     then begin  //¸
                               virname := StrNew('Heur.Virus.Win32.Parite');
                               ftype   := NSHIELD_ALGOS;
                               exit;
                             end;
                    end;
(******************************************************************************)
{
                (* Engine VIRUS checking *)
                if ftype = NSHIELD_TYPEPE then begin
                    (* Getin EP buffer *)
                    desc.Seek(peinfo.entrypoint , soFromBeginning);

                    finalize (buff);
                    SetLength(buff    ,4096);
                    desc.Read(buff[0] ,4096);
                    (* Virus.KLEZ *)
                    for j := 0 to length(KLEZ)-1 do
                        if (KLEZ[j] <> NSHIELD_IGN) or (byte(buff[j]) <> KLEZ[j]) then
                            break
                        else if j = length(KLEZ)-1 then begin
                            virname := StrNew('Virus.Win32.Klez.A');
                            ftype   := NSHIELD_ALGOS;
                            exit;
                        end;
                    (* Virus.Bugle *)
                    for j := 0 to length(BUGLE)-1 do
                        if (BUGLE[j] <> NSHIELD_IGN) or (byte(buff[j]) <> BUGLE[j]) then
                            break
                        else if j = length(BUGLE)-1 then begin
                            virname := StrNew('Virus.Win32.Bugle.A');
                            ftype   := NSHIELD_ALGOS;
                            exit;
                        end;
                    (* Virus.Hybris *)
                    for j := 0 to length(HYBRIS)-1 do
                        if (HYBRIS[j] <> NSHIELD_IGN) or (byte(buff[j]) <> HYBRIS[j]) then
                            break
                        else if j = length(HYBRIS)-1 then begin
                            virname := StrNew('Virus.Win32.Hybris.A');
                            ftype   := NSHIELD_ALGOS;
                            exit;
                        end;
                    (* Virus.Parite.B *)
                    if peinfo.entrypoint = peinfo.wSectionNfo[peinfo.Sections - 1].rOffset then begin

                        pt := nshieldoutstack(buff, 4040, PARITE, length(PARITE) - 1);
                        pt := pt + 15;

                        if pt <> -1 then
                            if (( nshieldreadint32(buff, pt)      xor nshieldreadint32(buff, pt + 4) )  = $505a4f) and //PZO
                               (( nshieldreadint32(buff, pt + 8)  xor nshieldreadint32(buff, pt + 12) ) = $ffffb)  and   //ÿÿ
                               (( nshieldreadint32(buff, pt + 16) xor nshieldreadint32(buff, pt + 20) ) = $b8)     then begin  //¸
                               virname := StrNew('Heur.Virus.Win32.Parite');
                               ftype   := NSHIELD_ALGOS;
                               exit;
                             end;
                    end;
                    (* Virus.Magistr.A/B *)
                    if peinfo.sections > 1 then begin

                        dam := 0;
                        vs  := peinfo.wSectionNfo[peinfo.Sections - 1].vSize;
                        rs  := peinfo.wSectionNfo[peinfo.Sections - 1].rSize;

                        if rs < peinfo.wSectionNfo[peinfo.Sections - 1].rSize then begin
                            rs := peinfo.wSectionNfo[peinfo.Sections - 1].rSize;
                            dam := 1;
                        end;

                        if ((vs >= $612c) and (rs >= $612c) and (((vs and $ff) = $ec))) then begin

                            bw:= $7000;

                            desc.Seek(peinfo.wSectionNfo[peinfo.Sections - 1].rOffset + peinfo.wSectionNfo[peinfo.Sections - 1].rSize - bw, soFromBeginning);

                            finalize (buff);
                            SetLength(buff    ,4096);
                            desc.Read(buff[0] ,4096);

                            pt := nshieldoutstack(buff, 4091, Magistr_A,length(Magistr_A)-1);
                            if pt <> -1 then
                            begin
                                virname := strnew('Virus.Win32.Magistr.A');
                                ftype   := NSHIELD_ALGOS;
                                exit;
                            end;
                        end else
                        if ((rs >= $7000) and (vs >= $7000) and (((vs and $ff) = $ed))) then  begin

                            bw := $8000;

                            desc.Seek(peinfo.wSectionNfo[peinfo.Sections - 1].rOffset + peinfo.wSectionNfo[peinfo.Sections - 1].rSize - bw, soFromBeginning);

                            finalize (buff);
                            SetLength(buff    ,4096);
                            desc.Read(buff[0] ,4096);

                            pt := nshieldoutstack(buff, 4091, MAGISTR_B,length(MAGISTR_B) - 1);

                            if pt <> -1 then
                            begin
                                virname := strnew('Virus.Win32.Magistr.B');
                                ftype   := NSHIELD_ALGOS;
                                exit;
                            end;
                        end;
                    end;    }
                    (* End of Virus Detection *)
(******************************************************************************)
                end;

                exit;
            end;
        //end;

    finally
        if ftype = NSHIELD_TYPENOTHING then ftype := NSHIELD_TYPEOTHER;
        peinfo.filesize := size;
        finalize(buff);
        result := ftype; 
        desc.free;
    end;
end;

end.
