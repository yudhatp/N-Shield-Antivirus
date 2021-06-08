unit Normalisasi;  

interface
  uses windows, sysutils, EHeader, Strings;


function norm_scanbuff(const root: nshield_engine; const buffer: my_buffer; info: nav_fileinfo; ftype, realoff, length: integer; var virname: pchar): boolean;
function norm_add_suffix(var root: nshield_engine; const virname: pchar; hexsig: pchar; offset: pchar; ftype: dword): boolean;
procedure free_norm(var norm_suffix: nav_normsuffix; var norm_shift: navnorm_shift);
procedure fill_quebytes(b1: char; bytetable: nav_bytesshift);

implementation
    uses
    compare;

procedure fill_quebytes(b1: char; bytetable: nav_bytesshift);
var
    i : integer;
begin
    for i := 0 to 255 do
        bytetable[b1,chr(i)] := true;
end;

function HASH(a,b,c,e: char): dword;
begin
    result := (211 * (byte(a)) + 37 * (byte(b)) + (byte(c)) * (byte(e) + 49));
end;

procedure free_norm_suffix(var suffix: nshield_normpatt);
var
    mem : nshield_normpatt;
begin
    while suffix <> nil do begin
        mem := suffix;
        suffix := suffix^.next;
        StrDispose(mem^.virname);
        finalize(mem^.pattern);
        freemem(mem);
    end;
    suffix := nil
end;

procedure free_norm(var norm_suffix: nav_normsuffix; var norm_shift: navnorm_shift);
var
    i : integer;
    shift : integer;
begin
    for i := 0 to MAX_HASH_SIZE do begin
        shift := norm_shift[i];
        if shift <> -1 then begin
            free_norm_suffix(norm_suffix[i]^);
            freemem(norm_suffix[i]);
            norm_suffix[i] := nil;
        end;
    end;
end;

function norm_add_patt(var root: nshield_normpatt; const virname: pchar; hexsig: my_buffer; offset: pchar; ftype: dword): boolean;
var
    newitem        : nshield_normpatt;
    i              : integer;
    zppos, wppos   : integer;
    zp, wp         : char;
    maxbfs         : integer;
begin
    result := true;
    try
 	      getmem(newitem, sizeof(nav_normpatt));
        zeromemory(NewItem, sizeof(nav_normpatt));
        (* *)
        newitem^.next := root;
        (* *)
        newitem^.virname := strnew(virname);
        (* *)
        newitem^.offset := nshieldpchar2offset(offset);
        (* *)
        setlength(newitem^.pattern, length(hexsig));
        (* *)
        newitem^.ptype := ftype;
        newitem^.pattern := hexsig;
        newitem^.patlen := length(newitem^.pattern)-1;
        (* MAKE Z,W PREFIXES *)
        zppos := newitem^.patlen div 2;
        zp    := newitem^.pattern[zppos];
        (* *)
        wppos := newitem^.patlen;
        wp    := newitem^.pattern[wppos];
        (* *)
        newitem^.zprefix.ppos   := zppos;
        newitem^.zprefix.prefix := zp;
        newitem^.wprefix.ppos   := wppos;
        newitem^.wprefix.prefix := wp;
        (* NEW ITEM *)
        root := newitem;
    except
        result := false;
    end;
end;

function norm_add_suffix(var root: nshield_engine; const virname: pchar; hexsig: pchar; offset: pchar; ftype: dword): boolean;
var
    idx, shift: integer;
    pattern   : my_buffer;
begin
    result := false;
    if not pchar2buffer(pattern,hexsig) then exit;

    inc(root^.sigloaded);

    root^.norm_b1b2[pattern[0],pattern[1]] := true;
    root^.norm_b1b3[pattern[0],pattern[2]] := true;
    root^.norm_b2b3[pattern[1],pattern[2]] := true;
    (* *)
    idx := HASH(pattern[0],pattern[1],pattern[2],pattern[3]);
    shift := root^.norm_shift[idx];

    if shift = -1 then begin
        root^.norm_shift[idx] := idx;
        shift := root^.norm_shift[idx];
        new(root^.norm_suffix[shift]);
        root^.norm_suffix[shift]^ := nil;
    end;
    
    result := norm_add_patt(root^.norm_suffix[shift]^, virname, pattern, offset, ftype);
    pattern := nil;
end;

function norm_scanbuff(const root: nshield_engine; const buffer: my_buffer; info: nav_fileinfo; ftype, realoff, length: integer; var virname: pchar): boolean;
var
    i, j, idx, shift, boff : integer;
    found                  : boolean;
    prefix, zprefix        : char;
    patt                   : nshield_normpatt;
begin
    result := false;
    found := false;
    (* *)
    boff  := length - root^.maxpatlen - MIN_NORM_LEN;
    (* *)
    for i := 0 to length - MIN_NORM_LEN do begin

        if not (root^.norm_b1b2[buffer[i]    ,buffer[i + 1]]) then Continue;
        if not (root^.norm_b2b3[buffer[i + 1],buffer[i + 2]]) then Continue;
        if not (root^.norm_b1b3[buffer[i]    ,buffer[i + 2]]) then Continue;

        idx   := HASH(buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]);
        shift := root^.norm_shift[idx];

        if shift > -1 then begin

            prefix  := buffer[i + MIN_NORM_LEN]; 
            zprefix := buffer[i];
            patt    := root^.norm_suffix[shift]^;

            while (patt <> nil) and (patt^.pattern[MIN_NORM_LEN] <> prefix) do
                  patt := patt^.next;

            while (patt <> nil) do begin
                (* PREFIXES *)
                if buffer[i + patt^.zprefix.ppos] <> patt^.zprefix.prefix then
                begin
                    patt := patt^.next;
                    continue;
                end;

                if buffer[i + patt^.wprefix.ppos] <> patt^.wprefix.prefix then
                begin
                    patt := patt^.next;
                    continue;
                end;
                (* *)
                if patt^.ptype <> 0 then
                    if patt^.ptype <> ftype then begin
                        patt := patt^.next;
                        continue;
                    end;
                    
                if i > boff then
                    if i + patt^.patlen > length then begin
                        patt := patt^.next;
                        continue;
                    end;
                (* *)
                    if patt^.pattern[0] = zprefix then begin

                        for j := patt^.patlen - 1 downto 1 do
                            if buffer[i + j] <> patt^.pattern[j] then
                            begin
                                found := false;
                                break;
                            end else
                                if j = 1 then
                                begin
                                    found := true;
                                    break;
                                end;

                            if found then begin

                                if patt^.offset.otype <> nav_all then
                                    if not validatesign(patt^.offset,realoff + i,info) then begin
                                        patt := patt^.next;
                                        Continue;
                                    end;

                                result := true;
                                virname := patt^.virname;
                                exit;
                            end;
                            
                    end;
                (* *)
                patt := patt^.next;
            end;
        end;
    end; 
end;
(******************************************************************************)
end.
