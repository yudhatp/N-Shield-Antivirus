unit Hashing;     

interface
  uses windows, sysutils, EHeader, Strings;

procedure free_hash(var hash_shift: navnorm_shift; var hash_suffix: navhash_suffix);
procedure hash_add_suffix(var root: nshield_engine; var md_suffix: navhash_suffix; var md_shift: navnorm_shift; const virname: pchar; mdsig: pchar; mdsize: integer);
function hash_scanbuff(const md_suffix: navhash_suffix; const md_shift: navnorm_shift; buffer: nshield_mdbuff; bufsize: integer; var virname: pchar):boolean;

implementation
    uses
    compare;
(******************************************************************************)
{function HASH(a,b,c: char): dword;
begin
    result := (211 * (byte(a)) + 37 * (byte(b)) + (byte(c)));
end; }
function HASH(a,b,c,e: char): dword;
begin
        result := (211 * (byte(a)) + 37 * (byte(b)) + (byte(c)) * (byte(e) + 49));
end;

procedure free_hash_suffix(var suffix: nshield_hashpatt);
var
    mem : nshield_hashpatt;
begin
    while suffix <> nil do begin
        mem := suffix;
        suffix := suffix^.next;
        StrDispose(mem^.virname);
        freemem(mem);
    end;
    suffix := nil
end;

procedure free_hash(var hash_shift: navnorm_shift; var hash_suffix: navhash_suffix);
var
    i : integer;
    shift : integer;
begin
    for i := 0 to MAX_HASH_SIZE do begin
        shift := hash_shift[i];
        if shift <> -1 then begin
            free_hash_suffix(hash_suffix[i]^);
            freemem(hash_suffix[i]);
            hash_suffix[i] := nil;
        end;
    end;
end;

procedure hash_add_patt(var root: nshield_hashpatt; const virname: pchar; pattern: nshield_mdbuff; size: integer);
var
    newitem : nshield_hashpatt;
begin
 	  GetMem(newitem, SizeOf(nav_hashpatt));
    ZeroMemory(NewItem, SizeOf(nav_hashpatt));
    newitem^.next    := root;

    newitem^.virname := strnew(virname);

    newitem^.pattern := pattern;
    newitem^.mdsize  := size;
    root             := newitem;
end;

procedure hash_add_suffix(var root: nshield_engine; var md_suffix: navhash_suffix; var md_shift: navnorm_shift; const virname: pchar; mdsig: pchar; mdsize: integer);
var
    idx, shift: integer;
    pattern   : nshield_mdbuff;
begin
    if not pchar2mdbuffer(pattern,mdsig) then begin
        exit;
    end;

    inc(root^.sigloaded);

    idx   := HASH(pattern[0],pattern[1],pattern[2], pattern[3]);
    shift := md_shift[idx];

    if shift = -1 then begin
        md_shift[idx] := idx;
        shift := md_shift[idx];
        new(md_suffix[shift]);
        md_suffix[shift]^ := nil;
    end;

    hash_add_patt(md_suffix[shift]^, virname, pattern, mdsize);
end;

function hash_scanbuff(const md_suffix: navhash_suffix; const md_shift: navnorm_shift; buffer: nshield_mdbuff; bufsize: integer; var virname: pchar):boolean;
var
    j, idx, shift, found : integer;
    prefix : char;
    patt : nshield_hashpatt;
begin
    result := false;
    idx   := HASH(buffer[0], buffer[1], buffer[2], buffer[3]);
    shift := md_shift[idx];

    if shift > -1 then begin

        prefix := buffer[0];
        patt   := nil;
        patt   := md_suffix[shift]^;

        while (patt <> nil) and (patt^.pattern[0] <> prefix) do
            patt := patt^.next;

        while (patt <> nil) do begin
            if patt^.mdsize = bufsize then
                if patt^.pattern[0] = prefix then begin
                    for j := 1 to 15 do
                        if buffer[j] <> patt^.pattern[j] then
                        begin
                            found := -1;
                            break;
                        end else
                        if j = 15 then begin
                            found := 0;
                            result := true;
                            virname := patt^.virname;
                            exit;
                        end;
                end;
            patt := patt^.next;
        end;
    end;
end;

end.
