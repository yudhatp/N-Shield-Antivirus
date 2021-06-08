{
=====================================
N-Shield Virus Scanner Engine
25 Agustus 2013
Unit white_sig
untuk list white list/white signature
=====================================
}
unit WhiteList;

interface
  uses Eheader, Strings, windows, sysutils;

function inwhitesigs(engine: nshield_engine; mdhash: nshield_mdbuff; size: integer; var wn: pchar): boolean;
function addwhitesigs(var engine: nshield_engine; wn: pchar; mdhash: pchar; size: integer): boolean;
function nshieldfilebersih(engine: nshield_engine; mdhash: pchar; size: integer; var whitename: pchar): boolean;
procedure freewhitesigs(var root: white_sigs);

implementation

//==================================================
procedure freewhitesigs(var root: white_sigs);
var
    mem: white_sigs;
begin
    while root <> nil do begin
        mem := root;
        root := root^.next;
        finalize(mem^.mdhash);
        StrDispose(mem^.whitename);
        freemem(mem);
        Pointer(mem) := nil;
    end;
    root := nil;
end;

//========================================================================================
function addwhitesigs(var engine: nshield_engine; wn: pchar; mdhash: pchar; size: integer): boolean;
var
    newitem: white_sigs;
    pattern: nshield_mdbuff;
begin
    result := false;

    if strlen(wn) = 0 then exit;

    if engine^.whitesigs = nil then begin
        new(engine^.whitesigs);
        engine^.whitesigs^ := nil;
    end;

    getmem(newitem, sizeof(nav_whitesigs));
    zeromemory(newitem, sizeof(nav_whitesigs));


    if not pchar2mdbuffer(pattern, mdhash) then begin
        freemem(newitem);
        exit;
    end;

    newitem^.size := size;
    newitem^.mdhash := pattern;

    newitem^.whitename := strnew(wn);

    newitem^.next := engine^.whitesigs^;
    engine^.whitesigs^ := newitem;

    result := true;
end;

//====================================================================================================
function inwhitesigs(engine: nshield_engine; mdhash: nshield_mdbuff; size: integer; var wn: pchar): boolean;
var
    white: white_sigs;
begin
    result := false;
    white := nil;

    if engine^.whitesigs = nil then exit;

    white := engine^.whitesigs^;

    while white <> nil do begin
        if size = white^.size then
            if mdhash = white^.mdhash then begin
                wn := white^.whitename;
                result := true;
                exit;
            end;
        white := white^.next;
    end;
end;

//===============================================================================================================
function nshieldfilebersih(engine: nshield_engine; mdhash: pchar; size: integer; var whitename: pchar): boolean stdcall;
var
    hash: nshield_mdbuff;
begin
    result := false;
    whitename := '';
    if not pchar2mdbuffer(hash, mdhash) then exit;

    result := inwhitesigs(engine, hash, size, whitename);
end;

end.
