unit ntech;   

interface
  uses Eheader, Strings, windows, sysutils, zlib, classes;

function addforcesigs(var engine: nshield_engine; pattern: nshield_mdbuff; size: integer): boolean;
function inforcesigs(engine: nshield_engine; mdhash: nshield_mdbuff; size: integer): boolean;
procedure nshieldfreeforce(var root: nshieldforcesigs);

implementation

procedure nshieldfreeforce(var root: nshieldforcesigs);
var
    mem: nshieldforcesigs;
begin
    while root <> nil do begin
        mem := root;
        root := root^.next;
        finalize(mem^.mdhash);
        freemem(mem);
        Pointer(mem) := nil;
    end;
    root := nil;
end;

function addforcesigs(var engine: nshield_engine; pattern: nshield_mdbuff; size: integer): boolean;
var
    newitem: nshieldforcesigs;
begin
    result := false;

    if engine^.navforce = nil then begin
        new(engine^.navforce);
        engine^.navforce^ := nil;
    end;

    getmem(newitem, sizeof(nav_forcesigs));
    zeromemory(newitem, sizeof(nav_forcesigs));

    newitem^.size := size;
    newitem^.mdhash := pattern;

    newitem^.next := engine^.navforce^;
    engine^.navforce^ := newitem;

    result := true;
end;

function inforcesigs(engine: nshield_engine; mdhash: nshield_mdbuff; size: integer): boolean;
var
    force: nshieldforcesigs;
begin
    result := false;
    force := nil;

    if engine^.navforce = nil then exit;

    force := engine^.navforce^;

    while force <> nil do begin
        if size = force^.size then
            if mdhash = force^.mdhash then begin
                result := true;
                exit;
            end;
        force := force^.next;
    end;
end;

end.
