unit DBkode;

interface
  uses EHeader, windows, sysutils;

function addbadsigs(var engine: nshield_engine; sn: pchar): boolean;
function inbadsigs(engine: nshield_engine; sn: pchar): boolean;
procedure freebadsigs(var root: bad_sigs);

implementation

procedure freebadsigs(var root: bad_sigs);
var
    mem: bad_sigs;
begin
    while root <> nil do begin
        mem := root;
        root := root^.next;
        StrDispose(mem^.signame);
        freemem(mem);
        Pointer(mem) := nil;
    end;
    root := nil;
end;

function addbadsigs(var engine: nshield_engine; sn: pchar): boolean;
var
    newitem: bad_sigs;
begin
    result := false;

    if strlen(sn) = 0 then exit;

    if engine^.badsigs = nil then begin
        new(engine^.badsigs);
        engine^.badsigs^ := nil;
    end;       

    getmem(newitem, sizeof(navbad_sigs));
    zeromemory(newitem, sizeof(navbad_sigs));

    newitem^.next := engine^.badsigs^;

    newitem^.signame := strnew(sn);

    engine^.badsigs^ := newitem;

    result := true;
end;

function inbadsigs(engine: nshield_engine; sn: pchar): boolean;
var
    bad: bad_sigs;
    signm, badnm : string;
begin
    result := false;
    bad := nil;

    if engine^.badsigs = nil then exit;
    
    bad := engine^.badsigs^;
    signm := sn;

    while bad <> nil do begin
        badnm := bad^.signame;
        if signm = badnm then begin
            result := true;
            exit;
        end;
        bad := bad^.next;
    end;
end;

end.
