{
=====================================
N-Shield Virus Scanner Engine
25 Agustus 2013
Unit wild_matcher
untuk compare pattern dengan wildcard
=====================================
}
unit PatternMatch;  

interface
  uses windows, sysutils, EHeader, Strings;

procedure free_wild(var wild_node: nav_wild_nodelist);

function nshieldwildscanbuff(root: nshield_engine; buffer: my_buffer; info: nav_fileinfo; ftype: dword; var virname: pchar): boolean;
function wild_scanbuff(root: nshield_engine; buffer: my_buffer; var partcnt, partoff: nav_acclc; info: nav_fileinfo; ftype, realoff, len: integer; var virname: pchar): boolean;
function wild_addsig(var root: nshield_engine; virname, hexsig: pchar; sigid, parts, partno : integer; ptype, mindist, maxdist : integer; offset : pchar): boolean;

implementation
    uses
    compare, Normalisasi;

//==================================================
procedure free_wild_node(var suffix: nshield_wildpatt);
var
    mem : nshield_wildpatt;
    i: integer;
begin
    while suffix <> nil do begin
        mem := suffix;
        suffix := suffix^.next;
        StrDispose(mem^.virname);
        finalize(mem^.pattern);
        for i := 0 to length(mem^.altc)-1 do
            finalize(mem^.altc[i]);

        finalize(mem^.altc);
        freemem(mem);
    end;
    suffix := nil
end;

//===================================================
procedure free_wild(var wild_node: nav_wild_nodelist);
var
    i,j   : integer;
begin
    for i := 0 to 255 do
        for j := 0 to 255 do begin
            if wild_node[chr(i),chr(j)] <> nil then
            begin
                free_wild_node(wild_node[chr(i),chr(j)]^);
                freemem(wild_node[chr(i),chr(j)]);
                pointer(wild_node[chr(i),chr(j)]) := nil;
            end;
        end;
    finalize(wild_node);
end;

//=========================================================================================================
function wild_addpatt(var root: nshield_engine; pattern: nav_wildpatt; virname: pchar; offset: pchar): boolean;
var
    i, zppos, wppos : integer;
    zp, wp          : char;
    newitem         : nshield_wildpatt;
    sigof           : integer;
begin
    result := true;
    sigof := -1;
    (* MAKE REAL SIG OFFSET *)
    for i := 0 to pattern.length do
        if (pattern.pattern[i] >= 0) and (pattern.pattern[i+1] >= 0) then begin
            sigof := i;
            break;
        end;

    if sigof = -1 then begin
        result := false;
        exit;
    end;
    (* MAKE Z,W PREFIX *)
    zppos := -1;
    wppos := -1;
    if pattern.length > 1 then begin
        for i := 0 to pattern.length do
            if (i <> sigof) and (pattern.pattern[i] >= 0) then
            begin
                zppos := i - sigof;
                zp    := chr(pattern.pattern[i]);
            end;

        for i := pattern.length downto 0 do
            if (i <> sigof + 1) and (pattern.pattern[i] >= 0) then
            begin
                wppos := i - sigof;
                wp    := chr(pattern.pattern[i]);
            end;
    end else begin
        zppos := sigof;
        zp    := chr(pattern.pattern[sigof]);
        wppos := sigof + 1;
        wp    := chr(pattern.pattern[sigof + 1]);
    end;
    (* *)
    getmem(newitem, sizeof(nav_wildpatt));
    zeromemory(newitem, sizeof(nav_wildpatt));

    if root^.wild_node[chr(pattern.pattern[sigof]),chr(pattern.pattern[sigof+1])] = nil then begin
        new(root^.wild_node[chr(pattern.pattern[sigof]),chr(pattern.pattern[sigof+1])]);
        root^.wild_node[chr(pattern.pattern[sigof]),chr(pattern.pattern[sigof+1])]^ := nil;
    end;
    (* *)
    newitem^.pattern := pattern.pattern;
    newitem^.altc    := pattern.altc;

    newitem^.length  := pattern.length;
    newitem^.mindist := pattern.mindist;
    newitem^.maxdist := pattern.maxdist;
    newitem^.ptype   := pattern.ptype;
    newitem^.sigid   := pattern.sigid;
    newitem^.parts   := pattern.parts;
    newitem^.partno  := pattern.partno;

    newitem^.sigof   := sigof;
    (* PREFIX *)
    newitem^.zprefix.ppos   := zppos;
    newitem^.zprefix.prefix := zp;
    newitem^.wprefix.ppos   := wppos;
    newitem^.wprefix.prefix := wp;
    (* *)
    if (pattern.sigid = 0) or (pattern.partno = pattern.parts) then begin
        newitem^.virname := strnew(virname);
        inc(root^.sigloaded);
    end;
    (* *)
    newitem^.offset := nshieldpchar2offset(offset);

    newitem^.next := root^.wild_node[chr(pattern.pattern[sigof]),chr(pattern.pattern[sigof+1])]^;
    root^.wild_node[chr(pattern.pattern[sigof]),chr(pattern.pattern[sigof+1])]^ := newitem;
end;

//====================================================================================================
function wild_findmatch(const buffer: nav_buffer; position: integer; pattern: nshield_wildpatt): boolean;
var
    i, j, alt, spos, error: integer;
begin

    result := false;
    alt    := 0;
    error  := 0;
    spos   := position - pattern^.sigof;
    
    for i := 0 to pattern^.length do begin
        case pattern^.pattern[i] of
            NSHIELD_IGN : Continue;
            NSHIELD_ALT : for j := 0 to length(pattern^.altc[alt]) - 1 do
                         if pattern^.altc[alt][j] = buffer^[spos + i] then begin
                             error := 0;
                             asm inc alt end;
                             break;
                         end else error := 1;
            (* BYTE *)
            else begin
                if error = 1 then exit;
                if chr(pattern^.pattern[i]) <> buffer^[spos + i] then exit;
            end;
        end;
    end;

    result := true;
end;

//=========================================================================================================================================================================
function wild_scanbuff(root: nshield_engine; buffer: my_buffer; var partcnt, partoff: nav_acclc; info: nav_fileinfo; ftype, realoff, len: integer; var virname: pchar): boolean;
var
    i,j,dist,err, boff : integer;
    pt, trans : nshield_wildpatt;
    fn : boolean;
begin
    result := false;
    (* *)
    boff := len - root^.maxpatlen - MIN_NORM_LEN;
    (* *)
    for i := 0 to len - root^.minpatlen do begin

        pt := nil;
        
        if root^.wild_node[buffer[i] , buffer[i+1]] <> nil then
            pt := root^.wild_node[buffer[i] , buffer[i+1]]^
            else
            continue;
        (* *)
        while (pt <> nil) and (pt^.wprefix.prefix <> buffer[i + pt^.wprefix.ppos]) do
           pt := pt^.next;

        while (pt <> nil) and (pt^.zprefix.prefix <> buffer[i + pt^.zprefix.ppos]) do
           pt := pt^.next;
        (* *)
        while pt <> nil do begin
            (* *)
            if pt^.length > 1 then begin
                if pt^.wprefix.prefix <> buffer[i + pt^.wprefix.ppos] then begin
                    pt := pt^.next;
                    Continue;
                end else
                if pt^.zprefix.prefix <> buffer[i + pt^.zprefix.ppos] then begin
                    pt := pt^.next;
                    Continue;
                end;
            end;
            (* FIXME *)
            if pt^.partno > 1 then
                if partcnt[pt^.sigid] = 0 then begin
                    pt := pt^.next;
                    Continue;
                end;
            (* *)
            if pt^.ptype <> 0 then
                if pt^.ptype <> ftype then begin
                    pt := pt^.next;
                    Continue;
                end;

            if i > boff then
                if i + pt^.length > len then begin
                    pt := pt^.next;
                    continue;
                end;
            (* *)
            if pt^.length = 1 then
                fn := true else
                fn := wild_findmatch(@buffer,i,pt);
            (* *)
            if fn then begin

                if pt^.partno = 1 then
                    if pt^.offset.otype <> nav_all then
                        if not validatesign(pt^.offset, realoff + i - pt^.sigof, info) then begin
                            pt := pt^.next;
                            Continue;
                        end;

                if pt^.sigid <> 0 then begin

                    if (pt^.mindist = -1) and (pt^.maxdist = -1) and (pt^.partno >= partcnt[pt^.sigid]) then begin
                        partoff[pt^.sigid] := realoff + i + pt^.length;
                        partcnt[pt^.sigid] := pt^.partno;
                        pt := pt^.next;
                        Continue;
                    end
                    else                

                        if partcnt[pt^.sigid] + 1 = pt^.partno then begin

                            dist := 1;

                            if (pt^.maxdist <> 0) then
                                if (realoff + i - partoff[pt^.sigid] > pt^.maxdist) then
                                    dist := 0;

              	    		    if (dist <> 0) and (pt^.mindist <> 0) then
                           			if (realoff + i - partoff[pt^.sigid] < pt^.mindist) then
				                            dist := 0;

                            if (dist <> 0) then begin

                                inc(partcnt[pt^.sigid]);

                                if partcnt[pt^.sigid] = pt^.parts then begin
                                    result := true;
                                    virname := pt^.virname;
                                    exit;
                                end;

                                partoff[pt^.sigid] := realoff + i + pt^.length;

                            end;

                        end;

                end else begin
                    result := true;
                    virname := pt^.virname;
                    exit;
                end;
            end;
            pt := pt^.next;
        end;
    end;
end;

//=============================================================================================================================================================
function wild_addsig(var root: nshield_engine; virname, hexsig: pchar; sigid, parts, partno : integer; ptype, mindist, maxdist : integer; offset : pchar): boolean;
var
  	snew : nav_wildpatt;
	  virlen, ret, i, j, error, altpt, altcn, len : integer;
    pt, hex, hexcpy, hexsnew, start, h: pchar;
    c : char;
begin
    error := 0; altpt := 0; result := true;

    snew.sigof   := 0;
    snew.mindist := mindist;
    snew.maxdist := maxdist;
    snew.ptype   := ptype;
    snew.sigid   := sigid;
    snew.partno  := partno;
    snew.parts   := parts;

    if pos(')',hexsig) <> 0 then begin
        len := strlen(hexsig);

        for i := 0 to len do
            if (hexsig[i] = ')') then
                inc(altpt);
        inc(altpt);
    
        setlength(snew.altc, altpt);

        hexcpy := hexsig;
        pt     := hexsig;
        start  := hexsig;

        for i := 0 to altpt do begin

            pt := '';
            if i <> altpt then
                for j := 0 to (strlen(start)) do
                    if start[j] = '(' then begin
                        pt := start + j + 1;
                        start := pchar(strget(pchar(start), j, '{'));
                        break;
                    end;

            hexsnew := pchar(strcat(hexsnew,start));
            if strlen(pt) <> 0 then
                hexsnew := pchar(strcat(hexsnew,'@@'));

            start := pt;
            pt    := pchar(copy(pt,1,pos(')',pt)-1));
            start := pchar(copy(start,strlen(pt)+2,strlen(start)));

            if i = altpt then break;

            altcn := 0;
            for j := 0 to strlen(pt) do
                if (pt[j] = '|') then
                    inc(altcn);

            for j := 0 to altcn-1 do begin
                h := pchar(strtok(pt,j,'|'));
                setlength(snew.altc[i],j+1);
                if not (h[0] in RIGHTHEX) and not (h[1] in RIGHTHEX) then begin
                    result := false;
                    exit;
                end;
                snew.altc[i][j] := chr(nshieldhex2int(h));
            end;
        end;
    end else begin
        hexsnew := hexsig;
    end;

    if not hex2si(snew.pattern, hexsnew) then begin
        result := false;
        exit;
    end;

    snew.length := length(snew.pattern)-1;
    
    if root^.minpatlen > snew.length then
        root^.minpatlen := snew.length;
    if root^.maxpatlen < snew.length then
        root^.maxpatlen := snew.length;

    wild_addpatt(root,snew,virname,offset);
end;

//===========================================================================================================================
function nshieldwildscanbuff(root: nshield_engine; buffer: my_buffer; info: nav_fileinfo; ftype: dword; var virname: pchar): boolean;
var
    partcnt, partoff: nav_acclc;
    i : integer;
begin
    setlength(partcnt, root^.wild_partsigs+1);
    setlength(partoff, root^.wild_partsigs+1);
    
    try

        for i := 0 to root^.wild_partsigs do begin
            partcnt[i] := 0;
            partoff[i] := 0;
        end;

        result := wild_scanbuff(root, buffer, partcnt, partoff, info, ftype, 0, length(buffer)-1, virname);

    finally
        finalize(partcnt);
        finalize(partoff);
    end;
end;

end.
