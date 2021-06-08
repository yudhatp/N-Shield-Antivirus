unit Strings;

interface
  uses windows, sysutils, classes, EHeader;

type
  TSChar = set of char;
  
function pchar2buffer(var buffer: my_buffer; line: string): boolean;
function pchar2mdbuffer(var buffer: nshield_mdbuff; const line: string):boolean;
function strget(const line: string;  fieldno: integer;  delim: char): string;
function strtok(const line: string;  fieldno: integer;  delim: char): string;
function strchr(s: string; c: char) : string;
function strcat(s1, s2: string) : string;
function hex2si(var pattern: nav_pattern; hex: pchar): boolean;
function buffer2str(const buff: my_buffer):string;
function nshieldshortfilename(const LongName: String): String;
function nshieldpchar2offset(const offstr: pchar) : nav_offset;

function strtoken(const line: pointer; fieldno: integer; const delim: char; var fields, linepos: integer): string;

function NShield_str2hex(const str: widestring): widestring;
function hexafile(filename: widestring; spos, count: integer): widestring;

function nshieldhex2int(const S: string): byte;
function nshieldstr2int(const Value: AnsiString) : Integer;
function nshieldlowercase(const S: string): string;

function nshieldoutstack(const haystack: my_buffer; hs: integer; needle: array of char; ns: integer):integer;
function nshieldreadint32(const buff: my_buffer; pos: integer): int64;

procedure str2buffer(const str: string; var buff: my_buffer);
procedure nshieldtrimstr(var str: string);

implementation

function nshieldlowercase(const S: string): string;
asm
        PUSH     ESI
        XCHG     EAX, EDX
        PUSH     EAX
        CALL     System.@LStrAsg
        POP      EAX

        CALL     UniqueString

        PUSH     EAX
        CALL     System.@LStrLen
        POP      ESI

        XCHG     ECX, EAX

        JECXZ    @@exit

@@go:
        LODSB
        {$IFDEF PARANOIA} DB $2C, 'A' {$ELSE} SUB AL, 'A' {$ENDIF}
        {$IFDEF PARANOIA} DB $3C, 26 {$ELSE} CMP AL, 'Z'-'A'+1 {$ENDIF}
        JNB      @@1

        ADD      byte ptr [ESI - 1], 20h
@@1:
        LOOP     @@go
@@exit:
        POP      ESI
end;

function S2Int( S: AnsiChar ): Integer;
asm
        XCHG     EDX, EAX
        XOR      EAX, EAX
        TEST     EDX, EDX
        JZ       @@exit

        XOR      ECX, ECX
        MOV      CL, [EDX]
        INC      EDX
        CMP      CL, '-'
        PUSHFD
        JE       @@0
@@1:    CMP      CL, '+'
        JNE      @@2
@@0:    MOV      CL, [EDX]
        INC      EDX
@@2:    SUB      CL, '0'
        CMP      CL, '9'-'0'
        JA       @@fin
        LEA      EAX, [EAX+EAX*4] //
        LEA      EAX, [ECX+EAX*2] //
        JMP      @@0
@@fin:  POPFD
        JNE      @@exit
        NEG      EAX
@@exit:
end;

function nshieldstr2int(const Value : AnsiString) : Integer;
asm
        CALL     S2Int
end;

function nshieldhex2int(const S: string): byte;
const
  ErrorMessage: string = '';
asm
        PUSH    ESI
        PUSH    EBX
        MOV     ESI,EAX
        TEST    EAX,EAX
        JE      @@err
        MOV     ECX,[EAX-4]
        TEST    ECX,ECX
        JE      @@err
        MOV     EBX,EAX
        XOR     EAX,EAX
@@lp:   MOV     DL,BYTE PTR [EBX]
        SHL     EAX,4
        SUB     DL,$30
        JB      @@err
        CMP     DL,$09
        JBE     @@ct
        SUB     DL,$11
        JB      @@err
        CMP     DL,$05
        JBE     @@pt
        SUB     DL,$20
        JB      @@err
        CMP     DL,$05
        JA      @@err
@@pt:   ADD     DL,$0A
@@ct:   OR      AL,DL
        INC     EBX
        DEC     ECX
        JNE     @@lp
        POP     EBX
        POP     ESI
        RET
@@err:  MOV     EAX,ErrorMessage
        MOV     EDX,ESI
        POP     EBX
        POP     ESI
end;

function nshieldposchars(const ch  : TSChar;
                  const str : string;
                  fromPos   : cardinal = 1;
                  toPos     : cardinal = maxInt) : integer;
var c1 : cardinal;
begin
    result := 0;
    if str <> '' then begin
        c1 := Length(str);
        if fromPos > toPos then begin
            if toPos <= c1 then begin
                if fromPos > c1 then fromPos := c1;
                for c1 := fromPos downto toPos do
                    if str[c1] in ch then begin
                        result := c1;
                        break;
                    end;
            end;
        end else
            if fromPos <= c1 then begin
                if toPos > c1 then toPos := c1;
                for c1 := fromPos to toPos do
                    if str[c1] in ch then begin
                        result := c1;
                        break;
                    end;
            end;
    end;
end;

procedure nshieldkeep(var str : string;
               index   : cardinal;
               count   : cardinal = maxInt);
begin
    str := Copy(str, index, count);
end; 
(******************************************************************************)
procedure nshieldtrimstr(var str: string);
var c1, c2 : cardinal;
begin
    c1 := nshieldposchars([#33..#255], str);
    if c1 <> 0 then begin
        c2 := nshieldposchars([#33..#255], str, maxInt, 1);
        nshieldkeep(str, c1, c2 - c1 + 1);
    end else str := '';
end;
(******************************************************************************)
function nshieldshortfilename(const LongName: String): String;
var
    i: integer;
begin
    SetLength(Result,Length(LongName));
    i := GetShortPathName(pChar(LongName),pChar(Result),Length(Result));
    if i > Length(Result)  then begin
       SetLength(Result,i);
       i := GetShortPathName(pChar(LongName),pChar(Result),Length(Result));
    end;
    SetLength(Result,i);
end;

function nshieldreadint32(const buff: my_buffer; pos: integer): int64;
var
    ret: int64;
begin
    ret := byte(buff[pos]) and $ff;
    ret := ret or ((byte(buff[pos + 1]) and $ff) shl 8);
    ret := ret or ((byte(buff[pos + 2]) and $ff) shl 16);
    ret := ret or ((byte(buff[pos + 3]) and $ff) shl 24);
  	result := ret;
end;

function nshieldoutstack(const haystack: my_buffer; hs: integer; needle: array of char; ns: integer):integer;
var
    i,j  : integer;
begin
    if hs < ns then begin
        Result := -1;
        exit;
    end;
    (* *)
    if haystack = needle then begin
  	    result := 0;
        exit;
    end;
    (* *)
    for i := 0 to hs do
        if haystack[i] = needle[0] then
            for j := 1 to ns do
                if haystack[i+j] <> needle[j] then break else
                if j = ns then begin
                    result := i;
                    exit;
                end;
    (* *)
    Result := -1;
end;

function hexafile(filename: widestring; spos, count: integer): widestring stdcall;
var
    i: integer;
    fsize: int64;
    ret: string;
    buf: my_buffer;
    desc: TFileStream;
begin
    result := '';
    if not FileExists(filename) then exit;
    try
        desc := TFileStream.Create(filename, fmShareDenyNone);

        if count = -1 then
            setlength(buf, desc.size)
            else
            setlength(buf, count+1);

        desc.Seek(spos, soFromBeginning);
        if count = -1 then
            desc.Read(buf[0], desc.Size - spos)
            else
            desc.Read(buf[0], count);

        for i := 0 to length(buf)-2 do
            result := result + nshieldlowercase(inttohex(byte(buf[i]),2));

        desc.Free;
        finalize(buf);
    except
        result := '';
    end;
end;

function NShield_str2hex(const str: widestring): widestring stdcall;
var
    i: integer;
    return: string;
begin
    return := '';
    for i := 1 to length(str) do
        return := return + IntToHex(byte(str[i]),2);

    result := nshieldlowercase(return);
    return := '';
end;

function buffer2str(const buff: my_buffer):string;
var
    i: integer;
begin
    Result := '';
    for i := 0 to length(buff)-1 do
        result := result + buff[i];
end;

procedure str2buffer(const str: string; var buff: my_buffer);
var
    i: integer;
begin
    finalize(buff);
    setlength(buff, length(str));
    for i := 1 to length(str)-1 do
        buff[i-1] := str[i];
end;

function strget(const line: string;  fieldno: integer;  delim: char): string;
var
    i: integer;
begin
    result  := '';
    for i := 1 to fieldno do begin
        if line[i] = delim then begin
            result := pchar(result + '');
            break;
        end else
            result := pchar(result + line[i]);
    end;
end;

function strtok(const line: string; fieldno: integer; delim: char): string;
var
    counter: integer;
    i: integer;
begin
    result  := '';
    counter := 0;
    for i := 1 to length(line) do begin
        if line[i] = delim then begin
            asm inc counter end;
            if counter > fieldno then break else Continue;
        end;
        if fieldno = counter then
            result := result + line[i];
    end;
end;

function strtoken(const line: pointer; fieldno: integer; const delim: char; var fields, linepos: integer): string;
var
    counter, cn: integer;
    cur: char;
    i, ln: integer;
begin
    result  := '';
    counter := fields;
    cn      := 0;
    ln      := length(string(line^));

    for i := linepos to ln do begin
        cur := string(line^)[i];
        if cur = delim then begin
            inc(counter);
            if counter > fieldno then begin
                Result := copy(string(line^), linepos, cn);

                linepos := i;
                fields  := counter - 1;
                exit;
            end else begin
                linepos := i + 1;
                Continue;
            end;
        end;
        if fieldno = counter then
            asm inc cn end;
           //result := result + cur;
    end;
    Result := copy(string(line^), linepos, cn);
    linepos := i + 1;
    fields  := counter - 1;
end;

function strchr(s: string; c: char) : string;
var
    ps: integer;
begin
    result := '';
    ps := pos(c,s);
    if ps = 0 then exit;
    result := copy(s,ps + 1,length(s));
end;

function strcat(s1, s2: string) : string;
begin
    Result := s1 + s2;
end;

function hex2si(var pattern: nav_pattern; hex: pchar): boolean;
var
    i,j: integer;
    cst: string[2];
begin
    result := true;
    setlength(pattern, strlen(hex) div 2);
    
    for i := 0 to (strlen(hex) div 2)-1 do begin
        cst := copy(hex,(i*2)+1,2);
        if cst = '@@' then
            j := NSHIELD_ALT else
        if cst = '??' then
            j := NSHIELD_IGN else
            begin
                if not (cst[1] in RIGHTHEX) or
                   not (cst[2] in RIGHTHEX) then begin
                       result := false;
                       finalize(pattern);
                       exit;
                   end;
                j := nshieldhex2int(cst);
            end;
        pattern[i] := j;
    end;
end;

function pchar2buffer(var buffer: my_buffer; line: string): boolean;
var
    i, ln: integer;
    c: char;
begin
    result := true;

    ln := length(line);

    if (ln = 0) or (ln div 2 < MIN_NORM_LEN) then begin
        Result := false;
        exit;
    end;

    buffer := nil;
    setlength(buffer,ln div 2);

    for i := 1 to (ln div 2) do begin
        try
            buffer[i-1] := chr(nshieldhex2int(line[(i*2)-1] + line[(i*2)]));
        except
            result := false;
            exit;
        end;
    end;
end;  

function pchar2mdbuffer(var buffer: nshield_mdbuff; const line: string):boolean;
var
    i, ln: integer;
    c: char;
begin
    Result := true;

    ln := length(line);

    if (ln = 0) or (ln div 2 < MD_HASH_LEN) then begin
        Result := false;
        exit;
    end;

    for i := 1 to 16 do begin
        try
            buffer[i-1] := chr(nshieldhex2int(line[(i*2)-1] + line[(i*2)]));
        except
            result := false;
            exit;
        end;
    end;
end;       

function nshieldpchar2offset(const offstr: pchar): nav_offset;
var
    i: integer;
    n,s : pchar;
begin

    result.otype := nav_all;
    result.osect := 0;
    result.offcn := 0;
    (* *)
    case offstr[0] of
        '*' : begin
                  exit;
              end;
        'S' : begin
              (* Section Last *)
                  if offstr[1] = 'L' then begin
                      result.otype := nav_lastsection;
                      result.osect := 0;
                      (* *)
                      if pos('-',offstr) <> 0 then begin
                          n := pchar(strtok(offstr,1,'-'));
                          result.offcn := 0 - nshieldstr2int(n);
                      end else
                      if pos('+',offstr) <> 0 then begin
                          n := pchar(strtok(offstr,1,'+'));
                          result.offcn := nshieldstr2int(n);
                      end;
                      (* *)
                      exit;
                  end;
              (* Section Num *)
                  result.otype := nav_section;
                  s := '';
                  n := '0';
                  for i := 1 to strlen(offstr) do
                      if (offstr[i] <> '-') and (offstr[i] <> '+') then
                          s := pchar(s + offstr[i])
                      else
                          break;
                  (* *)
                  result.osect := nshieldstr2int(s);
                  (* *)
                  if pos('-',offstr) <> 0 then begin
                      n := pchar(strtok(offstr,1,'-'));
                      result.offcn := 0 - nshieldstr2int(n);
                  end else
                  if pos('+',offstr) <> 0 then begin
                      n := pchar(strtok(offstr,1,'+'));
                      result.offcn := nshieldstr2int(n);
                  end;
              (* *)
              end;
        'E' : begin
              (* *)
                  case offstr[1] of
                      'P' : begin
                                result.otype := nav_entrypoint;
                                if pos('-',offstr) <> 0 then begin
                                    n := pchar(strtok(offstr,1,'-'));
                                    result.offcn := 0 - nshieldstr2int(n);
                                end else
                                if pos('+',offstr) <> 0 then begin
                                    n := pchar(strtok(offstr,1,'+'));
                                    result.offcn := nshieldstr2int(n);
                                end;
                            end;
                      'O' : begin
                                result.otype := nav_eof;
                                n := pchar(strtok(offstr,1,'-'));
                                result.offcn := 0 - nshieldstr2int(n);
                            end;
                  end;
              (* *)
              end;
        else begin
            result.otype := nav_stable;
            result.offcn := nshieldstr2int(offstr);
        end;
    end;

end;
(******************************************************************************)

end.
