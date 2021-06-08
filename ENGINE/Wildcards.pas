{$B-,H+,X+,J-} //Essential directives

unit Wildcards;

interface

uses
  Windows, SysUtils, Classes;

function PatternMatching(const FileName : string;
                         SearchPattern : String;
                         Offset : Longint = -1;
                         BufLength : Integer = -1) : Integer;
function PatternMatchingStr(const SourceBuffer, SearchPatternInHexStr : ansistring; Offset : Integer = -1; BufferLength : Integer = -1) : Integer;
function DumpFileToString(const FileName: string; Offset : Longint = -1; const StrLength : Integer = -1): AnsiString;

implementation

type
  TMask = array[0..31] of Byte; //generic bit mapped character table

var
  L1, L2, R1, R2 : Integer;
  AlphaT, AlphaNumT : TMask;
  RevCase : array [0..255] of Char; //character conversion tables

procedure MsgOk(pesan : string);
begin
  MessageBox(0, PChar(Pesan), 'Info', MB_APPLMODAL + MB_TOPMOST);
end;

function StrToHexStr(a : string): string;
var
  i : integer;
  s: string;
begin
  for i := 1 to Length(a) do
    s := s + inttohex(ord(a[i]), 2);
  Result := s;
end;

function DumpFileToString(const FileName: string; Offset : Longint = -1; const StrLength : Integer = -1): AnsiString;
var
  fs: TFileStream;
  Len: Integer;
begin
  Result := '';
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    if FS = nil then exit;
    //abcdefghijklmnopqrstuvwxyz

    if StrLength = -1 then
      Len := fs.Size
    else if StrLength = 0 then
      Exit
    else if StrLength > 0 then
      Len := StrLength;

    if Offset = -1 then
      Offset := 0;

    if (Offset + Len) > FS.Size then
    begin
      //raise Exception.Create(Format('Offset(%d) + Length (%d) = %d melebihi ukuran Stream.Size (%d)!', [Offset, Len, (Offset + Len), FS.Size]));
      Len := fs.Size - Offset; //Sesuaikan Len, karena Offset defined! Misal Offset mulai dari 10 sementara panjang 100, jadi Len = 100 - 10 = 90
    end;

    //ShowMessage(IntToStr(Offset));
    //ShowMessage(IntToStr(Len));

    SetLength(Result, Len);
    try
      fs.Seek(Offset, soFromBeginning);
      fs.ReadBuffer(Result[1], Len);
    except
      on E: EReadError do
      begin
        Result := '';
        raise Exception.Create('FileToString EReadError: ' + FileName);
      end;
    end;
  finally
    fs.Free;
  end;
end;

function RChar(const Source:Char):Char;
  {Reverse the case (lower to upper or upper to lower) of a single character
   using user-defined table.}
begin
  Result:=RevCase[Ord(Source)];
end;

procedure _TstBit;
asm
  Push  EDX
  Push  EAX
  And   EAX,255
  Mov   EDX,EAX
  And   EDX,7           //bit index
  Shr   EAX,3           //byte index
  Mov   AL,[EBX+EAX]    //get byte
  Bt    EAX,EDX         //test the bit
  Pop   EAX
  Pop   EDX
end;


{Forward scan from Start looking for a match of Search string containing
 wildcards:

   '*' = match any string (including null string)
   '?' = match any single character
   '#' = match any numeric character (0..9)
   '@' = match any alpha character (a..z, A..Z)
   '$' = match any alphanumeric character
   '~' = match any non-alphanumeric, non-space char.
  else = match given character only

 For case insensitive scan, use negative Start.

 Returns:  Minimum matching length, Start = Match location.  If no match,
           Result = 0 AND Start = 0. To continue a search, manually adjust
           Start beyond the returned match.}

function IsMatchEx(const Source, Search:AnsiString; var Start:integer) : Integer;
asm
  Push  EBX              //save the important stuff
  Push  ESI
  Push  EDI
  Push  EBP

  Mov   R1,ECX           //save Start address
  Or    EAX,EAX          //zero source ?
  Jz    @NotFound
  Or    EDX,EDX          //zero search ?
  Jz    @NotFound

  Mov   ESI,EAX          //source address
  Mov   L1,EAX           //save it in L1
  Mov   EDI,EDX          //search address
  Mov   ECX,[ECX]        //get start value
  Or    ECX,ECX          //case insensitive ?
  Jns   @L0              //no, then skip
  Neg   ECX              //absolute value of ECX
  Mov   EAX,-1           //set case flag
@L0:
  Dec   ECX              //zero based start position
  Js    @NotFound        //abort if less than zero

  Mov   EDX,[ESI-4]      //source length
  Or    EDX,EDX
  Jz    @NotFound        //abort on null string
  Sub   EDX,ECX          //consider only remaining of source
  Jbe   @NotFound        //abort if source is too short
  Add   ESI,ECX          //start at the given offset

  Mov   ECX,[EDI-4]      //search length
  Or    ECX,ECX
  Jz    @NotFound        //abort on null string
  Mov   L2,ECX           //save it in L2
  Mov   ECX,EDX          //source length in ECX
  Xor   EBX,EBX          //source offset
  Xor   EDX,EDX          //search offset
  Xor   EBP,EBP
  Mov   R2,EDX           //zero our anchor
@Next:
  Cmp   EDX,L2           //end of search ?
  Jz    @Found           //yes, we found it!

  Mov   AH,[EDI+EDX]     //get next character from search
  Inc   EDX              //next offset

  Cmp   AH,42            //wildcard '*'
  Jnz   @L1              //no, then skip
  Mov   R2,EDX           //drop anchor here
  Mov   EBP,EBX
  Jmp   @Next            //get next character

@L1:
  Cmp   EBX,ECX          //end of source ?
  Ja    @NotFound        //yes, then time to go

  Mov   AL,[ESI+EBX]     //get next character from source
  Inc   EBX              //next offset

  Cmp   AH,63            //wildcard '?'
  Jz    @Next            //yes, then check next char.
@L3:
  Cmp   AH,35            //wildcard '#'
  Jnz   @L5
  Cmp   AL,48
  Jb    @L4
  Cmp   AL,57
  Jbe   @Next
  Jmp   @L4
@L5:
  Cmp   AH,64            //wildcard '@'
  Jnz   @L6
  Cmp   AL,32
  Jz    @L4

  Push  EBX
  Lea   EBX,AlphaT

  Call  _TstBit
  Pop   EBX
  Jc    @Next
  Jmp   @L4
@L6:
  Cmp   AH,126            //wildcard '~'
  Jnz   @L7

  Push  EBX
  Lea   EBX,AlphaNumT
  Call  _TstBit
  Pop   EBX
  Jnc   @Next
  Jmp   @L4
@L7:
  Cmp   AH,36            //wildcard '$'
  Jnz   @L8
  Cmp   AL,32
  Jz    @L4

  Push  EBX
  Lea   EBX,AlphaNumT
  Call  _TstBit
  Pop   EBX
  Jc    @Next
  Jmp   @L4
@L8:
  Cmp   AL,AH            //match ?
  Jz    @Next            //yes, then check next char.

  Test  EAX,$80000000    //case insensitive flag
  Jz    @L4

  Push  EAX
  Call  RChar
  Mov   [ESP],AL
  Pop   EAX
  Cmp   AL,AH            //match ?
  Jz    @Next            //yes, then check next char.

@L4:
  Mov   EBX,EBP          //roll back Source offset
  Mov   EDX,R2           //roll back Search
  Or    EDX,EDX          //anchored ?
  Jz    @L2              //no, then skip
  Inc   EBP              //increment offset instead of base
  Inc   EBX
  Jmp   @Next
@L2:
  Inc   ESI              //move to next character in source
  Dec   ECX
  Jnz   @Next

@NotFound:
  Xor   EAX,EAX          //clear return
  Mov   ESI,EAX
  Jmp   @Done            //and bail
@Found:
  Sub   ESI,L1           //calc offset
  Inc   ESI
  Mov   EAX,EBX          //match length
@Done:
  Mov   EDI,R1           //Start = offset
  Mov   [EDI],ESI

  Pop   EBP              //restore the world
  Pop   EDI
  Pop   ESI
  Pop   EBX
end;

procedure StringToFile(String2BeSaved, FileName: string);
var
  MyStream: TMemoryStream;
begin
  if String2BeSaved = '' then exit;
  MyStream := TMemoryStream.Create;
  try
    MyStream.WriteBuffer(Pointer(String2BeSaved)^, Length(String2BeSaved));
    MyStream.SaveToFile(FileName);
  finally
    MyStream.Free;
  end;
end;

//Result is match offset. -1 for not found.
//SearchPattern in HEX STRING !!!
function PatternMatching(const FileName : string; SearchPattern : String; Offset : Longint = -1; BufLength : Integer = -1) : Integer;
var
  StartPos : integer;
  BufStr : string;
begin
  Result := -1;
  BufStr := StrToHexStr(DumpFileToString(FileName, Offset, BufLength));

  //ShowMessage(IntToStr(Length(BufStr)) + ':' + BufStr);
  //ShowMessage(IntToStr(Length(PatternInHexStr)) + ':' + PatternInHexStr);
  //StringToFile(BufStr, 'abc.txt');

  //StringToFile(BufStr, 'SOURCE.TXT');
  //StringToFile(UpperCase(SearchPattern), 'SEARCH.TXT');

  StartPos := 1; //String dimulai dari 1
  if IsMatchEx(BufStr, UpperCase(SearchPattern), StartPos) > 0 then
  begin
    if Offset = -1 then
    begin
      //MsgOk(IntToStr(StartPos));
      Result := StartPos div 2;
    end
    else
    begin
      if Offset > -1 then
      begin
        if (StartPos mod 2 = 0) then
          Result := StartPos div 2
        else
          Result := (StartPos + 1) div 2;

        if Result > 0 then
          Result := Result - 1;

        Result := Result + Offset;
        //MsgOk(Format('Offset: %d;'+#13#10+'StartPos: %d'+#13#10+'Result: %d', [Offset, StartPos, Result]));
      end;
    end;
  end;
  BufStr := '';
end;

//Result is match offset. -1 for not found.
//SearchPattern in HEX STRING !!!
function PatternMatchingStr(const SourceBuffer, SearchPatternInHexStr : ansistring;
                            Offset : Integer = -1; BufferLength : Integer = -1) : Integer;
var
  StartPos : integer;
  BufStr : string;
  FoundPos : integer;
begin
  Result := -1;

  if BufferLength > Length(SourceBuffer) then exit;
  if Offset <> -1 then if (Offset + BufferLength) > Length(SourceBuffer) then exit;

  if BufferLength = -1 then
    BufStr := StrToHexStr(SourceBuffer)
  else
  begin
    if Offset = -1 then //ABCDEFG
      BufStr := StrToHexStr(Copy(SourceBuffer, 1, BufferLength))
    else
    begin
      BufStr := StrToHexStr(Copy(SourceBuffer, Offset + 1, BufferLength));
    end
  end;

  {
  if (Offset = -1) or (Offset = 0) then
  begin
    StartPos := 1; //String dimulai dari 1
  end
  else
    if Offset > 0 then
      StartPos := Offset * 2; //HEX CHAR = 2. Ex: 0D
  }
  StartPos := 1;

  FoundPos := IsMatchEx(BufStr, UpperCase(SearchPatternInHexStr), StartPos); //StartPos nanti berisi offset ketemu
  if FoundPos > 0 then
  begin
    if (StartPos mod 2 = 0) then
      Result := StartPos div 2
    else
      Result := (StartPos + 1) div 2;
    if Result > 0 then
      Result := Result - 1;
  end;

  BufStr := '';
end;

end.
