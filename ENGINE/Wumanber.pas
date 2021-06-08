{*******************************************************************}
{                                                                   }
{       Jasakom Security                                            }
{       JasaAV                                                      }
{       Version 0.0.0.1                                             }
{                                                                   }
{       Copyright (c) 2009 Jasakom Security                         }
{       ALL RIGHTS RESERVED                                         }
{                                                                   }
{       Author: meong                                               }
{       Contaqh : jasaav@ymail.com                                  }
{       Credit: Daniel Gauﬂmann                                     }
{                                                                   }
{*******************************************************************}
(*
program ApplicationEngine;


uses
  windows,SysUtils,
  U_WuManber in 'U_WuManber.pas';

function FileToBytes(sPath:string; var bFile:TarrayByte):Boolean;
var
hFile:  THandle;
dSize:  DWORD;
dRead:  DWORD;
begin
 Result := FALSE;
 hFile := CreateFile(PChar(sPath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
 if hFile <> 0 then
 begin
  dSize := GetFileSize(hFile, nil);
  SetFilePointer(hFile, 0, nil, FILE_BEGIN);
  SetLength(bFile, dSize);
  if ReadFile(hFile, bFile[0], dSize, dRead, nil) then
   Result := TRUE;
  CloseHandle(hFile);
 end;
end;

var
virus : string;
abhe : TWUMatch;
search : TarrayByte;
begin
  try
    if FileToBytes('ApplicationEngine.exe',search) then begin
      abhe := TWUMatch.Create;
      abhe.AddPattern('D77017C9F98CC25FF0A15BC4D0E0F364810B','meongvirus');
      abhe.InitHash;
      virus := abhe.Search(search);
      abhe.Destroy;
      messagebox(0,pchar(virus),nil,mb_ok);
    end;
  except
    on E:Exception do
      Writeln(E.Classname, ': ', E.Message);
  end;
end.
*)
unit Wumanber;

interface
uses
sysutils,
classes;

const
 MAXHASH = $7FFF;
 MASK = $1F;
 
type
  PNode = ^Node;
  Node = record
    Pattern : TarrayByte;
    Length : integer;
    virusname : string;
  end; 
  
////////////////////////////////////////////////////////////////////////////////
////  TWUMatch
////////////////////////////////////////////////////////////////////////////////
  TWUMatch = class
  private  
    FCount   : longint;
    Prefix: Array of Integer;
    Shift: Array[0..MAXHASH] of Integer;
    Hash: Array[0..MAXHASH] of TList;
    Pat : array of PNode;
    Lmin : integer;
    B : integer;
  Public
    Procedure InitHash;
    constructor Create;
    Destructor Destroy; override;
    Procedure Clear;
    Procedure AddPattern(Pattern,virusname: string);    
    Function Search(const buffer: TarrayByte):String;
    Property Count : integer read FCount;
  end;

implementation 

function HexToInt(HexNum: string): LongInt;
begin
   Result:=StrToInt('$' + HexNum) ;
end;

function GetByte(hexnum:string):TarrayByte;
var
i,d : integer;
begin
  setlength(result,length(hexnum) div 2);
  d := 0;
  i:=1;
  While i<Length(hexnum) Do
  begin
    Result[d] := HexToInt(Copy(hexnum,i,2));
    Inc(i,2);
    Inc(d);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
////  TWUMatch
////////////////////////////////////////////////////////////////////////////////
constructor TWUMatch.Create;
var
i : integer;
begin
  inherited create;
  FCount := 0;
  lmin := High(Integer);
  for i := 0 to MAXHASH do begin
    Shift[i] := 0;
    hash[i] := nil;
  end;
  setlength(Pat,FCount);
  setlength(Prefix,FCount);
end; 
{---------------}
Procedure TWUMatch.Clear;
var
i : integer;
begin
  for i := 0 to FCount-1 do begin
    dispose(Pat[i]);
  end;
  for i := 0 to MAXHASH do
    if assigned(Hash[i]) then hash[i].Free;
end; 
{---------------}
Destructor TWUMatch.Destroy;
begin
  Clear;
  FCount := 0;
  lmin := High(Integer);
  setlength(Pat,FCount);
  setlength(Prefix,FCount);
  inherited Destroy;
end;
{---------------}
procedure TWUMatch.InitHash;
var
r,def,i,mi,h: integer;
begin
  for r := 0 to FCount -1 do begin
    if lmin > pat[r].Length then lmin := pat[r].Length; 
  end;
  if lmin = 1 then B := 1
  else if (lmin > 2) and (lmin*FCount > 400) then B := 3
  else B := 2;
  def := lmin - B +1 ;
  for i := 0 to MAXHASH do Shift[i] := def;
  Setlength(Prefix,FCount);
  for r := 0 to FCount - 1 do begin
    mi := pat[r].Length;
    if B=1 then Prefix[r] := Integer(pat[r].Pattern[mi-lmin])
    else Prefix[r] := (Integer(pat[r].Pattern[mi-lmin]) shl 8) + Integer(pat[r].Pattern[mi-lmin+1]);
  end;
  for r := 0 to FCount - 1 do begin
    mi := pat[r].Length;
    for i := (mi - lmin + B)-1 to mi - 1 do begin
      h := Integer(pat[r].Pattern[i]) AND MASK;
      if B >= 2 then h := (h shl 5) + (Integer(pat[r].Pattern[i-1]) and MASK);
      if B >= 3 then h := (h shl 5) + (Integer(pat[r].Pattern[i-2]) and MASK);
      if Shift[h] > mi-i then Shift[h] := mi-i;
    end;
    h := Integer(pat[r].Pattern[mi]) AND MASK;
    if B >= 2 then h := (h shl 5) + (Integer(pat[r].Pattern[mi-1]) and MASK);
    if B >= 3 then h := (h shl 5) + (Integer(pat[r].Pattern[mi-2]) and MASK);
    Shift[h] := 0;
    if not assigned(Hash[h]) then Hash[h] := TList.Create;
    Hash[h].Add(Pointer(r));
  end;    
end;
{---------------}
Procedure TWUMatch.AddPattern(Pattern,virusname: string);
var
N : PNode;
mi : integer;
pattemp : TarrayByte;
begin
  pattemp := GetByte(expattern);
  mi := Length(pattemp)-1;
  N := New(PNode);
  N^.Pattern := pattemp;
  N^.virusname := virusname;
  N^.Length := mi;
  inc(FCount);
  SetLength(Pat, FCount);
  pat[FCount-1] := N;  
end;
{---------------}
Function TWUMatch.Search(const buffer: TarrayByte):String;
var
k,n,h,r,i,j : integer;
TextPref: Integer;
begin
  result := '';
  if lmin = High(Integer) then exit;
  k := lmin;
  n := length(buffer)-1;
  while k <= n do begin
    h := Integer(buffer[k]) AND MASK;
    if B >= 2 then h := (h shl 5) + (Integer(buffer[k-1]) and MASK);
    if B >= 3 then h := (h shl 5) + (Integer(buffer[k-2]) and MASK);
    if shift[h]=0 then begin
      if B=1 then TextPref := buffer[k - lmin]
      else TextPref := (buffer[k - lmin] shl 8) + buffer[k - lmin + 1];
      if assigned(Hash[h]) then begin
        for r := 0 to Hash[h].Count - 1 do begin
          i := Integer(Hash[h].Items[r]);
          if Prefix[i] = TextPref then begin
            if k >= pat[i].Length then begin
              j := 0;
              while (j <= pat[i].Length) and (buffer[k-j] = pat[i].Pattern[pat[i].Length-j]) do inc(j);
              if (j-1 = pat[i].Length) then begin
                  result := pat[i].virusname;
                  exit;
              end;
            end;
          end;
        end;
      end;
      k := k + 1;
    end else k := k + shift[h];
  end;
end;