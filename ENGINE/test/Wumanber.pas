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
{       Credit: Daniel Gaußmann                                     }
{                                                                   }
{*******************************************************************}

unit Wumanber;

interface
uses
  Windows, sysutils,Classes;
 
const
 MAXHASH = $7FFF;
 MASK = $1F;
 
type
  PMatchItem = ^TMatchItem;
  TMatchItem = record
    Len: WORD;
    Pattern: PByte;
    InfoIndex: Integer;
  end;
  TMatchArray = Array of PMatchItem;
  THashArray  = Array Of Integer;
 
  TMatchWU = class
  Private
    FCount: Integer;
    suffix: Array of Integer;
    ShiftList: Array[0..MAXHASH] of Integer;
    HashList: Array[0..MAXHASH] of THashArray;
    ItemList: TMatchArray;
    LMin: integer;
    B: integer;
  Public
    constructor Create;
    Destructor Destroy; override;
    Function AddPattern(Pattern: AnsiString; InfoIndex: Integer):Boolean;
    Procedure InitHash;
    Function Search(Buffer: PByte; SzSize: LongInt; Var InfoIndex:Integer):Integer;
  end;
 
implementation
 
Function GetByte(Pattern:PByte; Loc:Integer):Integer;
begin
  Result := PByte(Pointer(Integer(Pattern)+Loc))^;
end;
 
constructor TMatchWU.Create;
var
i: integer;
begin
  inherited create;
  FCount := 0;
  lmin := High(Integer);
  for i := 0 to MAXHASH do begin
    ShiftList[i] := 0;
    Setlength(HashList[i], 0);
  end;
  Setlength(suffix, FCount);
  Setlength(ItemList, FCount);
end;
 
Destructor TMatchWU.Destroy;
var
i : integer;
begin
  for i := 0 to MAXHASH do begin
    setlength(HashList[i], 0);
  end;
  for i := 0 to FCount-1 do begin
    if assigned(ItemList[i]) then begin
      with ItemList[i]^ do begin
        if assigned(Pattern) then FreeMem(Pattern, len+1);
      end;
      FreeMem(ItemList[i]);
    end;
  end;
  setlength(ItemList, 0);
  setlength(suffix, 0);
  inherited Destroy;
end;
 
Function TMatchWU.AddPattern(Pattern: AnsiString; InfoIndex: Integer):Boolean;
var
  Item: PMatchItem;
begin
  result := false;
  Item := AllocMem(SizeOf(TMatchItem));
  if Assigned(Item) then begin
    Item^.Len := (Length(Pattern) div 2);
    if (Item^.Len > 0) then begin
      try
        Item^.Pattern := AllocMem(Item^.Len);
        HexToBin(pwidechar(Pattern), Item^.Pattern, Length(Pattern));
        Item^.InfoIndex := InfoIndex;
        Dec(Item^.Len);
        inc(FCount);
        SetLength(ItemList, FCount);
        ItemList[FCount-1] := Item;
        result := true;
      except
      end;
    end;
    if (result = false) and Assigned(Item) then FreeMem(Item);
  end;
end;
 
Procedure TMatchWU.InitHash;
var
  i, def, pl, hi, h: Integer;
begin
  {calculated shorted pattern length}
  for i := 0 to FCount -1 do begin
    if lmin > ItemList[i]^.Len then lmin := ItemList[i]^.Len;
  end;
 
  {calculated shift count}
  if lmin = 1 then B := 1
  else if (lmin > 2) and (lmin*FCount > 400) then B := 3
  else B := 2;
  def := lmin - B + 1;
 
  {Insert default shift}
  for i := 0 to MAXHASH do ShiftList[i] := def;
 
  {Configure Suffix List}
  Setlength(suffix, FCount);
  for i := 0 to FCount - 1 do begin
    pl := ItemList[i]^.Len;
    if B=1 then suffix[i] := GetByte(ItemList[i]^.Pattern, pl-lmin)
    else suffix[i] := (GetByte(ItemList[i]^.Pattern, pl-lmin) shl 8) + GetByte(ItemList[i]^.Pattern, pl-lmin+1);
  end;
 
  {Configure Hash List}
  for i := 0 to FCount - 1 do begin
    pl := ItemList[i]^.Len;
    for hi := (pl - lmin + B)-1 to (pl - 1) do begin
      h := GetByte(ItemList[i]^.Pattern, hi) AND MASK;
      if (B >= 2) then h := (h shl 5) + (GetByte(ItemList[i]^.Pattern, hi-1) and MASK);
      if (B >= 3) then h := (h shl 5) + (GetByte(ItemList[i]^.Pattern, hi-2) and MASK);
      if (ShiftList[h] > pl-hi) then ShiftList[h] := pl-hi;
    end;
    h := GetByte(ItemList[i]^.Pattern, pl) AND MASK;
    if (B >= 2) then h := (h shl 5) + (GetByte(ItemList[i]^.Pattern, pl-1) and MASK);
    if (B >= 3) then h := (h shl 5) + (GetByte(ItemList[i]^.Pattern, pl-2) and MASK);
    ShiftList[h] := 0;
    Setlength(HashList[h], Length(HashList[h])+1);
    HashList[h][Length(HashList[h])-1] := i;
  end;
end;
 
Function TMatchWU.Search(Buffer: PByte; SzSize: LongInt; Var InfoIndex:Integer):Integer;
var
  i, h, j, k, l: Integer;
  TextSuft: Integer;
begin
  result := -1;
  if lmin = High(Integer) then exit;
 
  {shorted pattern as starting point}
  i := lmin;
  while (i <= SzSize) do begin
 
    {Get Hash}
    h := GetByte(Buffer, i) AND MASK;
    if B >= 2 then h := (h shl 5) + (GetByte(Buffer, i-1) and MASK);
    if B >= 3 then h := (h shl 5) + (GetByte(Buffer, i-2) and MASK);
    if (ShiftList[h] = 0) then begin
 
      {Get Suffix}
      if B=1 then TextSuft := GetByte(Buffer, i-lmin)
      else TextSuft := (GetByte(Buffer, i-lmin) shl 8) + GetByte(Buffer, i-lmin + 1);
      if (Length(HashList[h]) <> 0) then begin
        for j := 0 to Length(HashList[h]) - 1 do begin
 
          {Check if Suffix same}
          k := HashList[h][j];
          if (suffix[k] = TextSuft) and (i >= ItemList[k]^.Len) then begin
 
            {Check if pattern same}
            l := 0;
            while (l <= ItemList[k]^.Len) and (GetByte(Buffer, i-l) = GetByte(ItemList[k]^.Pattern, ItemList[k]^.Len-l)) do inc(l);
            if (l-1 = ItemList[k]^.Len) then begin
 
              {get the result}
              InfoIndex := ItemList[k]^.InfoIndex;
              result := i-ItemList[k]^.Len;
              exit;
            end;
          end;
        end;
      end;
      inc(i);
    end else inc(i, ShiftList[h]);
  end;
end;
 
end.