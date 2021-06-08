unit kpSStrng;

{ Secrets of Delphi 2, by Ray Lischner. (1996, Waite Group Press).
  Chapter 1: Introduction.
  Copyright © 1996 The Waite Group, Inc. }
  
{ Delphi 1.0/Delphi 2.0 string compatibility unit. Delphi 2.0 has long
  strings, and uses the SetLength and SetString functions to manipulate
  them. Delphi 1.0 lacks these functions. For portability, this unit
  defines these procedures appropriately for Delphi 1.0. Also, Delphi 2.0
  strings can be converted directly to PChar, but Delphi 1.0 strings might
  need to be copied into a character array. The StrToPChar function hides
  this difference.
}

interface

{ Convert a Pascal string to a PChar. }
function StrToPChar(const Str: string): PChar;

{ Assuming that all versions of Delphi past VER80 will support the
  new string type, implement the compatibility code for VER80 only. }
{$ifdef VER80}
type
  ShortString = string;
  PShortString = ^ShortString;
  AnsiChar = Char;
  PAnsiChar = ^AnsiChar;

{ Set the length of string, Str, to Length. }
procedure SetLength(var Str: string; Length: Byte);

{ Set the contents of string Str, to Length bytes, starting at From. }
procedure SetString(var Str: string; From: PChar; Length: Byte);

{ Copy and return Str, after trimming leading and trailing white space
  characters. Do not modify Str. }
function Trim(const Str: string): string;

{ Copy and return Str, after trimming leading white space
  characters. Do not modify Str. }
function TrimLeft(const Str: string): string;

{ Copy and return Str, after trimming trailing white space
  characters. Do not modify Str. }
function TrimRight(const Str: string): string;
{$endif}

implementation

{$ifndef VER80}
{ Delphi 2.0 knows how to convert string to PChar. }
function StrToPChar(const Str: string): PChar;
begin
  Result := PChar(Str);
end;

{$else}
uses SysUtils;

{ Return a PChar representation of the string, Str. Allocate a dynamic
  copy of the string. Keep a ring of 8 dynamic strings, and free the
  old strings. Thus, you can usually rely on the returned string being
  valid while it is needed. The most common need is to pass an argument
  to a Windows API function, so the need is temporary, but several
  such strings might be required. That's why the ring has 8 items in it:
  more than enough for most uses. }
type
  TRingIndex = 0..7;
var
  Ring: array[TRingIndex] of PChar;
  RingIndex: TRingIndex;
  
function StrToPChar(const Str: string): PChar;
begin
  { Allocate a PChar and copy the original string. }
  Result := StrAlloc(Length(Str)+1);    
  StrPCopy(Result, Str);

  { Add the string to the ring. }
  StrDispose(Ring[RingIndex]);
  Ring[RingIndex] := Result;
  RingIndex := (RingIndex + 1) mod (High(TRingIndex) + 1);
end;

{ Set the length of a string. }
procedure SetLength(var Str: string; Length: Byte);
begin
  Str[0] := Chr(Length)
end;

{ Set the contents of a string. If there are fewer than Length bytes
  in the string, From, then leave the remaining bytes unchanged. }
procedure SetString(var Str: string; From: PChar; Length: Byte);
var
  FromLen: Integer;
begin
  Str[0] := Chr(Length);
  { In Delphi 2.0, a nil pointer represents an empty string. The representation
    should be hidden by the compiler, but some people use an explicit nil
    pointer to mean an empty string. This is sloppy programming, but some
    people do it anyway. }
  if From <> nil then
  begin
    { Only copy as many bytes as are in the From string. }
    FromLen := StrLen(From);
    if FromLen < Length then
      Length := FromLen;
    Move(From^, Str[1], Length);
  end;
end;

{ Return whether the character C, is a white space character,
  or a nonprintable control character. }
function IsWhiteSpace(C: Char): Boolean;
begin
  Result := C in [#0..' ']
end;

{ Trim all leading and trailing white space characters. }
function Trim(const Str: string): string;
var
  L, R: Integer;
begin
  L := 1;
  R := Length(Str);
  while (L < R) and IsWhiteSpace(Str[L]) do
    Inc(L);
  while (L < R) and IsWhiteSpace(Str[R]) do
    Dec(R);
  Result := Copy(Str, L, R-L+1);
end;

{ Trim leading white space characters. }
function TrimLeft(const Str: string): string;
var
  L, R: Integer;
begin
  L := 1;
  R := Length(Str);
  while (L < R) and IsWhiteSpace(Str[L]) do
    Inc(L);
  Result := Copy(Str, L, 255);
end;

{ Trim trailing white space characters. }
function TrimRight(const Str: string): string;
var
  R: Integer;
begin
  R := Length(Str);
  while (1 < R) and IsWhiteSpace(Str[R]) do
    Dec(R);
  Result := Copy(Str, 1, R);
end;

{ Free all the left over strings in the StrToPChar ring. }
procedure Terminate; far;
var
  I: TRingIndex;
begin
  for I := Low(TRingIndex) to High(TRingIndex) do
  begin
    StrDispose(Ring[I]);
    Ring[I] := nil; { just in case StrToPChar is called again }
  end;
end;

initialization
  AddExitProc(Terminate);
{$endif}

end.
