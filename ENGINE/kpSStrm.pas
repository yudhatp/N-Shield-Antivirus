unit kpSStrm;

{ Secrets of Delphi 2, by Ray Lischner. (1996, Waite Group Press).
  Chapter 3: Streams and File I/O
  Copyright © 1996 The Waite Group, Inc. }

{ Buffered I/O stream and buffered text stream. }

{ $Log: }


interface

uses
{$IFDEF WIN32}
  Windows,
{$ELSE}
  WinTypes,
{$ENDIF}
  Classes, SysUtils;

type
  TS_BufferState = (bsUnknown, bsRead, bsWrite);
  TS_BufferStream = class(TStream)
  private
    fStream: TStream;
    fBuffer: PChar;
    fBufPtr: PChar;
    fBufEnd: PChar;
    fBufSize: Cardinal;
    fState: TS_BufferState;
    fOnFillBuffer: TNotifyEvent;
    fOnFlushBuffer: TNotifyEvent;
    function GetBufPosition: Integer;
  protected
    function FillBuffer: Boolean; virtual;
    function FlushBuffer: Boolean; virtual;
    procedure PutBack(Ch: Char); virtual;
    procedure AfterFillBuffer; virtual;
    procedure AfterFlushBuffer; virtual;
    property Buffer: PChar read fBuffer;
    property BufPtr: PChar read fBufPtr;
    property BufSize: Cardinal read fBufSize;
    property BufEnd: PChar read fBufEnd;
    property BufPosition: Integer read GetBufPosition;
    property State: TS_BufferState read fState;
    property Stream: TStream read fStream;
  public
    constructor Create(Stream: TStream); virtual;
    destructor Destroy; override;
    function Read(var Buffer; Count: LongInt): LongInt; override;
    function Write(const Buffer; Count: LongInt): LongInt; override;
    function Seek(Offset: LongInt; Origin: Word): LongInt; override;
    function IsEof: Boolean;
    property OnFillBuffer: TNotifyEvent read fOnFillBuffer
        write fOnFillBuffer;
    property OnFlushBuffer: TNotifyEvent read fOnFlushBuffer
        write fOnFlushBuffer;
  end;

  TS_TextStream = class(TS_BufferStream)
  private
    fOwnStream: Boolean;
  protected
    procedure FreeStream; virtual;
    property OwnStream: Boolean read fOwnStream write fOwnStream;
  public
    constructor CreateFromFile(const Filename: string; Mode: Word);
    destructor Destroy; override;

    { Useful input routines. }
    procedure SkipSpaces;
    function GetChar: Char;
    function GetInteger: LongInt;
    function GetFloat: Extended;
    function GetToken(const Delimiters: string): string;
    function GetLine: string;

    { Basic output routines. }
    function PutChar(Ch: Char): TS_TextStream;
    function PutInteger(Int: LongInt): TS_TextStream;
    function PutFloat(Flt: Extended): TS_TextStream;
    function PutString(const Str: string): TS_TextStream;
    function PutLine(const Str: string): TS_TextStream;
    function PutPChar(const Str: PChar): TS_TextStream;
  {$ifdef WIN32}
    function PutWideChar(WCh: WideChar): TS_TextStream;
  {$endif}

    { Special output characters. }
    function PutSpace: TS_TextStream;
    function PutTab: TS_TextStream;
    function PutEndOfLine: TS_TextStream;

    { Formatted output routines. }
    procedure WriteArgs(Args: array of const);
    procedure WriteLn(Args: array of const);
    procedure Format(const Fmt: string; Args: array of const);
    procedure FormatLn(const Fmt: string; Args: array of const);
  end;

{$ifdef VER80}
  { Stream for reading a resource. }
  TResourceStream = class(THandleStream)
  private
    fStartPos: LongInt;    { starting file position of resource }
    fEndPos: LongInt;      { ending file position of resource }
  protected
    { This constructor is protected, to preserve compatibility with
      TResourceStream in Delphi 2.0, which does not declare CreateFromPChar. }
    constructor CreateFromPChar(Instance: THandle; ResName, ResType: PChar);
  public
    constructor Create(Instance: THandle; const ResName: string;
        ResType: PChar);
    constructor CreateFromID(Instance: THandle; ResID: Integer;
        ResType: PChar);
    destructor Destroy; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
  end;
{$endif}

const
  BufferSize: Integer = 8192;

implementation

uses
{$IFNDEF WIN32}
  WinProcs,
{$ENDIF}
  kpSHuge, kpSStrng, kpStrRes;

{$R *.res}
{ String resource IDs }
const
  S_SeekError = 1;
  S_InvalidOrigin = 2;
  S_PutBackOverflow = 3;
  S_CantFindResource = 4;
  S_CantAccessResource = 5;
  S_SeekPastEof = 6;
  S_CantWriteResource = 7;

{ Create and initialize a buffer stream. }
constructor TS_BufferStream.Create(Stream: TStream);
begin
  inherited Create;
  fStream := Stream;
  fBufSize := BufferSize;
  { Allocate the buffer. }
  GetMem(fBuffer, BufSize);
  fBufEnd := Buffer + BufSize;
  fState := bsUnknown;
end;

{ Destroy the buffer stream. If the buffer is in write mode, then
  make sure the last bufferful is written to the stream. }
destructor TS_BufferStream.Destroy;
begin
  if State = bsWrite then
    FlushBuffer;
  FreeMem(fBuffer, BufSize);
  inherited Destroy;
end;

{ Fill the input buffer. }
function TS_BufferStream.FillBuffer: Boolean;
var
  NumBytes: Cardinal;
begin
  { Read from the actual stream. }
  NumBytes := Stream.Read(Buffer^, BufSize);
  { Set the buffer pointer and end. }
  fBufPtr := Buffer;
  fBufEnd := Buffer + NumBytes;
  { If nothing was read, it must be the end of file. }
  Result := NumBytes > 0;
  if Result then
    fState := bsRead
  else
    fState := bsUnknown;
  AfterFillBuffer;
end;

{ Write the output buffer to the stream. When done, the
  buffer is empty, so set the state back to bsUnknown. }
function TS_BufferStream.FlushBuffer: Boolean;
var
  NumBytes: Cardinal;
begin
  { Determine the number of bytes in the buffer. }
  NumBytes := BufPtr - Buffer;
  { Write the buffer contents. }
  Result := NumBytes = Stream.Write(Buffer^, NumBytes);
  { Th ebuffer is empty, so reset the state. }
  fBufPtr := Buffer;
  fState := bsUnknown;
  AfterFlushBuffer;
end;

{ Read Count bytes. Copy first from the input buffer, and then
  fill the input buffer repeatedly, until fetching all Count bytes.
  Return the number of bytes read. If the state was Write, then
  flush the output buffer before reading. }
function TS_BufferStream.Read(var Buffer; Count: LongInt): LongInt;
var
  Ptr: PChar;
  NumBytes: Cardinal;
begin
  if State = bsWrite then
    FlushBuffer
  else if BufPtr = nil then
    fBufPtr := BufEnd; { empty buffer, so force a FillBuffer call }

  { The user might ask for more than one bufferful.
    Prepare to loop until all the requested bytes have been read. }
  Ptr := @Buffer;
  Result := 0;
  while Count > 0 do
  begin
    { If the buffer is empty, then fill it. }
    if BufPtr = BufEnd then
      if not FillBuffer then
        Break;
    NumBytes := BufEnd - BufPtr;
    if Count < NumBytes then
      NumBytes := Count;

    { Copy the buffer to the user's memory. }
    HMemCpy(Ptr, BufPtr, NumBytes);
    { Increment the pointers. The stream’s buffer is always within a single
      segment, but the user's buffer might cross segment boundaries. }
    Dec(Count, NumBytes);
    Inc(fBufPtr, NumBytes);
    Inc(Result, NumBytes);
    Ptr := HugeOffset(Ptr, NumBytes);
  end;
end;

{ Write Count bytes from Buffer to the stream. If the state was
  bsRead, then reposition the stream to match. }
function TS_BufferStream.Write(const Buffer; Count: LongInt): LongInt;
var
  Ptr: Pointer;
  NumBytes: Cardinal;
begin
  { If the stream is for reading, then ignore the current buffer
    by forcing the position of the underlying stream to match
    the buffered stream's position. }
  if State = bsRead then
    fStream.Position := Position
  else if BufPtr = nil then
  begin
    { Unknown state, so start with an empty buffer. }
    fBufPtr := fBuffer;
    fBufEnd := fBuffer + BufSize;
  end;

  { The user might write more than one bufferful.
    Prepare to loop until all the requested bytes have been written. }
  Ptr := @Buffer;
  Result := 0;                   { Total number of bytes written. }
  while Count > 0 do
  begin
    { Calculate the number of bytes remaining in the buffer. }
    NumBytes := BufEnd - BufPtr;
    if Count < NumBytes then
      NumBytes := Count;
    { Copy from the user's memory to the buffer. }
    HMemCpy(BufPtr, Ptr, NumBytes);
    { Increment the pointers. The stream's buffer is always in
      a single segment, but the user's buffer might cross
      segment boundaries.}
    Dec(Count, NumBytes);
    Inc(fBufPtr, NumBytes);
    Inc(Result, NumBytes);
    Ptr := HugeOffset(Ptr, NumBytes);
    if BufPtr = BufEnd then
      if not FlushBuffer then
        Break;
  end;
  { If anything remains in the buffer, then set the state to bsWrite. }
  if BufPtr <> fBuffer then
    fState := bsWrite;
end;

{ Seek to a new position. Calling Seek to learn the current
  position is a common idiom, so do not disturb the buffers
  and just return the position, taking the current buffer
  position into account. If the Seek is to move to a different
  position in the stream, the dump the buffer and reset the state. }
function TS_BufferStream.Seek(Offset: LongInt; Origin: Word): LongInt;
var
  CurrentPosition: LongInt;

  { this function needed because Stream.Size is not always the actual end }
  { of the file.  There is likely some in the buffer not flushed out yet  }
  { Added by Kevin L. Boylan, KpGb Software, 10/09/97 }
  function RealSize: LongInt;
  begin
     Result := Stream.Position + BufPosition;
     If Result < Stream.Size then
        Result := Stream.Size;
  end;

begin
  { Determine the current position. }
  CurrentPosition := Stream.Position + BufPosition;

  { Determine the new position }
  case Origin of
  soFromBeginning: Result := Offset;
  soFromCurrent:   Result := Stream.Position + BufPosition + Offset;
  {soFromEnd:       Result := Stream.Size - Offset;}
  { Modified 10/09/97 by Kevin L. Boylan, KpGb Software }
  { Needed Abs() because a negative offset number is expected with soFromEnd }
  { Needed RealSize, see function above }
  soFromEnd:       Result := RealSize - Abs(Offset);
  else
    raise Exception.CreateFmt(LoadDelphiString('S_Stream', S_InvalidOrigin), [Origin]);
  end;

  { Is the desired position different? }
  if Result <> CurrentPosition then
  begin
    { Flush a partial write. }
    if (State = bsWrite) and not FlushBuffer then
      raise EStreamError.Create(LoadDelphiString('S_Stream', S_SeekError));
    { Reset the stream. }
    Stream.Position := Result;
    { Discard the current buffer. }
    fBufPtr := nil;
    fState := bsUnknown;
  end;
end;

{ Return an offset that can be added to Stream.Position to
  yield the effective position in the stream. }
function TS_BufferStream.GetBufPosition: Integer;
begin
  Result := 0;
  case State of
  bsUnknown:
    Result := 0;
  bsRead:
    Result := BufPtr - BufEnd;
  bsWrite:
    Result := BufPtr - Buffer;
  end;
end;

{ Push a character back onto the input buffer. }
procedure TS_BufferStream.PutBack(Ch: Char);
begin
  if fBufPtr <= fBuffer then
    raise EStreamError.Create(LoadDelphiString('S_Stream', S_PutBackOverflow));
  Dec(fBufPtr);
  BufPtr[0] := Ch;
end;

{ Return whether the current position is at the end of the file. }
function TS_BufferStream.IsEof: Boolean;
begin
  Result := (BufPtr = BufEnd) and (Stream.Position = Stream.Size);
end;

procedure TS_BufferStream.AfterFillBuffer;
begin
  if Assigned(fOnFillBuffer) then
    fOnFillBuffer(Self);
end;

procedure TS_BufferStream.AfterFlushBuffer;
begin
  if Assigned(fOnFlushBuffer) then
    fOnFlushBuffer(Self);
end;


{ TS_TextStream }
constructor TS_TextStream.CreateFromFile(const Filename: string; Mode: Word);
begin
  inherited Create(TFileStream.Create(Filename, Mode));
  OwnStream := True;
end;

destructor TS_TextStream.Destroy;
begin
  { Call the inherited destructor first, to flush the buffer.
    Then free the stream, if it is locally owned. }
  inherited Destroy;
  FreeStream;
end;

{ If the text stream owns the underlying stream, then free it. }
procedure TS_TextStream.FreeStream;
begin
  if OwnStream then
  begin
    fStream.Free;
    fStream := nil;
  end;
end;

{ Read a token, delimited by arbitrary characters. An empty string
  means any white space characters. }
function TS_TextStream.GetToken(const Delimiters: string): string;
var
  Ch: Char;
begin
  Result := '';
  { Read the input one character at a time. }
  while Read(Ch, 1) = 1 do
  begin
    { Check for delimiters. When a delimiter is found, the delimiter
      character is pushed back onto the input buffer before exiting
      from the loop. }
    if (Length(Delimiters) = 0) and (Ch < ' ') then
    begin
      Putback(Ch);
      Break;
    end
    else if (Length(Delimiters) > 0) and (Pos(Ch, Delimiters) > 0) then
    begin
      Putback(Ch);
      Break;
    end;
    { Append a non-delimiter to the token string. }
    AppendStr(Result, Ch);
  end;
end;

{ Read a line of text, stripping the line ending characters. }
function TS_TextStream.GetLine: string;
var
  Ch: Char;
begin
  Result := '';
  { Read characters until reaching at end-of-line character. }
  while (Read(Ch, 1) = 1) and not (Ch in [#10,#13]) do
    AppendStr(Result, Ch);
  { If the end-of-line is CR, look for a subsequent LF. }
  if Ch = #13 then
  begin
    if (Read(Ch, 1) = 1) and (Ch <> #10) then
      Putback(Ch);
  end;
end;

{ Skip over white space (<= ' ') characters. }
procedure TS_TextStream.SkipSpaces;
var
  C: Char;
begin
  while Read(C, 1) = 1 do
    if C > ' ' then
    begin
      { Stop with the first nonspace character. }
      Putback(C);
      Break;
    end;
end;

{ Read & return one character from the input buffer. }
function TS_TextStream.GetChar: Char;
begin
  ReadBuffer(Result, 1);
end;

{ Read a token and convert it to an integer. }
function TS_TextStream.GetInteger: LongInt;
begin
  SkipSpaces;
  Result := StrToInt(GetToken(''));
end;

{ Read a token and convert it to a floating point number. }
function TS_TextStream.GetFloat: Extended;
begin
  SkipSpaces;
  Result := StrToFloat(GetToken(''));
end;

{ Print a single character. }
function TS_TextStream.PutChar(Ch: Char): TS_TextStream;
begin
  WriteBuffer(Ch, 1);
  Result := Self;
end;

{$ifdef WIN32}
function TS_TextStream.PutWideChar(WCh: WideChar): TS_TextStream;
begin
  WriteBuffer(WCh, SizeOf(WCh));
  Result := Self;
end;
{$endif}

{ Print an integer. }
function TS_TextStream.PutInteger(Int: LongInt): TS_TextStream;
begin
  PutString(IntToStr(Int));
  Result := Self;
end;

{ Print a floating point number. }
function TS_TextStream.PutFloat(Flt: Extended): TS_TextStream;
begin
  PutString(FloatToStr(Flt));
  Result := Self;
end;

{ Print a string. }
function TS_TextStream.PutString(const Str: string): TS_TextStream;
begin
  WriteBuffer(Str[1], Length(Str));
  Result := Self;
end;

{ Print a line of text, appending a line ending. }
function TS_TextStream.PutLine(const Str: string): TS_TextStream;
begin
  WriteBuffer(Str[1], Length(Str));
  PutEndOfLine;
  Result := Self;
end;

{ Print a PChar string. }
function TS_TextStream.PutPChar(const Str: PChar): TS_TextStream;
begin
  WriteBuffer(Str[0], StrLen(Str));
  Result := Self;
end;

{ Print a space character. }
function TS_TextStream.PutSpace: TS_TextStream;
begin
  PutChar(' ');
  Result := Self;
end;

{ Print a tab character. }
function TS_TextStream.PutTab: TS_TextStream;
begin
  PutChar(#9);
  Result := Self;
end;

{ Print an end of line. }
function TS_TextStream.PutEndOfLine: TS_TextStream;
begin
  PutChar(#13);
  PutChar(#10);
  Result := Self;
end;

{ Write arbitrary arguments, using default formatting. }
procedure TS_TextStream.WriteArgs(Args: array of const);
var
  I: Integer;
begin
  for I := Low(Args) to High(Args) do
  begin
    case Args[I].VType of
    vtInteger:         PutInteger(Args[I].VInteger);
    vtBoolean:
      if Args[I].VBoolean then
        PutString('True')
      else
        PutString('False');
    vtChar:            PutChar(Args[I].VChar);
    vtExtended:        PutFloat(Args[I].VInteger);
    vtString:          PutString(Args[I].VString^);
    vtPointer:         Format('%p', [Args[I].VPointer]);
    vtPChar:           PutPChar(Args[I].VPChar);
    vtClass:           PutString(Args[I].VClass.ClassName);
    vtObject:
      begin
        PutChar('(');
        PutString(Args[I].VObject.ClassName);
        PutChar(')');
      end;
{$ifndef VER80}
    vtAnsiString:      PutString(string(Args[I].VAnsiString));
    vtWideChar:        PutWideChar(Args[I].VWideChar);
    vtCurrency:        PutFloat(Args[I].VCurrency^);
    vtVariant:         PutString(Args[I].VVariant^);
{$endif}
    end;
    if (I < High(Args)) and (Args[I].VType <> vtChar) then
      PutSpace;
  end;
end;

{ Write arbitrary arguments, appending a line ending. }
procedure TS_TextStream.WriteLn(Args: array of const);
begin
  WriteArgs(Args);
  PutEndOfLine;
end;

{ Format and write arbitrary arguments. }
procedure TS_TextStream.Format(const Fmt: string; Args: array of const);
begin
  PutString(SysUtils.Format(Fmt, Args));
end;

{ Format and write arbitrary arguments, appending a line ending. }
procedure TS_TextStream.FormatLn(const Fmt: string; Args: array of const);
begin
  PutString(SysUtils.Format(Fmt, Args));
  PutEndOfLine;
end;

{$ifdef VER80}
{ TResourceStream }
{ Open a file to access the resources. The file position is automatically
  set to the start of the resource, but the TResourceStream object makes it
  appear that the resource starts at position zero, and that the size of
  the stream is the size of the resource. }
constructor TResourceStream.Create(Instance: THandle; const ResName: string; ResType: PChar);
begin
  CreateFromPChar(Instance, StrToPChar(ResName), ResType);
end;

constructor TResourceStream.CreateFromID(Instance: THandle; ResID: Integer; ResType: PChar);
begin
  CreateFromPChar(Instance, MakeIntResource(ResID), ResType);
end;

constructor TResourceStream.CreateFromPChar(Instance: THandle; ResName, ResType: PChar);
var
  ResInfo: THandle;
  Handle: Integer;
begin
  { Locate and open the resource. }
  ResInfo := FindResource(Instance, ResName, ResType);
  if ResInfo = 0 then
    raise EResNotFound.Create(LoadDelphiString('S_Stream', S_CantFindResource));

  Handle := AccessResource(Instance, ResInfo);
  if Handle < 0 then
    raise EResNotFound.Create(LoadDelphiString('S_Stream', S_CantAccessResource));

  { Initialize the THandleStream. }
  inherited Create(Handle);

  { Remember the starting & ending positions of the resource. }
  fStartPos := inherited Seek(0, soFromCurrent);
  fEndPos := fStartPos + SizeOfResource(Instance, ResInfo);
end;

{ Close the file handle when we destroy the stream. }
destructor TResourceStream.Destroy;
begin
  if Handle >= 0 then
    FileClose(Handle);
  inherited Destroy;
end;

{ A resource is read-only, so calling Write raises an exception. This is
  exactly the same behavior as TResourceStream in Delphi 2.0. }
function TResourceStream.Write(const Buffer; Count: Longint): Longint;
begin
  raise EStreamError.Create(LoadDelphiString('S_Stream', S_CantWriteResource));
end;

{ Create the illusion that the stream starts at zero and has the
  size of the resource. }
function TResourceStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  case Origin of
  soFromBeginning:
    Result := inherited Seek(fStartPos + Offset, Origin) - fStartPos;
  soFromCurrent:
    Result := inherited Seek(Offset, Origin) - fStartPos;
  soFromEnd:
    Result := inherited Seek(fEndPos + Offset, soFromBeginning) - fStartPos;
  else
    raise EStreamError.Create(LoadDelphiString('S_Stream', S_InvalidOrigin));
  end;
  { Do not allow the user to seek past the end of the resource since that
    is probably the next resource, or worse. }
  if Result > fEndPos then
    raise EStreamError.Create(LoadDelphiString('S_Stream', S_SeekPastEof));
end;
{$endif}

end.
