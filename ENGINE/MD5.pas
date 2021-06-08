unit MD5;

interface

uses Windows, SysUtils, Classes, EHeader;

const
  S11 = 7;
  S12 = 12;
  S13 = 17;
  S14 = 22;
  S21 = 5;
  S22 = 9;
  S23 = 14;
  S24 = 20;
  S31 = 4;
  S32 = 11;
  S33 = 16;
  S34 = 23;
  S41 = 6;
  S42 = 10;
  S43 = 15;
  S44 = 21;
  
type
  PMD5Digest = ^TMD5Digest;
  TMD5Digest = record
    case Integer of
      0: (A, B, C, D: LongInt);
      1: (v: array[0..15] of Byte);
  end;

  UINT4 = LongWord;

  PArray4UINT4 = ^TArray4UINT4;
  TArray4UINT4 = array[0..3] of UINT4;
  PArray2UINT4 = ^TArray2UINT4;
  TArray2UINT4 = array[0..1] of UINT4;
  PArray16Byte = ^TArray16Byte;
  TArray16Byte = array[0..15] of Byte;
  PArray64Byte = ^TArray64Byte;
  TArray64Byte = array[0..63] of Byte;

  PByteArray = ^TByteArray;
  TByteArray = array[0..0] of Byte;

  PUINT4Array = ^TUINT4Array;
  TUINT4Array = array[0..0] of UINT4;

  PMD5Context = ^TMD5Context;
  TMD5Context = record
    state: TArray4UINT4;
    count: TArray2UINT4;
    buffer: TArray64Byte;
  end;

procedure nshieldMD5init(var Context: TMD5Context);
procedure nshieldMD5update(var Context: TMD5Context; Input: PByteArray; InputLen: LongWord);
procedure nshieldMD5final(var Digest: TMD5Digest; var Context: TMD5Context);

function nshieldScanString(const str: widestring): widestring;
function nshieldMD5scan(const filename: widestring): widestring;
function nshieldMD5streamex(const Stream: TStream; sPos, ePos: integer): TMD5Digest;

function nshieldMD5stream(const Stream: TStream): TMD5Digest;
function nshieldMD5buffer(const Buffer; Size: Integer): TMD5Digest;
function nshieldMD5bufferex(const Buffer; Size: Integer): TMD5Digest;
function nshieldMD5digest2str(const Digest: TMD5Digest): string;

implementation

var
    Padding: TArray64Byte =
    ($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

function _F(x, y, z: UINT4): UINT4; assembler;
asm
    and   edx,eax
    not   eax
    and   eax,ecx
    or    eax,edx
end;

function _G(x, y, z: UINT4): UINT4; assembler;
asm
    push  ecx
    and   ecx,eax
    and   eax,edx
    or    eax,ecx
    pop   ecx
    not   ecx
    and   edx,ecx
    or    eax,edx
end;

function _H(x, y, z: UINT4): UINT4; assembler;
asm
    xor eax,edx
    xor eax,ecx
end;

function _I(x, y, z: UINT4): UINT4; assembler;
asm
    not   ecx
    or    eax,ecx
    xor   eax,edx
end;

Function ROTATE_LEFT(A: Longint; Amount: BYTE): Longint; Assembler;
asm
    mov cl, Amount
    rol eax, cl
end;

procedure FF(var a: UINT4; b, c, d, x, s, ac: UINT4);
begin
    a := a + _F(b, c, d) + x + ac;
    a := ROTATE_LEFT(a, s);
    a := a + b;
end;

procedure GG(var a: UINT4; b, c, d, x, s, ac: UINT4);
begin
    a := a + _G(b, c, d) + x + ac;
    a := ROTATE_LEFT(a, s);
    a := a + b;
end;

procedure HH(var a: UINT4; b, c, d, x, s, ac: UINT4);
begin
    a := a + _H(b, c, d) + x + ac;
    a := ROTATE_LEFT(a, s);
    a := a + b;
end;

procedure II(var a: UINT4; b, c, d, x, s, ac: UINT4);
begin
    a := a + _I(b, c, d) + x + ac;
    a := ROTATE_LEFT(a, s);
    a := a + b;
end;

procedure MD5Encode(Output: PByteArray; Input: PUINT4Array; Len: LongWord);
var
    i, j: LongWord;
begin
    j := 0;
    i := 0;
    while j < Len do
    begin
        output[j] := Byte(input[i] and $FF);
        output[j + 1] := Byte((input[i] shr 8) and $FF);
        output[j + 2] := Byte((input[i] shr 16) and $FF);
        output[j + 3] := Byte((input[i] shr 24) and $FF);
        Inc(j, 4);
        Inc(i);
    end;
end;

procedure MD5Decode(Output: PUINT4Array; Input: PByteArray; Len: LongWord);
var
    i, j: LongWord;
begin
    j := 0;
    i := 0;
    while j < Len do
    begin
        Output[i] := UINT4(input[j]) or (UINT4(input[j + 1]) shl 8) or
        (UINT4(input[j + 2]) shl 16) or (UINT4(input[j + 3]) shl 24);
        Inc(j, 4);
        Inc(i);
    end;
end;

procedure MD5_memcpy(Output: PByteArray; Input: PByteArray; Len: LongWord);
begin
    Move(Input^, Output^, Len);
end;

procedure MD5_memset(Output: PByteArray; Value: Integer; Len: LongWord);
begin
    FillChar(Output^, Len, Byte(Value));
end;

Procedure MD5Transform (Accu: PArray4UINT4; Const Buf: PArray64Byte);
Asm
    Push EBx;
    Push ESi;
    Push EDi;
    Push EBp
    Mov EBp,EDx ;
    Push EAx ;
    Mov EDx,[EAx+12];
    Mov ECx,[EAx+8];
    Mov EBx,[EAx+4];
    Mov EAx,[EAx]
    Add EAx,[EBp+0];Add EAx,$D76AA478;Mov ESi,EBx;Not ESi;And ESi,EDx;Mov EDi,ECx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,7;Add EAx,EBx
    Add EDx,[EBp+4];Add EDx,$E8C7B756;Mov ESi,EAx;Not ESi;And ESi,ECx;Mov EDi,EBx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,12;Add EDx,EAx
    Add ECx,[EBp+8];Add ECx,$242070DB;Mov ESi,EDx;Not ESi;And ESi,EBx;Mov EDi,EAx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,17;Add ECx,EDx
    Add EBx,[EBp+12];Add EBx,$C1BDCEEE;Mov ESi,ECx;Not ESi;And ESi,EAx;Mov EDi,EDx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,22;Add EBx,ECx
    Add EAx,[EBp+16];Add EAx,$F57C0FAF;Mov ESi,EBx;Not ESi;And ESi,EDx;Mov EDi,ECx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,7;Add EAx,EBx
    Add EDx,[EBp+20];Add EDx,$4787C62A;Mov ESi,EAx;Not ESi;And ESi,ECx;Mov EDi,EBx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,12;Add EDx,EAx
    Add ECx,[EBp+24];Add ECx,$A8304613;Mov ESi,EDx;Not ESi;And ESi,EBx;Mov EDi,EAx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,17;Add ECx,EDx
    Add EBx,[EBp+28];Add EBx,$FD469501;Mov ESi,ECx;Not ESi;And ESi,EAx;Mov EDi,EDx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,22;Add EBx,ECx
    Add EAx,[EBp+32];Add EAx,$698098D8;Mov ESi,EBx;Not ESi;And ESi,EDx;Mov EDi,ECx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,7;Add EAx,EBx
    Add EDx,[EBp+36];Add EDx,$8B44F7AF;Mov ESi,EAx;Not ESi;And ESi,ECx;Mov EDi,EBx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,12;Add EDx,EAx
    Add ECx,[EBp+40];Add ECx,$FFFF5BB1;Mov ESi,EDx;Not ESi;And ESi,EBx;Mov EDi,EAx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,17;Add ECx,EDx
    Add EBx,[EBp+44];Add EBx,$895CD7BE;Mov ESi,ECx;Not ESi;And ESi,EAx;Mov EDi,EDx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,22;Add EBx,ECx
    Add EAx,[EBp+48];Add EAx,$6B901122;Mov ESi,EBx;Not ESi;And ESi,EDx;Mov EDi,ECx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,7;Add EAx,EBx
    Add EDx,[EBp+52];Add EDx,$FD987193;Mov ESi,EAx;Not ESi;And ESi,ECx;Mov EDi,EBx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,12;Add EDx,EAx
    Add ECx,[EBp+56];Add ECx,$A679438E;Mov ESi,EDx;Not ESi;And ESi,EBx;Mov EDi,EAx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,17;Add ECx,EDx
    Add EBx,[EBp+60];Add EBx,$49B40821;Mov ESi,ECx;Not ESi;And ESi,EAx;Mov EDi,EDx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,22;Add EBx,ECx
    Add EAx,[EBp+4];Add EAx,$F61E2562;Mov ESi,EDx;Not ESi;And ESi,ECx;Mov EDi,EDx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,5;Add EAx,EBx
    Add EDx,[EBp+24];Add EDx,$C040B340;Mov ESi,ECx;Not ESi;And ESi,EBx;Mov EDi,ECx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,9;Add EDx,EAx
    Add ECx,[EBp+44];Add ECx,$265E5A51;Mov ESi,EBx;Not ESi;And ESi,EAx;Mov EDi,EBx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,14;Add ECx,EDx
    Add EBx,[EBp+0];Add EBx,$E9B6C7AA;Mov ESi,EAx;Not ESi;And ESi,EDx;Mov EDi,EAx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,20;Add EBx,ECx
    Add EAx,[EBp+20];Add EAx,$D62F105D;Mov ESi,EDx;Not ESi;And ESi,ECx;Mov EDi,EDx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,5;Add EAx,EBx
    Add EDx,[EBp+40];Add EDx,$2441453;Mov ESi,ECx;Not ESi;And ESi,EBx;Mov EDi,ECx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,9;Add EDx,EAx
    Add ECx,[EBp+60];Add ECx,$D8A1E681;Mov ESi,EBx;Not ESi;And ESi,EAx;Mov EDi,EBx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,14;Add ECx,EDx
    Add EBx,[EBp+16];Add EBx,$E7D3FBC8;Mov ESi,EAx;Not ESi;And ESi,EDx;Mov EDi,EAx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,20;Add EBx,ECx
    Add EAx,[EBp+36];Add EAx,$21E1CDE6;Mov ESi,EDx;Not ESi;And ESi,ECx;Mov EDi,EDx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,5;Add EAx,EBx
    Add EDx,[EBp+56];Add EDx,$C33707D6;Mov ESi,ECx;Not ESi;And ESi,EBx;Mov EDi,ECx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,9;Add EDx,EAx
    Add ECx,[EBp+12];Add ECx,$F4D50D87;Mov ESi,EBx;Not ESi;And ESi,EAx;Mov EDi,EBx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,14;Add ECx,EDx
    Add EBx,[EBp+32];Add EBx,$455A14ED;Mov ESi,EAx;Not ESi;And ESi,EDx;Mov EDi,EAx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,20;Add EBx,ECx
    Add EAx,[EBp+52];Add EAx,$A9E3E905;Mov ESi,EDx;Not ESi;And ESi,ECx;Mov EDi,EDx;And EDi,EBx;Or ESi,EDi;Add EAx,ESi;Rol EAx,5;Add EAx,EBx
    Add EDx,[EBp+8];Add EDx,$FCEFA3F8;Mov ESi,ECx;Not ESi;And ESi,EBx;Mov EDi,ECx;And EDi,EAx;Or ESi,EDi;Add EDx,ESi;Rol EDx,9;Add EDx,EAx
    Add ECx,[EBp+28];Add ECx,$676F02D9;Mov ESi,EBx;Not ESi;And ESi,EAx;Mov EDi,EBx;And EDi,EDx;Or ESi,EDi;Add ECx,ESi;Rol ECx,14;Add ECx,EDx
    Add EBx,[EBp+48];Add EBx,$8D2A4C8A;Mov ESi,EAx;Not ESi;And ESi,EDx;Mov EDi,EAx;And EDi,ECx;Or ESi,EDi;Add EBx,ESi;Rol EBx,20;Add EBx,ECx
    Add EAx,[EBp+20];Add EAx,$FFFA3942;Mov ESi,EDx;Xor ESi,ECx;Xor ESi,EBx;Add EAx,ESi;Rol EAx,4;Add EAx,EBx
    Add EDx,[EBp+32];Add EDx,$8771F681;Mov ESi,ECx;Xor ESi,EBx;Xor ESi,EAx;Add EDx,ESi;Rol EDx,11;Add EDx,EAx
    Add ECx,[EBp+44];Add ECx,$6D9D6122;Mov ESi,EBx;Xor ESi,EAx;Xor ESi,EDx;Add ECx,ESi;Rol ECx,16;Add ECx,EDx
    Add EBx,[EBp+56];Add EBx,$FDE5380C;Mov ESi,EAx;Xor ESi,EDx;Xor ESi,ECx;Add EBx,ESi;Rol EBx,23;Add EBx,ECx
    Add EAx,[EBp+4];Add EAx,$A4BEEA44;Mov ESi,EDx;Xor ESi,ECx;Xor ESi,EBx;Add EAx,ESi;Rol EAx,4;Add EAx,EBx
    Add EDx,[EBp+16];Add EDx,$4BDECFA9;Mov ESi,ECx;Xor ESi,EBx;Xor ESi,EAx;Add EDx,ESi;Rol EDx,11;Add EDx,EAx
    Add ECx,[EBp+28];Add ECx,$F6BB4B60;Mov ESi,EBx;Xor ESi,EAx;Xor ESi,EDx;Add ECx,ESi;Rol ECx,16;Add ECx,EDx
    Add EBx,[EBp+40];Add EBx,$BEBFBC70;Mov ESi,EAx;Xor ESi,EDx;Xor ESi,ECx;Add EBx,ESi;Rol EBx,23;Add EBx,ECx
    Add EAx,[EBp+52];Add EAx,$289B7EC6;Mov ESi,EDx;Xor ESi,ECx;Xor ESi,EBx;Add EAx,ESi;Rol EAx,4;Add EAx,EBx
    Add EDx,[EBp+0];Add EDx,$EAA127FA;Mov ESi,ECx;Xor ESi,EBx;Xor ESi,EAx;Add EDx,ESi;Rol EDx,11;Add EDx,EAx
    Add ECx,[EBp+12];Add ECx,$D4EF3085;Mov ESi,EBx;Xor ESi,EAx;Xor ESi,EDx;Add ECx,ESi;Rol ECx,16;Add ECx,EDx
    Add EBx,[EBp+24];Add EBx,$4881D05;Mov ESi,EAx;Xor ESi,EDx;Xor ESi,ECx;Add EBx,ESi;Rol EBx,23;Add EBx,ECx
    Add EAx,[EBp+36];Add EAx,$D9D4D039;Mov ESi,EDx;Xor ESi,ECx;Xor ESi,EBx;Add EAx,ESi;Rol EAx,4;Add EAx,EBx
    Add EDx,[EBp+48];Add EDx,$E6DB99E5;Mov ESi,ECx;Xor ESi,EBx;Xor ESi,EAx;Add EDx,ESi;Rol EDx,11;Add EDx,EAx
    Add ECx,[EBp+60];Add ECx,$1FA27CF8;Mov ESi,EBx;Xor ESi,EAx;Xor ESi,EDx;Add ECx,ESi;Rol ECx,16;Add ECx,EDx
    Add EBx,[EBp+8];Add EBx,$C4AC5665;Mov ESi,EAx;Xor ESi,EDx;Xor ESi,ECx;Add EBx,ESi;Rol EBx,23;Add EBx,ECx
    Add EAx,[EBp+0];Add EAx,$F4292244;Mov ESi,EDx;Not ESi;Or ESi,EBx;Xor ESi,ECx;Add EAx,ESi;Rol EAx,6;Add EAx,EBx
    Add EDx,[EBp+28];Add EDx,$432AFF97;Mov ESi,ECx;Not ESi;Or ESi,EAx;Xor ESi,EBx;Add EDx,ESi;Rol EDx,10;Add EDx,EAx
    Add ECx,[EBp+56];Add ECx,$AB9423A7;Mov ESi,EBx;Not ESi;Or ESi,EDx;Xor ESi,EAx;Add ECx,ESi;Rol ECx,15;Add ECx,EDx
    Add EBx,[EBp+20];Add EBx,$FC93A039;Mov ESi,EAx;Not ESi;Or ESi,ECx;Xor ESi,EDx;Add EBx,ESi;Rol EBx,21;Add EBx,ECx
    Add EAx,[EBp+48];Add EAx,$655B59C3;Mov ESi,EDx;Not ESi;Or ESi,EBx;Xor ESi,ECx;Add EAx,ESi;Rol EAx,6;Add EAx,EBx
    Add EDx,[EBp+12];Add EDx,$8F0CCC92;Mov ESi,ECx;Not ESi;Or ESi,EAx;Xor ESi,EBx;Add EDx,ESi;Rol EDx,10;Add EDx,EAx
    Add ECx,[EBp+40];Add ECx,$FFEFF47D;Mov ESi,EBx;Not ESi;Or ESi,EDx;Xor ESi,EAx;Add ECx,ESi;Rol ECx,15;Add ECx,EDx
    Add EBx,[EBp+4];Add EBx,$85845DD1;Mov ESi,EAx;Not ESi;Or ESi,ECx;Xor ESi,EDx;Add EBx,ESi;Rol EBx,21;Add EBx,ECx
    Add EAx,[EBp+32];Add EAx,$6FA87E4F;Mov ESi,EDx;Not ESi;Or ESi,EBx;Xor ESi,ECx;Add EAx,ESi;Rol EAx,6;Add EAx,EBx
    Add EDx,[EBp+60];Add EDx,$FE2CE6E0;Mov ESi,ECx;Not ESi;Or ESi,EAx;Xor ESi,EBx;Add EDx,ESi;Rol EDx,10;Add EDx,EAx
    Add ECx,[EBp+24];Add ECx,$A3014314;Mov ESi,EBx;Not ESi;Or ESi,EDx;Xor ESi,EAx;Add ECx,ESi;Rol ECx,15;Add ECx,EDx
    Add EBx,[EBp+52];Add EBx,$4E0811A1;Mov ESi,EAx;Not ESi;Or ESi,ECx;Xor ESi,EDx;Add EBx,ESi;Rol EBx,21;Add EBx,ECx
    Add EAx,[EBp+16];Add EAx,$F7537E82;Mov ESi,EDx;Not ESi;Or ESi,EBx;Xor ESi,ECx;Add EAx,ESi;Rol EAx,6;Add EAx,EBx
    Add EDx,[EBp+44];Add EDx,$BD3AF235;Mov ESi,ECx;Not ESi;Or ESi,EAx;Xor ESi,EBx;Add EDx,ESi;Rol EDx,10;Add EDx,EAx
    Add ECx,[EBp+8];Add ECx,$2AD7D2BB;Mov ESi,EBx;Not ESi;Or ESi,EDx;Xor ESi,EAx;Add ECx,ESi;Rol ECx,15;Add ECx,EDx
    Add EBx,[EBp+36];Add EBx,$EB86D391;Mov ESi,EAx;Not ESi;Or ESi,ECx;Xor ESi,EDx;Add EBx,ESi;Rol EBx,21;Add EBx,ECx
    Pop ESi;
    Add [ESi],EAx;
    Add [ESi+4],EBx;
    Add [ESi+8],ECx;
    Add [ESi+12],EDx;
    Pop EBp;
    Pop EDi;
    Pop ESi;
    Pop EBx
end;

procedure nshieldMD5init(var Context: TMD5Context);
begin
    FillChar(Context, SizeOf(Context), 0);
    Context.state[0] := $67452301;
    Context.state[1] := $EFCDAB89;
    Context.state[2] := $98BADCFE;
    Context.state[3] := $10325476;
end;

procedure nshieldMD5update(var Context: TMD5Context; Input: PByteArray; InputLen: LongWord);
var
    i, index, partLen: LongWord;
begin
    index := LongWord((context.count[0] shr 3) and $3F);
    Inc(Context.count[0], UINT4(InputLen) shl 3);
    if Context.count[0] < UINT4(InputLen) shl 3 then
        Inc(Context.count[1]);

    Inc(Context.count[1], UINT4(InputLen) shr 29);
    partLen := 64 - index;

    if inputLen >= partLen then
    begin
        MD5_memcpy(PByteArray(@Context.buffer[index]), Input, PartLen);
        MD5Transform(@Context.state, @Context.buffer);
        i := partLen;
        while i + 63 < inputLen do
        begin
            MD5Transform(@Context.state, PArray64Byte(@Input[i]));
            Inc(i, 64);
        end;
        index := 0;
    end else
        i := 0;

    MD5_memcpy(PByteArray(@Context.buffer[index]), PByteArray(@Input[i]), inputLen - i);
end;

procedure nshieldMD5final(var Digest: TMD5Digest; var Context: TMD5Context);
var
    bits: array[0..7] of Byte;
    index, padLen: LongWord;
begin
    MD5Encode(PByteArray(@bits), PUINT4Array(@Context.count), 8);
    index := LongWord((Context.count[0] shr 3) and $3F);
    if index < 56 then
        padLen := 56 - index
    else
        padLen := 120 - index;
        
    nshieldMD5update(Context, PByteArray(@PADDING), padLen);
    nshieldMD5update(Context, PByteArray(@Bits), 8);
    MD5Encode(PByteArray(@Digest), PUINT4Array(@Context.state), 16);
    MD5_memset(PByteArray(@Context), 0, SizeOf(Context));
end;

function nshieldMD5digest2str(const Digest: TMD5Digest): string;
var
    i: Integer;
begin
    Result := '';
    for i := 0 to 15 do
        Result := Result + IntToHex(Digest.v[i], 2);
end;

function nshieldScanString(const str: widestring): widestring stdcall;
var
    ptr: string;
    ret: string;
begin
    ptr := str;
    ret := lowercase(nshieldMD5digest2str(nshieldMD5bufferex(PChar(ptr)^, length(ptr))));

    Result := ret;
end;

function nshieldMD5scan(const filename: widestring): widestring stdcall;
var
    FS : TFileStream;
    D: TMD5Digest;
    ret: string;
begin
    ret := '';
    if not FileExists(FileName) then exit;
    try
        FS := TFileStream.Create(filename, fmShareDenyNone);
        D := nshieldMD5stream(FS);
        ret := lowercase(nshieldMD5digest2str(D));
        result := ret;
        FS.Free;
    except
    end;
end;

function nshieldMD5stream(const Stream: TStream): TMD5Digest;
var
    Context: TMD5Context;
    Buffer: array[1..8192] of Byte;
    Size: Integer;
    ReadBytes: Integer;
    TotalBytes: Integer;
    SavePos: Integer;
begin
    nshieldMD5init(Context);
    Size := Stream.Size;
    SavePos := Stream.Position;
    TotalBytes := 0;
    try
        Stream.Seek(0, soFromBeginning);
        repeat
            ReadBytes := Stream.Read(Buffer, SizeOf(Buffer));
            Inc(TotalBytes, ReadBytes);
            nshieldMD5update(Context, @Buffer, ReadBytes);
        until (ReadBytes = 0) or (TotalBytes = Size);
    finally
        Stream.Seek(SavePos, soFromBeginning);
    end;
    nshieldMD5final(Result, Context);
end;

function nshieldMD5streamex(const Stream: TStream; sPos, ePos: integer): TMD5Digest;
var
    Context: TMD5Context;
    Buffer: array[1..8192] of char;
    Size: Integer;
    ReadBytes: Integer;
    TotalBytes: Integer;
    SavePos: Integer;
begin
    nshieldMD5init(Context);
    Size := Stream.Size;
    SavePos := Stream.Position;
    TotalBytes := 0;
    try
        Stream.Seek(sPos, soFromBeginning);
        repeat
            ReadBytes := Stream.Read(Buffer[1], SizeOf(Buffer));

            Inc(TotalBytes, ReadBytes);

            if stream.position > ePos then begin
                ReadBytes := readbytes - (TotalBytes - (ePos - sPos));
                TotalBytes := ePos - sPos;
            end;

            nshieldMD5update(Context, @Buffer, ReadBytes);
        until (ReadBytes = 0) or (TotalBytes = ePos - sPos) ;
    finally
        Stream.Seek(SavePos, soFromBeginning);
    end;
    nshieldMD5final(Result, Context);
    Stream.Seek(0, soFromBeginning);
end;

function nshieldMD5buffer(const Buffer; Size: Integer): TMD5Digest;
var
    Context: TMD5Context;
begin
    nshieldMD5init(Context);
//  xc_md5update(Context, PByteArray(@Buffer), Size);
    nshieldMD5update(Context, PByteArray(Buffer), Size);
    nshieldMD5final(Result, Context);
end;

function nshieldMD5bufferex(const Buffer; Size: Integer): TMD5Digest;
var
    Context: TMD5Context;
begin
    nshieldMD5init(Context);
    nshieldMD5update(Context, PByteArray(@Buffer), Size);
    nshieldMD5final(Result, Context);
end;

end.
