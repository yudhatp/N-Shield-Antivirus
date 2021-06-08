unit BoyerMoore;

interface

uses
  Windows;

{------------------------------ String Manipulation ---------------------------}
var
  fLockHandle : array of Integer;
type
  TAnsiStrRec = packed record
    AllocSize: Longint;
    RefCount: Longint;
    Length: Longint;
  end;
const
  AnsiStrRecSize  = SizeOf(TAnsiStrRec);
  AnsiCharCount   = Ord(High(Char)) + 1;
  AnsiLoOffset    = AnsiCharCount * 0;
  AnsiUpOffset    = AnsiCharCount * 1;
  AnsiReOffset    = AnsiCharCount * 2;
  AnsiAlOffset    = 12;
  AnsiRfOffset    = 8;
  AnsiLnOffset    = 4;
  AnsiCaseMapSize = AnsiCharCount * 3;
var
  AnsiCaseMap: array [0..AnsiCaseMapSize - 1] of Char; // case mappings

function NShield_BM_SearchString(const Substr, S: string; const Index: Integer): Integer; assembler;
  
implementation

function NShield_BM_SearchString(const Substr, S: string; const Index: Integer): Integer; assembler;
asm
    // make sure that strings are not null
    TEST    EAX, EAX
    JZ      @@SubstrIsNull

    TEST    EDX, EDX
    JZ      @@StrIsNull

    // limit index to satisfy 1 <= index, and dec it
    DEC     ECX
    JL      @@IndexIsSmall

    // ebp will hold # of chars in Substr to compare, esi pointer to Str,
    // edi pointer to Substr, ebx primary search char
    PUSH    EBX
    PUSH    ESI
    PUSH    EDI
    PUSH    EBP

    // set the string pointers
    MOV     ESI, EDX
    MOV     EDI, EAX

    // save the (Index - 1) in edx
    MOV     EDX, ECX

    // save the address of Str to compute the result
    PUSH    ESI

    // temporary get the length of Substr and Str
    MOV     EBX, [EDI-AnsiStrRecSize].TAnsiStrRec.Length
    MOV     ECX, [ESI-AnsiStrRecSize].TAnsiStrRec.Length

    // dec the length of Substr because the first char is brought out of it
    DEC     EBX
    JS      @@NotFound

    // # of positions in Str to look at = Length(Str) - Length(Substr) - Index - 2
    SUB     ECX, EBX
    JLE     @@NotFound

    SUB     ECX, EDX
    JLE     @@NotFound

    // point Str to Index'th char
    ADD     ESI, EDX

    // # of chars in Substr to compare
    MOV     EBP, EBX

    // clear EAX & ECX (working regs)
    XOR     EAX, EAX
    XOR     EBX, EBX

    // bring the first char out of the Substr, and
    // point Substr to the next char
    MOV     BL, [EDI]
    INC     EDI

    // jump into the loop
    JMP     @@Find

@@FindNext:

    // update the loop counter and check the end of string.
    // if we reached the end, Substr was not found.
    DEC     ECX
    JL      @@NotFound

@@Find:

    // get current char from the string, and /point Str to the next one.
    MOV     AL, [ESI]
    INC     ESI

    // does current char match primary search char? if not, go back to the main loop
    CMP     AL, BL
    JNE     @@FindNext

    // otherwise compare SubStr
@@Compare:

    // move # of char to compare into edx, edx will be our compare loop counter.
    MOV     EDX, EBP

@@CompareNext:

    // check if we reached the end of Substr. If yes we found it.
    DEC     EDX
    JL      @@Found

    // get last chars from Str and SubStr and compare them,
    // if they don't match go back to out main loop.
    MOV     AL, [EDI+EDX]
    CMP     AL, [ESI+EDX]
    JNE     @@FindNext

    // if they matched, continue comparing
    JMP     @@CompareNext

@@Found:
    // we found it, calculate the result and exit.
    MOV     EAX, ESI
    POP     ESI
    SUB     EAX, ESI

    POP     EBP
    POP     EDI
    POP     ESI
    POP     EBX
    RET

@@NotFound:
    // not found it, clear result and exit.
    XOR     EAX, EAX
    POP     ESI
    POP     EBP
    POP     EDI
    POP     ESI
    POP     EBX
    RET

@@IndexIsSmall:
@@StrIsNull:
    // clear result and exit.
    XOR     EAX, EAX

@@SubstrIsNull:
@@Exit:
end;

end.
