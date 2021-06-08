unit kpStrRes;

{ Secrets of Delphi 2, by Ray Lischner. (1996, Waite Group Press).
  Chapter 2: Components and Properties.
  Copyright © 1996 The Waite Group, Inc. }

{ Delphi String Resource }
interface

uses
{$IFDEF WIN32}
  Windows,
{$ELSE}
  WinTypes,
{$ENDIF}
  Classes, SysUtils, kpSStrng;

type
  { Each resource is stored in a string record. }
  PS_StringRec = ^TS_StringRec;
  TS_StringRec = record
    Ident: SmallInt;
    Str: ShortString;
  end;

  { A TS_StringResource object represents an S_StringTable resource.
    The resource contains a packed list of TS_StringRec objects. }
  TS_StringResource = class
  private
    fHandle: THandle;
    fData: PS_StringRec;
  protected
    function NextRecord(StringRec: PS_StringRec): PS_StringRec; virtual;
    function FindString(Ident: Integer): PS_StringRec; virtual;
    function GetString(Ident: Integer): string;
    procedure Load(const ResourceName: string); virtual;
    procedure Unload; virtual;
    procedure Lock; virtual;
    procedure Unlock; virtual;
    property ResHandle: THandle read fHandle;
    property FirstRecord: PS_StringRec read fData;
  public
    constructor Create(const ResourceName: string); virtual;
    destructor Destroy; override;
    property Strings[Ident: Integer]: string read GetString; default;
  end;

{ Resource type for Delphi string tables. }
const
  S_ResourceType = 'S_StringTable';

{ Load a string from a Delphi String resource. }
function LoadDelphiString(const Name: string; Ident: Integer): string;

implementation

uses
{$IFNDEF WIN32}
  WinProcs,
{$ENDIF}
  {Controls, }kpSConst;

{ Note that errors in the string table loader must use
  traditional string resources. The S_Consts.res file
  contains the string table resource. If there are
  resource ID conflicts, then change the S_Consts.pas
  unit and the S_Consts.res file. }
  
{ Load a Delphi string resource. }
procedure TS_StringResource.Load(const ResourceName: string);
var
  ResInfo: THandle;
begin
  ResInfo := FindResource(hInstance, StrToPChar(ResourceName), S_ResourceType);

  if ResInfo = 0 then
    raise Exception.CreateResFmt(S_NoSuchResource, [ResourceName]);

  fHandle := LoadResource(hInstance, ResInfo);
  if fHandle = 0 then
    raise EOutOfResources.CreateRes(S_CannotLoadResource);
end;

{ Unload the resource when it is no longer needed. }
procedure TS_StringResource.Unload;
begin
  while fData <> nil do
    Unlock;
  if fHandle <> 0 then
    FreeResource(fHandle);
  fHandle := 0;
end;

{ Before accessing the data, lock the resource in memory. }
procedure TS_StringResource.Lock;
begin
  fData := LockResource(fHandle);
  if fData = nil then
    raise EOutOfResources.CreateRes(S_CannotLockResource);
end;

{ Unlock the data and set the pointer to nil if the lock count is zero. }
procedure TS_StringResource.Unlock;
begin
  if not UnlockResource(fHandle) then
    fData := nil;
end;

{ Create and initialize the string resource object. }
constructor TS_StringResource.Create(const ResourceName: string);
begin
  inherited Create;
  if ResourceName <> '' then
    Load(ResourceName);
end;

{ Destroy the string resource. }
destructor TS_StringResource.Destroy;
begin
  Unload;
  inherited Destroy;
end;

{ Get the string identified by Ident, or return an empty string. }
function TS_StringResource.GetString(Ident: Integer): string;
var
  StringRec: PS_StringRec;
begin
  Lock;
  try
    StringRec := FindString(Ident);
    if StringRec = nil then
      Result := ''
    else
      Result := StringRec^.Str;
  finally
    Unlock;
  end;
end;

{ Locate the string identified by Ident. }
function TS_StringResource.FindString(Ident: Integer): PS_StringRec;
begin
  Result := FirstRecord;
  while (Result <> nil) and (Result^.Ident <> Ident) do
    Result := NextRecord(Result);
end;

{ Get the next record. The records are packed, so advance the pointer
  by the size of the identifier, plus the size of the string. }
function TS_StringResource.NextRecord(StringRec: PS_StringRec): PS_StringRec;
var
  Ptr: PChar;
begin
  Ptr := PChar(StringRec);
  Inc(Ptr, SizeOf(SmallInt) + Length(StringRec^.Str) + 1);
  Result := PS_StringRec(Ptr);
end;

{ Private table of Delphi String resources }
var
  StringTable: TStringList;

{ Load a string from a Delphi String resource. }
function LoadDelphiString(const Name: string; Ident: Integer): string;
var
  Index: Integer;
  Res: TS_StringResource;
begin
  Index := StringTable.IndexOf(Name);
  if Index >= 0 then
    Res := StringTable.Objects[Index] as TS_StringResource
  else
  begin
    Res := TS_StringResource.Create(Name);
    StringTable.AddObject(Name, Res);
  end;
  Result := Res[Ident];
end;

{$IFNDEF WIN32}
procedure Terminate; far;
begin
  StringTable.Free;
end;
{$ENDIF}

initialization
  {$IFNDEF WIN32}
  AddExitProc(Terminate);
  {$ENDIF}
  StringTable := TStringList.Create;
  StringTable.Sorted := True; { for faster searching }

{$IFDEF WIN32}
Finalization
  StringTable.Free;
{$ENDIF}

end.
