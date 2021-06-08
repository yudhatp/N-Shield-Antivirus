{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: UZTypes.pas                                                       }
{     Description: VCLUnZip component - native Delphi unzip component.               }
{     Date:        March 1997                                                        }
{     Author:      Kevin Boylan, CIS: boylank                                        }
{                                Internet: boylank@compuserve.com                    }
{                                                                                    }
{ ********************************************************************************** }

type

{ UNZIP }
  CharArrayPtr = ^CharArray;
  CharArray = array[0..MaxInt-1] of Char;
  ByteArrayPtr = ^ByteArray;
  ByteArray = array[0..MaxInt-1] of Byte;
  IntegerArrayPtr = ^IntegerArray;
  IntegerArray = array[0..MAX_SHORT-1] of Integer;
  IntPtr = ^Integer;
	BYTEPTR = PByte;
  WORDPTR = ^WORD;
	shortint = smallint;
  ULONG = LongInt;
  shrinktype = packed Record
     Prefix_of: array [0..HSIZE+2] of shortint;
     Suffix_of: array [0..HSIZE+2] of Byte;
     Stack    : array [0..HSIZE+2] of Byte;
  end;
  DataDescriptorType = packed Record
     Sig:     LongInt;
     crc32:   LongInt;
     compressed_size: LongInt;
     uncompressed_size: LongInt;
  end;

{$IFNDEF INFLATE_ONLY}
{ UNSHRINK }
{ EXPLODE }
{ UNREDUCE }
	f_array = array[0..255,0..63] of Byte;
{$ENDIF}

{ INFLATE }
	huftptr = ^huft;
  huftptrptr = ^huftptr;
  huftarrayptr = ^huftarray;
  huft = packed Record
  	e:		Byte;
     b:		Byte;
		v:		Record
  				case Integer of
     				0: (  n:		WORD );
     				1: (  t:		huftptr );
  			end;
  end;
  huftarray = packed array[-1..1000] of huft;
	llarrayptr = ^llarraytype;
	llarraytype = packed array [0..(286+30-1)] of WORD;

{ FILE }

	slidearray = array [0..WSIZE-1] of byte;
  slidearrayptr = ^slidearray;
  work = packed Record
     case Integer of
     	0: (  shrink: shrinktype );
     	1: (	Slide: slidearray);
   end;
	pString	= ^String;
  ppString = ^pString;
  TZipFilename = String; {[FILENAME_LEN]; }
	TZipPathname = String; {[PATH_LEN]; }

  TMultiMode = (mmNone, mmSpan, mmBlocks);
  TIncompleteZipMode = (izAssumeMulti, izAssumeBad);
  TUZOverwriteMode = (Prompt, Always, Never);
  TSkipReason = (srBadPassword, srNoOverwrite);

  {Decryption}

  DecryptKey = array[0..2] of LongInt;
  DecryptHeaderType = array[0..11] of BYTE;

  { Exceptions }
	EBadZipFile = class(Exception);
  EFileNotAllThere = Class( Exception );
  EIncompleteZip = class( Exception );
	EFatalUnzipError = class( Exception );
	EUserCanceled = class( Exception );
  EInvalidPassword = class( Exception );

   { Event types }

 TStartUnzipInfo = procedure( Sender: TObject; NumFiles: Integer;
 											TotalBytes: Comp; var StopNow: Boolean ) of Object;
 TStartUnZipEvent = procedure( Sender: TObject; FileIndex: Integer;
                                FName: String; var Skip: Boolean ) of Object;
 TEndUnZipEvent = procedure( Sender: TObject; FileIndex: Integer; FName: String ) of Object;
 TFilePercentDone = procedure( Sender: TObject; Percent: LongInt ) of Object;
 TTotalPercentDone = procedure( Sender: TObject; Percent: LongInt ) of Object;
 TPromptForOverwrite = procedure( Sender: TObject; var OverWriteIt: Boolean;
 						FileIndex: Integer; var FName: String ) of Object;
 TSkippingFile = procedure( Sender: TObject; Reason: TSkipReason;
 												 FileIndex: Integer ) of Object;
 TBadPassword = procedure( Sender: TObject; FileIndex: Integer; var NewPassword: String ) of Object;
 TBadCRC = procedure(Sender: TObject; CalcCRC, StoredCRC: LongInt;
 								FileIndex: Integer ) of Object;
 TIncompleteZip = procedure(Sender: TObject; var IncompleteMode: TIncompleteZipMode ) of Object;
 TGetNextDisk = procedure(Sender: TObject; NextDisk: Integer; var FName: String ) of Object;
 TNewDiskEvent = procedure(Sender: TObject; var S: TStream) of Object;
