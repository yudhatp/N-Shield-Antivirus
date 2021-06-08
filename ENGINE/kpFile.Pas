{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: File.pas                                                          }
{     Description: VCLUnZip component - native Delphi unzip component.               }
{     Date:        March 1997                                                        }
{     Author:      Kevin Boylan, boylank@bigfoot.com                                 }
{                                                                                    }
{                                                                                    }
{ ********************************************************************************** }
{$Q-} { turn off overflow checking }
{$R-} { turn off range checking }

function FlushOutput: WORD;
var
	len: WORD;
  Percent: LongInt;
  debugret: LongInt;
begin
	if (outcnt <> 0) then
	 begin
		len := outcnt;
		debugret := zip_out_file.Write( outbuf^, len );
     Update_CRC_buff( outbuf, len );
		Inc(outpos, outcnt);
     if Assigned(FOnFilePercentDone) then
      begin
        Percent := CRate( file_info.uncompressed_size, outpos );
			{Percent := min(((outpos * 100) div file_info.uncompressed_size), 100 ); }
        FOnFilePercentDone( self, Percent );
      end;
     if Assigned(FOnTotalPercentDone) then
      begin
        TotalBytesDone := TotalBytesDone + outcnt;
     	{Inc(TotalBytesDone, outcnt);}
        Percent := CBigRate( TotalUncompressedSize, TotalBytesDone );
			{Percent := min(((TotalBytesDone * 100) div TotalUncompressedSize), 100 );}
        FOnTotalPercentDone( self, Percent );
      end;
    	outcnt := 0;
		outptr := outbuf;
	 end;
	Result := 0;
end;

function ReadByte( var x: WORD ): Integer;
var
	number_to_read, number_read: Integer;
  tmpbuf: BYTEPTR;
begin
  If csize <= 0 then
   begin
  	Dec(csize);
  	Result := 0;
     exit;
   end;
  Dec(csize);
  If incnt = 0 then
   begin
     If DoProcessMessages then
      begin
//        Application.ProcessMessages;
        If CancelOperation then
         begin
           CancelOperation := False;
           raise EUserCanceled.Create('User Aborted Operation');
         end;
      end;
   	number_to_read := min( file_info.compressed_size, LongInt(INBUFSIZ) );
     file_info.compressed_size := file_info.compressed_size - number_to_read;
     number_read := zip_in_file.Read( inbuf^, number_to_read );
     incnt := number_read;
     If (((ecrec.this_disk = 0) or (not (Assigned(FOnGetNextDisk))))
        and (incnt < number_to_read)) then
           raise EFatalUnzipError.Create('Premature end of file reached');
     tmpbuf := inbuf;
     While (incnt < number_to_read) do  {2/1/98 Changed If to While}
      begin
        zip_in_file := SwapDisk( CurrentDisk+2 );
        If zip_in_file = nil then  {2/1/98}
           raise EUserCanceled.Create('User Aborted Operation');
        Inc(tmpbuf,number_read);
        number_read := zip_in_file.Read( tmpbuf^, number_to_read-incnt );
        Inc(incnt, number_read);
      end;
     If file_info.Encrypted then
     	decrypt_buff( inbuf, number_to_read );
     { Cant do the following to a property}
     {Dec(file_info.compressed_size, number_to_read);}
     If incnt <= 0 then
      begin
     	Result := 0;
        exit;
      end;
    	inptr := inbuf;
   end;
 	x := inptr^;
  Inc(inptr);
  Dec(incnt);
  Result := 8;
end;

function FillBitBuffer: Integer;
var
	temp: WORD;
begin
	zipeof := True;
  while (bits_left < 25) and (ReadByte(temp) = 8) do
   begin
   	bitbuf := bitbuf or LongInt((LongInt(temp) shl bits_left));
     Inc(bits_left, 8);
     zipeof := False;
   end;
   Result := 0;
end;

{ MACRO'S}
procedure OUTB( intc: BYTE );
begin
	outptr^ := intc;
  Inc(outptr);
  Inc(outcnt);
  If outcnt = OUTBUFSIZ then
  	FlushOutput
end;

procedure READBIT( nbits: WORD; var zdest: shortint );
begin
	if nbits > bits_left then
  	FillBitBuffer;
  zdest :=  shortint(WORD(bitbuf) and mask_bits[nbits]);
  bitbuf := LongInt(bitbuf shr nbits);
  Dec(bits_left, nbits);
end;

procedure NEEDBITS(n: WORD; var b: ULONG; var k: WORD);
begin
	while (k < n) do
   begin
   	ReadByte(bytebuf);
   	b := b or ULONG((ULONG(bytebuf) shl k));
     Inc(k,8);
   end;
end;

procedure DUMPBITS( n: WORD; var b: ULONG; var k: WORD );
begin
	b := ULONG(b shr n);
  Dec(k,n);
end;


