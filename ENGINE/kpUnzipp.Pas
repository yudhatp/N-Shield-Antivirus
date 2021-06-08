{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: Unzipp.pas                                                        }
{     Description: VCLUnZip component - native Delphi unzip component.               }
{     Date:        March 1997                                                        }
{     Author:      Kevin Boylan, boylank@bigfoot.com                                 }
{                                                                                    }
{                                                                                    }
{ ********************************************************************************** }

{$Q-} { turn off overflow checking }
{$R-} { turn off range checking }

function TVCLUnZip.UnZipFiles( zip_in_file: TStream ): Integer;
var
	  csize: LongInt;
    ucsize: LongInt;
    area: ^work;
    outcnt: WORD;
    hufts: WORD;
    slide: slidearrayptr;
	  inbuf,
    inptr,
    outbuf,
    outptr: BYTEPTR;
    incnt: WORD;
    bitbuf: LongInt;
    bits_left: WORD;
    zipeof: LongBool;
    outpos: LongInt;
    zip_out_file: TStream;
	  bytebuf: WORD;
    FileCount: Integer;
    RepeatFile: Boolean;

{$I kpFile.Pas}

{****************************************************************************}
function huft_free(t: huftptr): shortint;
var
	p: huftarrayptr;
  q,z:   huftptr;
begin
{ t =  table to free }
{ Free the malloc'ed tables built by huft_build(), which makes a linked
   list of the tables it made, with the links in a dummy first entry of
   each table. }
{ Go through linked lIst, freeing from the malloced (t[-1]) address. }
	z := t;
  while (z <> nil) do
	 begin
  	Dec(z);
  	p := huftarrayptr(z);
		q := z^.v.t;
		StrDispose( PChar(p) );
		{FreeMem(p);}
     z := q;
   end;
  Result := 0;
end;

{****************************************************************************}
function huft_build(b: array of WORD; n,s: WORD; d,e: array of WORD;
							 t:huftptrptr; var m: shortint): shortint;
{	b = 		code lengths in bits (all assumed <= BMAX)	}
{ n =		number of codes (assumed <= N_MAX) 				}
{ s =		number of simple-valued codes (0..s-1) 		}
{ d =		list of base values for non-simple codes 		}
{ e =		list of extra bits for non-simple codes 		}
{ t =		result: starting table 								}
{ m =		maximum lookup bits, returns actual 			}
{ Given a list of code lengths and a maximum table size, make a set of
   tables to decode that set of codes.  Return zero on success, one if
   the given code set is incomplete (the tables are still built in this
   case), two if the input is invalid (all zero length codes or an
   oversubscribed set of lengths), and three if not enough memory. }
var
  a: 	WORD;                   	{ counter for codes of length k }
  c: 	array[0..BMAX] of WORD; 	{ bit length count table }
  f: 	WORD;                   	{ i repeats in table every f entries }
  g:		shortint;                  	{ maximum code length }
  h:		shortint;                 		{ table level }
  i:		WORD;          				{ counter, current code }
  j:		WORD;          				{ counter }
  k:		shortint;               		{ number of bits in current code }
  l:		shortint;                   	{ bits per table (returned in m) }
  p:		Integer;         				{ pointer into c[], b[], or v[] }
  q:		huftarrayptr; 					{ points to current table }
  r:		huft;                		{ table entry for structure assignment }
  u:		array[0..BMAX-1] of huftarrayptr;	{ table stack }
	v:		array[0..N_MAX-1] of WORD; { values in order of bit length }
  w:		shortint;               		{ bits before this table == (l * h) }
  x:		array[0..BMAX] of WORD;  	{ bit offsets, then code stack }
  xp:	Integer;                 	{ pointer into x }
  y:		shortint;                		{ number of dummy codes added }
  z:		WORD;                   	{ number of entries in current table }
begin
  { Generate counts for each bit length }
	ZeroMemory(@c, SizeOf(c));
  p := 0;
  i := n;
  Repeat
    Inc(c[b[p]]);
    Inc(p);
    Dec(i);                  { assume all entries <= BMAX }
  Until (i=0);
  if (c[0] = n) then               { null input--all zero length codes }
   begin
     t^ := nil;
     m := 0;
     Result := 0;
     exit;
   end;

 { Find minimum and maximum length, bound *m by those }
  l := m;
  j := 1;
  while ((j<=BMAX) and (c[j]=0)) do
  	Inc(j);
  k := j;                        { minimum code length }
  if (WORD(l) < j) then
    l := j;
  i := BMAX;
  while ((i>=0) and (c[i]=0)) do
  	Dec(i);
  g := i;                        { maximum code length }
  if (WORD(l) > i) then
    l := i;
  m := l;

  { Adjust last length count to fill out codes, if needed }
  y := shortint(1 shl j);
  while (j<i) do
   begin
   	Dec(y,c[j]);
     if y < 0 then
      begin
      	Result := 2;
        exit;
      end;
   	y := shortint(y shl 1);
     Inc(j);
   end;
  Dec(y,c[i]);
  if y < 0 then
   begin
   	Result := 2;
     exit;
   end;
  Inc(c[i],y);

 { Generate starting offsets into the value table for each length }
  x[1] := 0;
  j := 0;
  p := 1;
  xp := 2;
  Dec(i);
  while (i>0) do                 { note that i == g from above }
   begin
   	Inc(j,c[p]);
     Inc(p);
     x[xp] := j;
     Inc(xp);
    	Dec(i);
   end;

 { Make a table of values in order of bit lengths }
  p := 0;  i := 0;
  Repeat
  	j := b[p];
     Inc(p);
     if (j <> 0) then
      begin
     	v[x[j]] := i;
        Inc(x[j]);
      end;
  	Inc(i);
  Until (i>=n);

  { Generate the Huffman codes and for each, make the table entries }
  x[0] := 0;
  i := 0;                 { first Huffman code is zero }
  p := 0;             { grab values in bit order }
  h := -1;                { no tablEs yet--level -1 }
  w := -l;                { bits decoded == (l * h) }
  u[0] := nil;   			{ just to keep compilers happy }
  q := nil;      			{ ditto }
  z := 0;                 { ditto }

 { go through the bit lengths (k already is bits in shortest code) }
  while ( k <= g ) do
   begin
    	a := c[k];
    	while (a <> 0) do
      begin
     	Dec(a);
      	{ here i is the Huffman code of length k bits for value *p }
      	{ make tables up to required level }
      	while (k > (w + l)) do
         begin
        	Inc(h);
        	Inc(w,l);                 { previous table always l bits }
        	{ compute minimum size table less than or equal to l bits }
           z := g - w;
           if (z > WORD(l)) then
           	z := l;
           j := k - w;
           f := WORD(WORD(1) shl j);
           if (f > (a+1)) then      { too few codes for k-w bit table }
        	 begin
            	Dec(f,(a+1));         { deduct codes from patterns left }
          		xp := k;
              Inc(j);
          		while (j < z) do       { try smaller tables up to z bits }
          		 begin
               	f := WORD(f shl 1);
                 Inc(xp);
                 if (f <= c[xp]) then
              		break;            { enough codes to use up j bits }
            		Dec(f,c[xp]);           { else deduct codes from patterns }
                 Inc(j);
          		 end;
        	 end;
				z := WORD(WORD(1) shl j);             { table entries for j-bit table }

        	{ allocate and link in new table }
				try
					q := huftarrayptr( StrAlloc((z+1)*SizeOf(huft)));
					{GetMem( q, (z+1)*SizeOf(huft));}
				except
           	if (h <> 0) then
               begin
              	huft_free(@u[0]^[0]);
//						Application.MessageBox( '*** inflate out of memory ***','Error',mb_OK );
                 Result := 3;
                 exit;
               end;
           end;

        	Inc(hufts,z + 1);         	{ track memory usage }
        	t^ := @q^[0];
           q^[-1].v.t := nil;
           t := @(q^[-1].v.t);
        	u[h] := @q^[0];             		{ table starts after link }

        	{ connect to last table, if there is one }
        	if (h<>0) then
            begin
         		x[h] := i;             	{ save pattern for backing up }
		  			r.b := BYTE(l);        			{ bits to dump before this table }
		  			r.e := BYTE(16 + j); 			{ bits in this table }
          		r.v.t := @q^[0];         { pointer to this table }
          		j := WORD(i shr (w - l));     { (get around Turbo C bug) }
          		u[h-1]^[j-1] := r;        	{ connect to last table }
         	 end;
         end; { while (a <> 0) do }

      { set up table entry in r }
	  	 r.b := BYTE(k - w);
      if (p >= n) then
        r.e := 99               { out of values--invalid code }
      else if (v[p] < s) then
       begin
       	if v[p] < 256 then   { 256 is end-of-block code }
        	r.e := 16
        else
        	r.e := 15;
        r.v.n := v[p];           { simple code is just the value }
        Inc(p);
       end
      else
       begin
        If v[p]-s < N_MAX then
         begin
			   r.e := BYTE(e[v[p] - s]);  { non-simple--look up in lists }
           r.v.n := d[v[p] - s];
           Inc(p);
         end
        Else
           r.e := 99;
       end;

      { fill code-like entries with r }
      f := WORD(WORD(1) shl (k - w));
      j := WORD(i shr w);
      while (j<z) do
       begin
       	q^[j] := r;
        Inc(j,f);
       end;

      { backwards increment the k-bit code i }
      j := WORD(WORD(1) shl (k - 1));
      while ((i and j) <> 0) do
       begin
       	i := i xor j;
        j := WORD(j shr 1);
       end;
      i := i xor j;

      { backup over finished tables }
      while ((i and (WORD((WORD(1) shl w))-1)) <> x[h]) do
       begin
        Dec(h);                    { don't need to update q }
        Dec(w,l);
       end;
      end;  { while (a <> 0) do }
     Inc(k);
   end;  { while ( k <= g ) do }

   If (y <> 0) and (g <> 1) then
   	Result := 1
   else
   	Result := 0;
end;

{****************************************************************************}
procedure flushslide(w: WORD);
var
  n: WORD;
  p: BYTEPTR;
begin
{ w = number of bytes to flush }
{ Do the equivalent of OUTB for the bytes slide[0..w-1]. }
  p := @slide^[0];
  while(w <> 0) do
   begin
    n := OUTBUFSIZ - outcnt;
    If n >= w then
    	 n := w;
	  MoveMemory(outptr, p, n);       { try to fill up buffer }
    Inc(outptr,n);
    Inc(outcnt,n);
    If (outcnt = OUTBUFSIZ) then
      FlushOutput;            { if full, empty }
    Inc(p,n);
    Dec(w,n);
   end;
end;

{*******************  UnZip Methods  *********************}
{$I kpInflt.Pas}
{$IFNDEF INFLATE_ONLY}
{$I kpUnrdc.Pas}
{$I kpExpld.Pas}
{$I kpUshrnk.Pas}
{$ENDIF}
{****************************************************************************}

procedure UnStore;
begin
	outcnt := min( file_info.compressed_size, OUTBUFSIZ );
	while( file_info.compressed_size > 0 ) do
	 begin
		zip_in_file.read( outbuf^, outcnt );
     if file_info.Encrypted then         { added 11/2/97 }
     	decrypt_buff( outbuf, outcnt );  {     KLB       }
     {Can't do the following to a property}
		{Dec(file_info.compressed_size, outcnt);}
     file_info.compressed_size := file_info.compressed_size - outcnt;
     FlushOutput;
		outcnt := min( file_info.compressed_size, OUTBUFSIZ );
	 end;
end;

procedure Skip_Rest;
{ skip past current compressed file to the next one }
begin
	zip_in_file.Seek( file_info.compressed_size, soFromCurrent );
  Dec(FileCount);
end;

procedure Do_Unzip( Index: Integer );
{ Unzips file[Index] }
var
	MsgArray: array [0..300] of char; {For 16 bit's sake}
	zip_out_file_name: String;
	CRCHighByte, DecryptCRCByte: BYTE;
  {CRCHighWord, DecryptCRCWord: WORD;}
	OverWriteIt: Boolean;
  Skip: Boolean;
	FullPath: String;
  FinishedOK: Boolean;
  FileHandle: Integer;
  InternalDir: String;
  NewPassword: String;
begin
  FinishedOK := False;
  RepeatFile := False;
	file_info.Assign(sortfiles.Items[Index] as TZipHeaderInfo);  { Make a copy }
	If (file_info.filename <> '') then   { must be a directory entry }
	 begin
		If (ecrec.this_disk > 0) and (file_info.disk_number_start <> CurrentDisk) then
        zip_in_file := SwapDisk( file_info.disk_number_start+1 );
		zip_in_file.Seek( file_info.relative_offset, soFromBeginning );
		zip_in_file.Read( lrec, SizeOf(local_file_header) );
		zip_in_file.Seek( lrec.extra_field_length + lrec.filename_length, soFromCurrent );
	 end;
  If not StreamZipping then
   begin
	   if (RecreateDirs) and (file_info.directory <> '') then
	    begin
        InternalDir := file_info.directory;
        If (RootDir <> '') and (AnsiCompareText(LeftStr(InternalDir,Length(RootDir)),RootDir) = 0) then
              Delete(InternalDir,1,Length(RootDir));
		   { The directory in the zip file could be absolute }
		   if (InternalDir <> '') and ((InternalDir[1] = '\') or (InternalDir[2] = ':')) then
         begin
           If DestDir = '' then
			      FullPath := InternalDir
           Else
            begin
              If (InternalDir[1] = '\') then
                 FullPath := DestDir + InternalDir
              Else
                 FullPath := DestDir + RightStr( InternalDir, Length(InternalDir)-2);
            end;
         end
        else { otherwise just append it to the destination directory }
			   FullPath := DestDir + '\' + InternalDir;
        if not DirExists( FullPath ) then
			   ForceDirs( FullPath );  { Create dest directory if it doesn't exist }
	    end
	   Else
		   FullPath := DestDir + '\';

	   If file_info.filename = '' then   { it's just a directory entry }
	    begin
		   If (RecreateDirs) and (Assigned( FOnStartUnZip )) then
			   FOnStartUnZip( self, Index, FullPath, Skip );
		   exit;
	   end;

	   zip_out_file_name := FullPath + file_info.filename;
   end;

	If (file_info.Encrypted) then
   begin
     NewPassword := Password;
     While NewPassword = Password do
	    begin
        If file_info.HasDescriptor then
           CRCHighByte := HIBYTE(LOWORD( file_info.last_mod_file_date_time ))
        Else
           CRCHighByte := HIBYTE(HIWORD( file_info.crc32));
		   {CRCHighByte := HIBYTE(HIWORD( file_info.crc32 ));}
		   DecryptCRCByte := DecryptTheHeader( Password, zip_in_file );
        {DecryptCRCWord := DecryptTheHeader( Password, zip_in_file );}
		   {++Dec(file_info.compressed_size,SizeOf(DecryptHeaderType));}
		   if CRCHighByte <> DecryptCRCByte then
        {If CRCHighWord <> DecryptCRCWord then}
		    begin
           NewPassword := Password;
			   If Assigned( FOnBadPassword ) then
            begin
				   FOnBadPassword( self, Index, NewPassword );
              If NewPassword <> Password then
               begin
                 Password := NewPassword;
                 zip_in_file.Seek(-SizeOf(DecryptHeaderType),soFromCurrent);
                 file_info.compressed_size := file_info.compressed_size + SizeOf(DecryptHeaderType);
                 Continue;
               end;
            end;
			   If Assigned( FOnSkippingFile ) then
				FOnSkippingFile( self, srBadPassword, Index );
			   Skip_Rest; {skip file}
			   exit;
		    end
        Else NewPassword := '';
	    end;
   end;

	csize := file_info.compressed_size;
	ucsize := file_info.uncompressed_size;

  If not StreamZipping then
   begin
	   If (FOverwriteMode <> Always) and (File_Exists(zip_out_file_name)) then
	    begin
		   If FOverwriteMode = Prompt then  { Allow application to determine if overwrite }
		    begin
			   If Assigned( FOnPromptForOverwrite ) then
			    begin
				   OverWriteIt := False;		{ Assume we skip just to be safe }
				   FOnPromptForOverwrite( self, OverWriteIt, Index, zip_out_file_name );
			    end
			   Else  { FOnPromptForOverwrite event not assigned so we have to ask user ourselves }
			    begin
				   StrPCopy( MsgArray, 'Replace existing file ' + Filename[Index] + '?' );
//				   OverWriteIt :=
//				   Application.MessageBox( MsgArray, 'File Exists Alert', MB_YESNO) =  IDYES;
			    end;
			   If not OverWriteIt then
			    begin
				   If Assigned( FOnSkippingFile ) then
             	   FOnSkippingFile( self, srNoOverwrite, Index );
				   Skip_Rest; {skip file}
        	   exit;
            end;
         end
        Else  { Never Overwrite }
         begin
           If Assigned( FOnSkippingFile ) then
        	   FOnSkippingFile( self, srNoOverwrite, Index );
      	   Skip_Rest;  {skip file}
     	   exit;
         end;
	    end;
	   zip_out_file := TLFNFileStream.Create( zip_out_file_name, fmCreate );
   end { If not UnZippingToStream }
  Else
     zip_out_file := ZipStream;  { UnZipping to a stream }

try
  bits_left := 0;
  bitbuf := 0;
	outpos := 0;
	incnt := 0;
  outcnt := 0;
  Crc32Val := $FFFFFFFF;
  Skip := False;
  If Assigned( FOnStartUnZip ) then
		FOnStartUnZip( self, Index, zip_out_file_name, Skip );
  If Skip then
     exit;
  Case file_info.compression_method of
  	STORED:		UnStore;
     DEFLATED:   Inflate;
{$IFNDEF INFLATE_ONLY}
     SHRUNK:     UnShrink;
     REDUCED1,
     REDUCED2,
     REDUCED3,
     REDUCED4:	UnReduce;
     IMPLODED:   Explode;
{$ENDIF}
		else     	{Application.MessageBox( 'Unknown Compression Method', 'Zip Error', mb_OK )}
  end; { Case }
  FinishedOK := True;
finally
  If not StreamZipping then
   begin
{     If FinishedOK then     }
{        status := FileSetDate(TLFNFileStream(zip_out_file).Handle, file_info.last_mod_file_date_time); }
     zip_out_file.Free;
     zip_out_file := nil;
     If FinishedOK then
      begin
        If RetainAttributes then
           FileSetAttr( zip_out_file_name, file_info.external_file_attributes );
        FileHandle := FileOpen(zip_out_file_name, fmOpenWrite or fmShareDenyNone);
        FileSetDate(FileHandle, file_info.last_mod_file_date_time);
        FileClose(FileHandle);
      end;
   end;
end;  { try }
  Crc32Val := not Crc32Val;
  If (Crc32Val <> file_info.crc32) then
   begin
     If (file_info.Encrypted) then  { bad password entered }
		 begin
			If Assigned( FOnBadPassword ) then
         begin
           NewPassword := Password;
				FOnBadPassword( self, Index, NewPassword );
           If NewPassword <> Password then
            begin
              Password := NewPassword;
              RepeatFile := True;
            end;
         end;
			If (not RepeatFile) and Assigned( FOnSkippingFile ) then
				FOnSkippingFile( self, srBadPassword, Index );
		 end
     Else If (Assigned( FOnBadCRC )) then
        FOnBadCRC( self, Crc32Val, file_info.crc32, Index );
     If not StreamZipping then
        SysUtils.DeleteFile( zip_out_file_name );
     If (not RepeatFile) then
        Dec(FileCount);
   end
  Else If Assigned( FOnEndUnZip ) then
		FOnEndUnZip( self, Index, zip_out_file_name );
end;

{******************************************************************************************}
var
	i, j: Integer;
	finfo: TZipHeaderInfo;
	SaveDir: String;
	StopNow: Boolean;
	CompareFileName: String;
	SaveSortMode: TZipSortMode;
begin
	New( area );
	slide := @(area^.slide);
	GetMem( inbuf, INBUFSIZ+1 );
	GetMem( outbuf, OUTBUFSIZ+1 );
	If DestDir <> '' then
	 begin
		If not DirExists( FDestDir ) then
			ForceDirs(FDestDir);
		GetDirectory( 0, SaveDir );
		ChDirectory( FDestDir );
	 end
	Else
		GetDirectory( 0, SaveDir );

	SaveSortMode := ByNone;
	If (ecrec.this_disk <> 0) and (FSortMode <> ByNone) then
	 begin
		SaveSortMode := FSortMode;
		Sort(ByNone);
	 end;
	inptr := inbuf;
	outptr := outbuf;
try
	TotalUncompressedSize := 0;
	TotalBytesDone := 0;
	FileCount := Count;
	{ Determine which files will be extracted }
 	For j := 0 to Count-1 do
   begin
 		finfo := sortfiles.Items[j] as TZipHeaderInfo;
		finfo.MatchFlag := FDoAll;
		If (finfo.filename = '') and (not RecreateDirs) then  { it's just a dirname }
		 begin
			finfo.MatchFlag := False;
        Dec(FileCount);
			continue;
		 end;
		{If (not FDoAll) then }
      begin
       	i := 0;
       	While (i < FFilesList.Count) do  { Compare with fileslist till we find a match }
			 begin
				If Pos('\',FFilesList[i]) > 0 then    { Use directory in filename comparison? }
       			CompareFileName := LowerCase(finfo.Directory + finfo.filename)
       		Else
       			CompareFileName := LowerCase(finfo.filename);
          	If (IsMatch(LowerCase(FFilesList[i]), CompareFileName)) then
            begin
             	finfo.MatchFlag := True;   { Found a match }
             	Break;                     { So we can stop looking }
            end
           Else
       			Inc(i);                    { Didn't find a match yet }
       	 end;
        If finfo.MatchFlag then           { If this file is to be extracted }
           TotalUncompressedSize := TotalUnCompressedSize +  finfo.uncompressed_size
				{Inc(TotalUncompressedSize, finfo.uncompressed_size)} { Accumulate it's size }
        Else
          	Dec(FileCount);                { otherwise one less file to extract }
      end;
	 end;
  StopNow := False;
	If Assigned( FOnStartUnzipInfo ) then    { Give application a chance to stop it now }
  	OnStartUnzipInfo( self, FileCount, TotalUncompressedSize, StopNow );
  If (FileCount > 0) and (not StopNow) then                     { If not stopping then let's extract the files }
   begin
  	If FDoAll then                       { If all files, then do them fast }
  		For j := 0 to Count-1 do
         begin
           Repeat
     		   Do_Unzip( j )
           Until RepeatFile = False;
         end
  	Else                                 { otherwise, check their flag first }
   	 begin
  		For i := 0 to Count-1 do
			 begin
				finfo := sortfiles.Items[i] as TZipHeaderInfo;
				If finfo.MatchFlag then
            Repeat
     			Do_Unzip( i );
            Until RepeatFile = False;
   		 end;
   	 end;
   end;
finally
  Result := FileCount;
	ChDirectory( SaveDir );
  Dispose( area );
	FreeMem( inbuf, INBUFSIZ+1 );
  FreeMem( outbuf, OUTBUFSIZ+1 );
	If (ecrec.this_disk <> 0) and (SaveSortMode <> ByNone) then
		Sort(SaveSortMode);
end; { try/finally }
end; { UnZipp }



{****************************************************************************}
{                            Encryption                                      }
{****************************************************************************}
procedure TVCLUnZip.update_keys( ch: char );
begin
	Key[0] := UpdCRC(BYTE(ch), Key[0]);
  Inc(Key[1], Key[0] and $ff);
  Key[1] := Key[1] * 134775813 + 1;
  Key[2] := UpdCRC( BYTE(WORD(Key[1] shr 24)), Key[2] );
end;

function TVCLUnZip.decrypt_byte: BYTE;
var
	temp: WORD;
begin
	temp := WORD(Key[2]) or 2;
  Result := BYTE(WORD(temp * (temp xor 1)) shr 8);
end;

procedure TVCLUnZip.decrypt_buff( bufptr: BYTEPTR; num_to_decrypt: WORD );
var
	i: Integer;
begin
	for i := 0 to num_to_decrypt-1 do
   begin
   	bufptr^ := bufptr^ xor decrypt_byte;
     update_keys(Char(bufptr^));
     Inc(bufptr);
   end;
end;

procedure TVCLUnZip.Init_Keys( Passwrd: String );
var
  i: Integer;
begin
	Key[0] := 305419896;
  Key[1] := 591751049;
  Key[2] := 878082192;

  For i := 1 to Length(Passwrd) do
  	update_keys( Passwrd[i] );
end;

function TVCLUnZip.DecryptTheHeader( Passwrd: String; zfile: TStream ): BYTE;
var
  DecryptHeader: DecryptHeaderType;
  i: Integer;
  C: BYTE;
  {D: WORDPTR;}
begin
	zfile.Read( DecryptHeader, SizeOf(DecryptHeader) );
  {Cant't do the following to a property}
  {Dec(file_info.compressed_size, SizeOf(DecryptHeader));}
  file_info.compressed_size := file_info.compressed_size - SizeOf(DecryptHeader);

  Init_Keys( Passwrd );

  For i := 0 to 11 do
   begin
  	C := DecryptHeader[i] xor decrypt_byte;
     update_keys( char(C) );
     DecryptHeader[i] := C;
   end;
   {D := @DecryptHeader[10];}
   {Result := D^; }
   Result := DecryptHeader[11];
end;

{****************************************************************************}
{                                   CRC                                      }
{****************************************************************************}
Function TVCLUnZip.UpdCRC(Octet: Byte; Crc: LongInt) : LongInt;
Var
   L : LongInt;
   W : Array[1..4] of Byte Absolute L;
Begin

   Result := CRC_32_TAB[Byte(Crc XOR LongInt(Octet))] XOR ((Crc SHR 8) AND $00FFFFFF);

end {UpdCRC};

procedure TVCLUnZip.Update_CRC_buff( bufptr: BYTEPTR; num_to_update: WORD );
var
	i: Integer;
begin
	for i := 0 to num_to_update-1 do
   begin
   	Crc32Val := UpdCRC( bufptr^, Crc32Val );
     Inc(bufptr);
   end;
end;


