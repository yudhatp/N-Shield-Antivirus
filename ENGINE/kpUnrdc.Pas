{ ********************************************************************************** }
{                                                                                    }
{ 	 COPYRIGHT 1997 Kevin Boylan                                                    }
{     Source File: Unreduce.pas                                                      }
{     Description: VCLUnZip component - native Delphi unzip component.               }
{     Date:        March 1997                                                        }
{     Author:      Kevin Boylan, CIS: boylank                                        }
{                                Internet: boylank@compuserve.com                    }
{                                                                                    }
{ ********************************************************************************** }

procedure Unreduce;
var
	  followers: ^f_array;
	  Slen: array[0..255] of Byte;
	  factor: WORD;

procedure READBITS( nbits: WORD; var zdest: Byte );
begin
	if nbits > bits_left then
  	FillBitBuffer;
	zdest :=  Byte(WORD(bitbuf) and mask_bits[nbits]);
  bitbuf := LongInt(bitbuf shr nbits);
  Dec(bits_left, nbits);
end;

procedure LoadFollowers;
var
	x:		shortint;
  i:		shortint;
begin
	for x := 255 downto 0 do
   begin
		READBITS(6,Slen[x]);
     i := 0;
     while (i < Slen[x]) do
      begin
     	READBITS(8,followers^[x][i]);
        Inc(i);
      end;
   end;
end;

procedure xflush( w: WORD );
var
	n:		WORD;
  p:		BYTEPTR;
begin
	p := @area^.slide[0];
  while (w <> 0) do
   begin
		n := OUTBUFSIZ - outcnt;
  	if (n >= w) then
  		n := w;
     MoveMemory( outptr, p, n );
     Inc(outptr,n);
     Inc(outcnt,n);
     if (outcnt = OUTBUFSIZ) then
     	FlushOutput;
     Inc(p,n);
     Dec(w,n);
   end;
end;

var    { Unreduce }
	lchar:		shortint;
	nchar:		Byte;
  ExState:		shortint;
  V:				shortint;
  Len:			shortint;
  s:				LongInt;
  w:				WORD;
  u:				WORD;
  follower:	Byte;
  bitsneeded:	shortint;
  e:				WORD;
  n:				WORD;
  d:				WORD;

begin  { Unreduce }
	lchar := 0;
  ExState := 0;
  V := 0;
  Len := 0;
  s := ucsize;
  w := 0;
  u := 1;

	followers := @area^.slide[WSIZE div 2];
	factor := file_info.compression_method - 1;
  LoadFollowers;

  while (s > 0) do
   begin
   	if (Slen[lchar] = 0) then
			READBITS(8,nchar)
     Else
      begin
      	READBITS(1,nchar);
        if (nchar <> 0) then
        	READBITS(8,nchar)
        Else
         begin
           bitsneeded := B_table[Slen[lchar]];
				READBITS(bitsneeded, follower);
           nchar := followers^[lchar][follower];
         end;
      end;
      Case ExState of
      	0: begin
        		if (nchar <> DLE) then
               begin
               	Dec(s);
                 area^.slide[w] := Byte(nchar);
                 Inc(w);
						if (w = (WSIZE div 2)) then
                  begin
                  	xflush(w);
                    w := 0;
                    u := 0;
                  end;
               end
              Else
              	ExState := 1;
        	end; { 0: }
        1: begin
        		if (nchar <> 0) then
               begin
               	V := nchar;
                 Len := V and L_table[factor];
                 if (Len = L_table[factor]) then
                 	ExState := 2
                 Else
                 	ExState := 3;
               end
              Else
               begin
               	Dec(s);
                 area^.Slide[w] := DLE;
                 Inc(w);
						if (w = (WSIZE div 2)) then
                  begin
                  	xflush(w);
                    w := 0;
                    u := 0;
                  end;
                 ExState := 0;
               end;
        	end; { 1: }
        2: begin
        		Inc(Len,nchar);
              ExState := 3;
        	end; { 2: }
        3: begin
           	n := Len + 3;
              d := w - ((((V shr D_shift[factor]) and D_mask[factor]) shl 8) + nchar + 1);
              Dec(s,n);
              Repeat
              	d := d and $3fff;
                 if d > w then
							e := (WSIZE div 2) - d
                 else
							e := (WSIZE div 2) - w;
                 if e > n then
                 	e := n;
                 Dec(n,e);
                 if (u <> 0) and (w <= d) then
                  begin
                  	ZeroMemory( @area^.Slide[w], e );
                    Inc(w,e);
                    Inc(d,e);
                  end
                 Else
                  begin
                 	if (w - d < e) then
                    	Repeat
                       	area^.Slide[w] := area^.Slide[d];
                          Inc(w);
                          Inc(d);
                          Dec(e);
                       Until e = 0
                    Else
                     begin
                    	MoveMemory( @area^.Slide[w], @area^.Slide[d], e );
                       Inc(w,e);
                       Inc(d,e);
                     end;
                  end;
                 if (w = (WSIZE div 2)) then
                  begin
                  	xflush(w);
                    w := 0;
                    u := 0;
                  end;
              Until (n = 0);
              Exstate := 0;
        	end; { 3: }
      end; { Case ExState of}
   	lchar := nchar;
   end; { while (s > 0) }
  xflush(w);
  FlushOutput;
end;
