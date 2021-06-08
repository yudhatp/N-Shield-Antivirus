unit EHeader;

interface
uses windows;


const
                                                  
  ENGINENAME       = 'N-Shield AntiVirus Engine';
  ENGINEVERSION    = '14.0';
  ENGINETEMP       = 'x.temp\';
  //EVDBSIGN         = 'nshielddb';  //nvse
  MAINVDBEXT       = '.vdb';  //.xpb main database
  UPDVDBEXT        = '.db';  //.xdb daily/user database

  BERSIH    = 0;
  BERVIRUS  = 1;
  UKURAN    = 2;
  DIBACA    = 3;
  KOSONG    = 4;
  NSHIELD_ALGOS    = 1000;

  NSHIELD_INIT        = 0;
  NSHIELD_INITERROR   = 1;

  NSHIELD_LOADDB      = 2;
  NSHIELD_EREADDB     = 3;
  NSHIELD_EOPENDB     = 4;

  NSHIELD_LOAD_PDB    = 5;
  NSHIELD_EREAD_PDB   = 6;
  NSHIELD_EOPEN_PDB   = 7;
  NSHIELD_BUILD_PDB   = 8;

  NSHIELD_PARSE_EVN   = 9;
  NSHIELD_PARSE_ERR   = 10;
  NSHIELD_PARSE_UST   = 11;

  NSHIELD_UNARCH_FILE   = 31;

  RIGHTRPOS     = ['0'..'9'];
  RIGHTHEX      = ['a'..'f','0'..'9','A'..'F'];

  FTYPEBUFF     = 1023;
  BUFFER_READ   = 131072;
  MAX_HASH_SIZE = 140760;
  MAXFILESIZE   = (1024 * 1024) * 1024;
  MAXARCHSIZE   = (1024 * 1024) * 32;
  MIN_NORM_LEN  = 4;
  MIN_WILD_LEN  = 2;
  MD_HASH_LEN   = 15;

  NSHIELD_ALT        = -200;
  NSHIELD_IGN        = -201;

  NSHIELD_TYPEFULL    = 0;

  NSHIELD_TYPENOTHING = -1;

  NSHIELD_TYPEOTHER   = 0;
  NSHIELD_TYPEPE      = 1;
  NSHIELD_TYPEGRAPHIC = 2;
  NSHIELD_TYPEPDF     = 3;
  //NSHIELD_TYPEHTML    = 4;

  //NSHIELD_TYPERTF     = 5;
  //NSHIELD_TYPECRYPTFF = 6;
  //NSHIELD_TYPEBINHEX  = 7;

  //NSHIELD_TYPEDATA    = 100;
  NSHIELD_TYPEARCHIVE = 200;
  NSHIELD_TYPERAR     = 201;
  NSHIELD_TYPEZIP     = 202;

  type

  nshield_int      = -255..255;

  nshield_mdbuff   = array [0..15] of char;
  nav_buffer  = ^my_buffer;
  my_buffer   = array of char;
  nav_acclc   = array of integer;
  nav_pattern  = array of nshield_int;

  (* *)
  nshield_optscan  = (pindai_pdf, pindai_gambar, pindai_pe,
                      pindai_lainnya, pindai_rar, pindai_zip, pindai_force);
 

  myscan_options = set of nshield_optscan;

  navoptions  = record
      scanners : myscan_options;
      maxfsize : int64;
      maxasize : int64;
      tempdir  : string;
  end;

  (* *)

  //untuk databse
  nav_header = record
      //signature : string [9];  //nshielddb , tadinya 4 = nvse
      //basedate  : string [6];
      license   : array [0..7] of char;  //1023  , skrng 8 karakter
  end;

  (* *)
  nav_offtype = (nav_all ,nav_entrypoint, nav_section, nav_lastsection, nav_eof, nav_stable);

  nav_offset = record
      otype : nav_offtype;
      osect : dword;
      offcn : integer;
  end;
  
  nshield_pesections = record
      rSize   : integer;
      rOffset : integer;
      vSize   : integer;
      vOffset : integer;
      flags   : integer;
      rName   : Widestring;
  end;

  nav_fileinfo = record
      PE         : boolean;
      filesize   : integer;
      (* *)
      entrypoint : integer;
      epsection  : Widestring;
      linker     : Widestring;
      subsystem  : Widestring; 
      firstbytes : array [1..4] of char;
      (* *)
      Sections   : integer;
      wSections  : array [0..32] of integer;
      wSectionNfo: array [0..32] of nshield_pesections;
  end;

  (* *)
  nshield_pesection = record
      sec_raw_size, sec_raw_offset: integer;
      sec_vir_size, sec_vir_offset: integer;
      sec_flag: integer;
      sec_name, sec_md5: WideString;
  end;

  nshield_infope = record
      pe_entrypoint,
      pe_seccount: integer;
      pe_size: integer;
      pe_linker, pe_epsection, pe_subsys: WideString;
      pe_firstbytes: array [1..4] of char;
      pe_sections: array [0..32] of nshield_pesection;
  end;

  (* PREFIXES *)
  nav_sigprefix = record
      prefix : char;
      ppos   : dword;
  end;
  (* NORMAL HEX SIGNATURES *)

  nshield_norm_patt = ^nshield_normpatt;
  nshield_normpatt  = ^nav_normpatt;
  
  nav_normpatt   = packed record
      next     : nshield_normpatt;
      
      ptype    : dword;
      virname  : pchar;
      pattern  : my_buffer;
      patlen   : dword;
      (* PREFIXES *)
      zprefix, wprefix : nav_sigprefix;
      (* *)
      offset   : nav_offset;
  end;

  (* *)

  nshield_hash_patt = ^nshield_hashpatt;
  nshield_hashpatt  = ^nav_hashpatt;

  nav_hashpatt   = packed record
      next     : nshield_hashpatt;
      pattern  : nshield_mdbuff;
      virname  : pchar;
      mdsize   : integer;
  end;
  (* WILDCARDS TYPE *)
  (* FIXME *)
  nshield_wild_patt = ^nshield_wildpatt;
  nshield_wildpatt  = ^nav_wildpatt;

  nav_wildpatt   = packed record
      next        : nshield_wildpatt;

      pattern     : nav_pattern;
      altc        : array of array of char;

      virname     : pchar;
      offset      : nav_offset;
      (* Alternate prefix *)
      zprefix, wprefix : nav_sigprefix;
      (* *)
      length, mindist, maxdist : integer;
      ptype, sigid, parts, partno, sigof : dword;
  end;

  nav_wild_nodelist = array [char , char] of nshield_wild_patt;

  (* *)

  nav_normsuffix  = array [0..MAX_HASH_SIZE] of nshield_norm_patt;
  navhash_suffix  = array [0..MAX_HASH_SIZE] of nshield_hash_patt;
  navnorm_shift   = array [0..MAX_HASH_SIZE] of integer;
  nav_bytesshift  = array [char,char] of boolean;
  (* *)

  nshieldbadsigs = ^bad_sigs;
  bad_sigs = ^navbad_sigs;
  navbad_sigs  = record
      next    : bad_sigs;
      signame : pchar;
  end;
  (* *)
  nshieldwhitesigs = ^white_sigs;
  white_sigs = ^nav_whitesigs;
  nav_whitesigs  = record
      next      : white_sigs;
      whitename : pchar;
      mdhash    : nshield_mdbuff;
      size      : integer;
  end;

  (* *)
  nshieldforce_sigs = ^nshieldforcesigs;
  nshieldforcesigs = ^nav_forcesigs;
  nav_forcesigs  = record
      next      : nshieldforcesigs;
      mdhash    : nshield_mdbuff;
      size      : integer;
  end;

  (* *)

  nshieldscanprog = ^scan_progress;
  scan_progress = procedure(progres: integer);

  nshield_pesandbg = ^pesan_debug;
  pesan_debug = procedure(msg: dword; const args: array of const);
  (* *)

  nshield_engine  = ^nav_engine;
  nav_engine   = record
      // Extended hex matcher - without wildcard's
      norm_b1b2    : nav_bytesshift;
      norm_b1b3    : nav_bytesshift;
      norm_b2b3    : nav_bytesshift;
      (* byte x - byte x : exists byte test *)
      norm_shift   : navnorm_shift;
      norm_suffix  : nav_normsuffix;
      // Extended hash matcher - full file hash
      hash_shift   : navnorm_shift;
      hash_suffix  : navhash_suffix;
      // Extended hash matcher - section's hash
      sect_shift   : navnorm_shift;
      sect_suffix  : navhash_suffix;
      // Extended wild matcher
      wild_node     : nav_wild_nodelist;
      wild_partsigs : integer;
      // Ignoring sig names (wrong sigs)
      badsigs       : nshieldbadsigs;
      // White files md5
      whitesigs     : nshieldwhitesigs;
      // navforce scantechnology
      navforce        : nshieldforce_sigs;
      // Other params
      maxpatlen     : integer;
      minpatlen     : integer;
      sigloaded     : integer;

      options       : navoptions;

      debug         : nshield_pesandbg;

      lastdate      : string;
  end;

implementation

end.
