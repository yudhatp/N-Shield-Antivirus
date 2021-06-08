unit EngineDLLUnit;
interface
  uses windows, classes;

    const
    MESIN = 'navscan.dll';

    BERSIH      = 0;    //XC_CLEAR
    BERVIRUS    = 1;    //XC_VIRUS
    UKURAN      = 2;  //XC_ESIZE
    DIBACA      = 3;   //XC_EREAD
    KOSONG      = 4;   //XC_EMPTY

    { TODO : Сообщения движка при инициализации и загрузке баз (отладочные) }
    NSHIELD_INIT        = 0;
    NSHIELD_INITERROR  = 1;
    NSHIELD_LOADDB     = 2;
    NSHIELD_EREADDB    = 3;
    NSHIELD_EOPENDB    = 4;

    NSHIELD_LOAD_PDB    = 5;
    NSHIELD_EREAD_PDB   = 6;
    NSHIELD_EOPEN_PDB   = 7;
    NSHIELD_BUILD_PDB   = 8;

    NSHIELD_PARSE_EVN   = 9;
    NSHIELD_PARSE_ERR   = 10;
    NSHIELD_PARSE_UST   = 11;

    NSHIELD_UNARCH_FILE   = 31;
    type
    { TODO : Настройки движка (при инициализации настройки устанавливаются поумолчанию) }
    nshield_optscan  = (pindai_pdf, pindai_gambar, pindai_pe,
                        pindai_lainnya, pindai_rar, pindai_zip, pindai_force);

    myscan_options = set of nshield_optscan;

    { TODO : Главный тип движка }
    my_engine       = pointer;

    { TODO : Буфер для сканирования }
    my_buffer        = array of char;

    { TODO : Индикатор прогресса сканирования файла (0-100%) (-1 при распаковке архивов)}
    nshieldscanprog = ^scan_progress;
    scan_progress  = procedure(progres: integer);

    { TODO : Вывод отладочных сообщений }
    nshield_pesandbg  = ^pesan_debug;
    pesan_debug   = procedure(msg: dword; const args: array of const);

    { TODO : Информация о PE файле }
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

procedure NShield_Start_Engine(var engine: my_engine; debug: pesan_debug); external MESIN;
procedure NShield_Stop_Engine(var engine: my_engine); external MESIN;
procedure NShield_Config(engine: my_engine; scanners: myscan_options; maxfsize, maxasize: int64; tempdir: pchar); external MESIN;
procedure NShield_Virus_Signature(root: my_engine; const sign: pchar); external MESIN;
procedure NShield_Encrypt(dbfile: pchar; dbdate: pchar; license: pchar); external MESIN;
procedure NShield_Load_Database(root: my_engine; filename: pchar); external MESIN;
procedure NShield_Get_VBD_Dir(engine: my_engine; dir: pchar; loadfilevdb: boolean); external MESIN;

function NShield_Heal_Mumawow(const FileName: string): boolean; external MESIN;
function NShield_Heal_Smellsme(const FileName: string): boolean; external MESIN;
function NShield_Heal_Ramnit_B(const FileName: string): boolean; external MESIN;
function NShield_Heal_Runouce(const FileName: string): boolean; external MESIN;
function NShield_Heal_Annie_HTML(const FileName: string; const offsetVX: integer): boolean; external MESIN;
function NShield_Heal_Dorifel(const FileName: string; Offset: integer; const Key: string): boolean; external MESIN;

function NShield_HexStrToStr(HexStr : string): string; external MESIN;
function NShield_Hex2Dec(data: string): byte; external MESIN;
function NShield_BM_SearchString(const Substr, S: string; const Index: Integer): Integer; assembler; external MESIN;

function NShield_Match_File(engine: my_engine; filename: pchar; var virname: pchar; progresscall: scan_progress; debugcall: pesan_debug; progress: boolean = false): integer; external MESIN;
function NShield_Scan_Buffer(engine: my_engine; buffer: my_buffer; ftype: dword; var virname: pchar): boolean; external MESIN;
function Nshield_Get_VirusCount(engine: my_engine): integer; external MESIN;
function NShield_Get_VirusName: pchar; external MESIN;
function NShield_Get_Engine_Version: pchar; external MESIN;
function NShield_str2hex(const str: widestring): widestring; external MESIN;
function NShield_CheckEncrypted(FilePath:string):Boolean; external MESIN;
function NShield_CheckOverlay(FilePath:string):Boolean; external MESIN;
function NShield_FileToString(const FileName: string; const Length : Integer = -1): AnsiString; external MESIN;

implementation

end.
