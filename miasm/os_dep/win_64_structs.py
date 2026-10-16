from miasm.core.types import MemStruct, Num, Ptr, Str, \
    Array, RawStruct, Union, \
    BitField, Self, Void, Bits, \
    set_allocator, MemUnion, Struct


class UnicodeString(MemStruct):
    fields = [
        ("length", Num("H")),
        ("maxlength", Num("H")),
        #rajout padding
        ("padding", Num("I")),
        ("data", Ptr("<Q", Str("utf16"))),
    ]


class ListEntry(MemStruct):
    fields = [
        ("flink", Ptr("<Q", Void())),
        ("blink", Ptr("<Q", Void())),
    ]


class LdrDataEntry(MemStruct):

    """
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x010 InMemoryOrderLinks : _LIST_ENTRY
    +0x020 InInitializationOrderLinks : _LIST_ENTRY
    +0x030 DllBase : Ptr64 Void
    +0x038 EntryPoint : Ptr64 Void
    +0x040 SizeOfImage : Uint8B
    +0x048 FullDllName : _UNICODE_STRING
    +0x058 BaseDllName : _UNICODE_STRING
    +0x068 Flags : Uint4B 
    +0x06c LoadCount : Uint2B
    +0x06e TlsIndex : Uint2B
    +0x070 HashLinks : _LIST_ENTRY
    +0x080 TimeDateStamp : Uint8B
    +0x088 EntryPointActivationContext : Ptr64 Void
    """

    fields = [
        ("InLoadOrderLinks", ListEntry),
        ("InMemoryOrderLinks", ListEntry),
        ("InInitializationOrderLinks", ListEntry),
        ("DllBase", Ptr("<Q", Void())),
        ("EntryPoint", Ptr("<Q", Void())),
        ("SizeOfImage", Num("<Q")),
        ("FullDllName", UnicodeString),
        ("BaseDllName", UnicodeString),
        ("Flags", Array(Num("I"), 4)),
        ("LoadCount", Num("H")),
        ("TlsIndex", Num("H")),
        ("HashLinks", ListEntry),
        ("TimeDateStamp", Num("<Q")),
        ("EntryPointActivationContext", Ptr("<Q", Void())),

    ]


class PEB_LDR_DATA(MemStruct):

    """
    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr64 Void
    +0x010 InLoadOrderModuleList           : _LIST_ENTRY
    +0x020 InMemoryOrderModuleList         : _LIST_ENTRY
    +0x030 InInitializationOrderModuleList         : _LIST_ENTRY
    +0x040 EntryInProgress                  : Ptr64 Void
    """

    fields = [
        ("Length", Num("<I")),
        ("Initialized", Num("<I")),
        ("SsHandle", Ptr("<Q", Void())),
        ("InLoadOrderModuleList", ListEntry),
        ("InMemoryOrderModuleList", ListEntry),
        ("InInitializationOrderModuleList", ListEntry),
        ("EntryInProgress", Ptr("<Q", Void()))
    ]


class PEB(MemStruct):

    """
    +0x000 InheritedAddressSpace    : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged            : UChar
    +0x003 BitField                 : UChar
    +0x004 Padding                  : Uchar * 4
    +0x008 Mutant                   : Ptr64 Void
    +0x010 ImageBaseAddress         : Ptr64 Void
    +0x018 Ldr                      : Ptr64 _PEB_LDR_DATA
    +0x020 ProcessParameters         : Ptr64 _RTL_USER_PROCESS_PARAMETERS
    """

    fields = [
        ("InheritedAddressSpace", Num("B")),
        ("ReadImageFileExecOptions", Num("B")),
        ("BeingDebugged", Num("B")),
        ("Padding", Num("I")),
        ("BitField", Num("B")),
        ("Mutant", Ptr("<Q", Void())),
        ("ImageBaseAddress", Ptr("<Q", Void())),
        ("Ldr", Ptr("<Q", PEB_LDR_DATA)),
        ("ProcessParameters", Ptr("<Q", Void()))
    ]


class EXCEPTION_REGISTRATION_RECORD(MemStruct):
    """
    +0x00 Next    : struct _EXCEPTION_REGISTRATION_RECORD *
    +0x08 Handler : Ptr64 Void
    """

    fields = [
        ("Next", Ptr("<Q", Self())),
        ("Handler", Ptr("<Q", Void())),
    ]


class EXCEPTION_RECORD(MemStruct):
    """
    DWORD                    ExceptionCode;
    DWORD                    ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID                    ExceptionAddress;
    DWORD                    NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    """
    EXCEPTION_MAXIMUM_PARAMETERS = 15

    fields = [
        ("ExceptionCode", Num("<I")),
        ("ExceptionFlags", Num("<I")),
        ("ExceptionRecord", Ptr("<Q", Self())),
        ("ExceptionAddress", Ptr("<Q", Void())),
        ("NumberParameters", Num("<I")),
        ("ExceptionInformation", Ptr("<Q", Void())),
    ]


class NT_TIB(MemStruct):

    """
    +00 struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList => X
    +0x0 ExceptionList                  : Ptr64 Void ?
    +0x8 StackBase                      : Ptr64 Void                      
    +0x10 StackLimit                    : Ptr64 Void
    +0x18 SubSystemTib                  : Ptr64 Void
    +0x20 FiberData                     : Ptr64 Void
    +0x20 Version                       : uint64               
    +0x28 ArbitraryUserPointer          : Ptr64 Void
    +0x30 Self                          : Ptr64 Void 
    """

    fields = [
        ("ExceptionList", Ptr("<Q", EXCEPTION_REGISTRATION_RECORD)),
        ("StackBase", Ptr("<Q", Void())),
        ("StackLimit", Ptr("<Q", Void())),
        ("SubSystemTib", Ptr("<Q", Void())),
        (None, Union([
            ("FiberData", Ptr("<Q", Void())),
            ("Version", Num("<Q"))
        ])),
        ("ArbitraryUserPointer", Ptr("<Q", Void())),
        ("Self", Ptr("<Q", Self())),
    ]


class TEB(MemStruct):

    """
    +0x000 NtTib                     : _NT_TIB
    +0x038 EnvironmentPointer        : Ptr64 Void
    +0x040 ClientId                  : _CLIENT_ID
    +0x050 ActiveRpcHandle           : Ptr64 Void
    +0x058 ThreadLocalStoragePointer : Ptr64 Void
    +0x060 ProcessEnvironmentBlock   : Ptr64 _PEB
    +0x068 LastErrorValue            : Uint4B
    ...
    """

    fields = [
        ("NtTib", NT_TIB),
        ("EnvironmentPointer", Ptr("<Q", Void())),
        ("ClientId", Array(Num("B"), 0x10)),
        ("ActiveRpcHandle", Ptr("<Q", Void())),
        ("ThreadLocalStoragePointer", Ptr("<Q", Void())),
        ("ProcessEnvironmentBlock", Ptr("<Q", PEB)),
        ("LastErrorValue", Num("<I")),
    ]


class ContextException(MemStruct):
    fields = [
        ("ContextFlags", Num("<I")),
        ("dr0", Num("<I")),
        ("dr1", Num("<I")),
        ("dr2", Num("<I")),
        ("dr3", Num("<I")),
        ("dr4", Num("<I")),
        ("dr5", Num("<I")),

        ("Float", Array(Num("B"), 112)),

        ("gs", Num("<I")),
        ("fs", Num("<I")),
        ("es", Num("<I")),
        ("ds", Num("<I")),

        ("edi", Num("<I")),
        ("esi", Num("<I")),
        ("ebx", Num("<I")),
        ("edx", Num("<I")),
        ("ecx", Num("<I")),
        ("eax", Num("<I")),
        ("ebp", Num("<I")),
        ("eip", Num("<I")),

        ("cs", Num("<I")),
        ("eflags", Num("<I")),
        ("esp", Num("<I")),
        ("ss", Num("<I")),
    ]


## SEH 64 bits structures

class ExceptionRecord64(MemStruct):

    """
    LONG ExceptionCode;                                                     //0x0
    ULONG ExceptionFlags;                                                   //0x4
    ULONGLONG ExceptionRecord;                                              //0x8
    ULONGLONG ExceptionAddress;                                             //0x10
    ULONG NumberParameters;                                                 //0x18
    ULONG __unusedAlignment;                                                //0x1c
    ULONGLONG ExceptionInformation[15];                                     //0x20
    """

    fields = [
        ("ExceptionCode", Num("<I")),
        ("ExceptionFlags", Num("<I")),
        ("ExceptionRecord", Ptr("<Q", Self())),
        ("ExceptionAddress", Ptr("<Q", Void())),
        ("NumberParameters", Num("<I")),
        ("_pad", Num("<I")), 
        ("ExceptionInformation", Array(Num("<Q"), 15)),
    ]

class ContextException64(MemStruct):
    fields = [
        ("P1Home", Num("<Q")),
        ("P2Home", Num("<Q")),
        ("P3Home", Num("<Q")),
        ("P4Home", Num("<Q")),
        ("P5Home", Num("<Q")),
        ("P6Home", Num("<Q")),

        ("ContextFlags", Num("<I")), 
        ("mxcsr", Num("<I")),

        ("cs", Num("<H")), 
        ("ds", Num("<H")), 
        ("es", Num("<H")),
        ("fs", Num("<H")), 
        ("gs", Num("<H")), 
        ("ss", Num("<H")),

        ("eflags", Num("<I")),

        ("dr0", Num("<Q")), 
        ("dr1", Num("<Q")), 
        ("dr2", Num("<Q")),
        ("dr3", Num("<Q")), 
        ("dr6", Num("<Q")), 
        ("dr7", Num("<Q")),

        ("rax", Num("<Q")), 
        ("rcx", Num("<Q")), 
        ("rdx", Num("<Q")), 
        ("rbx", Num("<Q")),
        ("rsp", Num("<Q")), 
        ("rbp", Num("<Q")), 
        ("rsi", Num("<Q")), 
        ("rdi", Num("<Q")),

        ("r8", Num("<Q")), 
        ("r9", Num("<Q")), 
        ("r10", Num("<Q")), 
        ("r11", Num("<Q")),
        ("r12", Num("<Q")), 
        ("r13", Num("<Q")), 
        ("r14", Num("<Q")), 
        ("r15", Num("<Q")),

        ("rip", Num("<Q")),

        ("FltSave", Array(Num("B"), 512)),
        ("VectorRegister", Array(Num("B"), 26 * 16)),
        ("VectorControl", Num("<Q")),
        ("DebugControl", Num("<Q")),
        ("LastBranchToRip", Num("<Q")),
        ("LastBranchFromRip", Num("<Q")),
        ("LastExceptionToRip", Num("<Q")),
        ("LastExceptionFromRip", Num("<Q")),
    ]

class RuntimeFunction(MemStruct):
    fields = [
        ("BeginAddress", Num("<I")),
        ("EndAddress", Num("<I")),
        ("UnwindData", Num("<I")),
    ]

#https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170

# UNWIND_INFO contains an UnwindCode[CountOfCodes] table and an ExceptionData table of
# variable sizes. These are manually parsed in win_api_x86_64_seh.py

class UnwindInfoHeader(MemStruct):

    """ 
    typedef struct _UNWIND_INFO {
        UBYTE Version;
        UBYTE Flags;   // UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO...
        UBYTE SizeOfProlog;
        UBYTE CountOfCodes;
        UBYTE FrameRegister;
        UBYTE FrameOffset;
        UNWIND_CODE UnwindCode[CountOfCodes];

        // variable part : 
        union {
            OPTIONAL ULONG ExceptionHandler;
            OPTIONAL ULONG FunctionEntry;
        };
        OPTIONAL ULONG ExceptionData[];

        // or
        UNWIND_INFO ChainedUnwindInfo
    } UNWIND_INFO, *PUNWIND_INFO;
    """

    fields = [
        ("VersionAndFlags", Num("B")),
        ("SizeOfProlog", Num("B")),
        ("CountOfCodes", Num("B")),
        ("FrameRegisterAndOffset", Num("B")),
    ]

class UnwindCode(MemStruct):
    fields = [
        ("CodeOffset", Num("B")),
        ("UnwindOpAndInfo", Num("B")),
    ]


# SCOPE_TABLE has a ScopeRecord[Count] table of variable size so only the record
# type is declared to parse the table


class ScopeTableHeader(MemStruct):

    """ 
    typedef struct _SCOPE_TABLE_AMD64 { 
        ULONG Count;
        struct {
            ULONG BeginAddress;
            ULONG EndAddress;
            ULONG HandlerAddress; 
            ULONG JumpTarget;
        } ScopeRecord[];
    } SCOPE_TABLE_AMD64;
    """

    fields = [
        ("Count", Num("<I")),
    ]

class ScopeRecord(MemStruct):
    fields = [
        ("BeginAddress", Num("<I")),
        ("EndAddress", Num("<I")),
        ("HandlerAddress", Num("<I")),
        ("JumpTarget", Num("<I")),
    ]