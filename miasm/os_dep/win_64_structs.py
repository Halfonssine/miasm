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

