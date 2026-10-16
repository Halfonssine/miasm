#-*- coding:utf-8 -*-

#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
import logging
import os
import struct

from future.utils import viewitems

from miasm.loader import pe_init

from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import pck32
from miasm.core.utils import pck64
import miasm.arch.x86.regs as x86_regs
from miasm.jitter.loader.pe import get_dll_name
from miasm.os_dep import win_64_structs, win_32_structs


# Constants Windows
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xc0000005
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xc0000094
EXCEPTION_PRIV_INSTRUCTION = 0xc0000096
EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d


log = logging.getLogger("seh_helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

# fs:[0] Page (TIB)
tib_address = 0x7ff70000
PEB_AD = 0x7ffdf000
LDR_AD = 0x340000
DEFAULT_SEH = 0x7ffff000

MAX_MODULES = 0x40

peb_address = PEB_AD
peb_ldr_data_offset = 0x1ea0
peb_ldr_data_address = LDR_AD + peb_ldr_data_offset


# modules_list_offset = 0x1f00
modules_list_offset = 0x2000

# InInitializationOrderModuleList_offset = 0x1ee0
InInitializationOrderModuleList_offset = 0x1f00
InInitializationOrderModuleList_address = LDR_AD + \
    InInitializationOrderModuleList_offset

# InLoadOrderModuleList_offset = 0x1ee0 + \
InLoadOrderModuleList_offset = 0x1ee0 + \
    MAX_MODULES * 0x1000
InLoadOrderModuleList_address = LDR_AD + \
    InLoadOrderModuleList_offset


process_environment_address = 0x10000
process_parameters_address = 0x200000

return_from_exception = 0x6eadbeef


name2module = []
main_pe = None
main_pe_name = "c:\\xxx\\toto.exe"

MAX_SEH = 5

# http://blog.fireeye.com/research/2010/08/download_exec_notes.html
seh_count = 0


class WinEnv:
    """
    Build the Windows process execution context for the jitter
    """

    def __init__(self, arch, jitter):
        self.arch = arch

        if arch == "x86_64":
            self.structs = win_64_structs
            self.ptr_size = 8
            self.pck = pck64
            self.tib_ad = jitter.cpu.get_segm_base(jitter.cpu.GS)
        else: 
            # x86
            self.structs = win_32_structs
            self.ptr_size = 4
            self.pck = pck32
            self.tib_ad = jitter.cpu.get_segm_base(jitter.cpu.FS)

        self.TEB = self.structs.TEB
        self.PEB = self.structs.PEB
        self.NT_TIB = self.structs.NT_TIB
        self.PEB_LDR_DATA = self.structs.PEB_LDR_DATA
        self.LdrDataEntry = self.structs.LdrDataEntry
        self.ListEntry = self.structs.ListEntry
        self.EXCEPTION_RECORD = self.structs.EXCEPTION_RECORD
        self.EXCEPTION_REGISTRATION_RECORD = (
            self.structs.EXCEPTION_REGISTRATION_RECORD
        )

        self.LOAD_ORDER = self.LdrDataEntry.get_type().get_offset(
            "InLoadOrderLinks"
        )
        self.MEMORY_ORDER = self.LdrDataEntry.get_type().get_offset(
            "InMemoryOrderLinks"
        )
        self.INIT_ORDER = self.LdrDataEntry.get_type().get_offset(
            "InInitializationOrderLinks"
        )

    def build_teb(self, jitter, teb_address):
        """
        Build TEB information using following structure:

        @jitter: jitter instance
        @teb_address: the TEB address
        """

        NT_TIB = self.NT_TIB
        TEB = self.TEB


        jitter.vm.add_memory_page(
            teb_address,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * NT_TIB.sizeof(),
            "TEB.NtTib"
        )

        # Only allocate space for ExceptionList/ProcessEnvironmentBlock/Self
        # jitter.vm.add_memory_page(
        #     teb_address + NT_TIB.get_offset("Self"),
        #     PAGE_READ | PAGE_WRITE,
        #     b"\x00" * (NT_TIB.sizeof() - NT_TIB.get_offset("Self")),
        #     "TEB.NtTib.Self"
        # )

        jitter.vm.add_memory_page(
            teb_address + TEB.get_offset("ProcessEnvironmentBlock"),
            PAGE_READ | PAGE_WRITE,
            b"\x00" * (
                TEB.get_offset("LastErrorValue") -
                TEB.get_offset("ProcessEnvironmentBlock")
            ),
            "TEB.ProcessEnvironmentBlock"
        )

        Teb = TEB(jitter.vm, teb_address)
        Teb.NtTib.ExceptionList = DEFAULT_SEH
        Teb.NtTib.Self = teb_address
        Teb.ProcessEnvironmentBlock = peb_address

    def build_peb(self, jitter, peb_address):
        """
        Build PEB information using following structure:

        @jitter: jitter instance
        @peb_address: the PEB address
        """

        PEB = self.PEB

        if main_pe:
            # offset ImageBaseAddress
            offset, length = PEB.get_offset("ImageBaseAddress"), self.ptr_size
            # x86 : 0x8, 0x4 
            # x86_64 : 0x10, 0x8 
        else:
            # offset Ldr
            offset, length = PEB.get_offset("Ldr"), 0
            # x86 : 0xc, 0x0
            # x86_64 : 0x18, 0x0 

        length += self.ptr_size


        jitter.vm.add_memory_page(
            peb_address + offset,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * length,
            "PEB + 0x%x" % offset
        )

        Peb = PEB(jitter.vm, peb_address)
        if main_pe:
            Peb.ImageBaseAddress = main_pe.NThdr.ImageBase
        Peb.Ldr = peb_ldr_data_address


    def init_head_list(self, head, first_entry, last_entry, offset):
        """
        Initiate a module list

        @head : head of a LIST_ENTRY
        @first_entry : address of the first module
        @last_entry : address of the last module
        @offset : offset of the module list link in an LdrDataEntry
        """
        head.flink = first_entry + offset
        head.blink = last_entry + offset

    def build_ldr_data(self, jitter, modules_info):
        """
        Build Loader information using following structure:

        +0x000 Length                          : Uint4B
        +0x004 Initialized                     : UChar
        +0x008 SsHandle                        : Ptr32 Void
        +0x00c InLoadOrderModuleList           : _LIST_ENTRY
        +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
        +0x01C InInitializationOrderModuleList         : _LIST_ENTRY
        +0x024 EntryInProgress                 : Ptr32 Void

        64 bits : 
        +0x000 Length                          : Uint4B
        +0x004 Initialized                     : UChar
        +0x008 SsHandle                        : Ptr64 Void
        +0x010 InLoadOrderModuleList           : _LIST_ENTRY
        +0x020 InMemoryOrderModuleList         : _LIST_ENTRY
        +0x030 InInitializationOrderModuleList         : _LIST_ENTRY
        +0x040 EntryInprogress                 : Ptr64 Void
        
        @jitter: jitter instance
        @modules_info: LoadedModules instance
        """

        PEB_LDR_DATA = self.PEB_LDR_DATA

        # ldr offset pad
        offset = PEB_LDR_DATA.get_offset("InLoadOrderModuleList") 
        ldrdata = PEB_LDR_DATA(jitter.vm, peb_ldr_data_address)

        main_pe = modules_info.name2module.get(main_pe_name, None)
        ntdll_pe = modules_info.name2module.get("ntdll.dll", None)

        if main_pe == None:
            log.warn("No main PE")
        if ntdll_pe == None:
            log.warn("ntdll.dll is needed to create an InInitializationOrderModuleList")


        size = self.ListEntry.sizeof() * 3
        main_addr_entry = modules_info.module2entry[main_pe]
        ntdll_addr_entry = modules_info.module2entry[ntdll_pe]

        # #old logic
        # size = 0
        # if main_pe:
        #     size += ListEntry.sizeof() * 2
        #     main_addr_entry = modules_info.module2entry[main_pe]
        # if ntdll_pe:
        #     size += ListEntry.sizeof()
        #     ntdll_addr_entry = modules_info.module2entry[ntdll_pe]

        jitter.vm.add_memory_page(
            peb_ldr_data_address + offset,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * size,
            "Loader struct"
        )

        last_module = modules_info.module2entry[
            modules_info.modules[-1]]

        self.init_head_list(ldrdata.InLoadOrderModuleList, main_addr_entry, last_module, self.LOAD_ORDER)
        self.init_head_list(ldrdata.InMemoryOrderModuleList, main_addr_entry, last_module, self.MEMORY_ORDER)
        self.init_head_list(ldrdata.InInitializationOrderModuleList, ntdll_addr_entry, last_module, self.INIT_ORDER)
        
        jitter.vm.add_memory_page(peb_ldr_data_address + PEB_LDR_DATA.get_offset("EntryInProgress"),
                                PAGE_READ | PAGE_WRITE, self.pck(0),
                                "Loader struct dummy dllbase")


    class LoadedModules(object):

        """Class representing modules in memory"""

        def __init__(self):
            self.modules = []
            self.name2module = {}
            self.module2entry = {}
            self.module2name = {}

        def add(self, name, module, module_entry):
            """Track a new module
            @name: module name (with extension)
            @module: module object
            @module_entry: address of the module entry
            """

            self.modules.append(module)
            self.name2module[name] = module
            self.module2entry[module] = module_entry
            self.module2name[module] = name

        def __repr__(self):
            return "\n".join(str(x) for x in viewitems(self.name2module))


    def create_modules_chain(self, jitter, name2module):
        """
        Create the modules entries. Those modules are not linked in this function.

        @jitter: jitter instance
        @name2module: dict containing association between name and its pe instance
        """

        LdrDataEntry = self.LdrDataEntry

        modules_info = self.LoadedModules()
        base_addr = LDR_AD + modules_list_offset  # XXXX
        offset_name = 0x500
        offset_path = 0x600

        out = ""
        for i, (fname, pe_obj) in enumerate(viewitems(name2module), 1):
            if pe_obj is None:
                log.warning("Unknown module: omitted from link list (%r)",
                            fname)
                continue
            addr = base_addr + i * 0x1000
            bpath = fname.replace('/', '\\')

            # bname_str = os.path.split(fname)[1].lower()
            name_dll = get_dll_name(pe_obj)

            # LdrDataEntry.BaseDllName->Buffer is either filled with the dll name imported 
            # by the main PE or the name used in a LoadLibrary call

            # get_dll_name() returns the name "exported" by the dll's PE but it seems that
            # it has the same casing as the name imported by the main PE

            if name_dll == None :
                # the PE has no export meaning it is not a dll
                bname_str = os.path.split(fname)[1].lower()
            else :
                bname_str = name_dll.decode()

            bname_unicode = bname_str.encode("utf-16le")
            log.info("Add module %x %r", pe_obj.NThdr.ImageBase, bname_str)

            modules_info.add(bname_str, pe_obj, addr)
            print(bname_str, hex(addr))

            # Allocate a partial LdrDataEntry (0-Flags)
            jitter.vm.add_memory_page(
                addr,
                PAGE_READ | PAGE_WRITE,
                b"\x00" * LdrDataEntry.get_offset("Flags"),
                "Module info %r" % bname_str
            )

            LdrEntry = self.LdrDataEntry(jitter.vm, addr)

            LdrEntry.DllBase = pe_obj.NThdr.ImageBase
            LdrEntry.EntryPoint = pe_obj.Opthdr.AddressOfEntryPoint
            LdrEntry.SizeOfImage = pe_obj.NThdr.sizeofimage
            LdrEntry.FullDllName.length = len(bname_unicode)
            LdrEntry.FullDllName.maxlength = len(bname_unicode) + 2
            LdrEntry.FullDllName.data = addr + offset_path
            LdrEntry.BaseDllName.length = len(bname_unicode)
            LdrEntry.BaseDllName.maxlength = len(bname_unicode) + 2
            LdrEntry.BaseDllName.data = addr + offset_name

            jitter.vm.add_memory_page(
                addr + offset_name,
                PAGE_READ | PAGE_WRITE,
                bname_unicode + b"\x00" * 2,
                "Module name %r" % bname_str
            )

            if isinstance(bpath, bytes):
                bpath = bpath.decode('utf8')
            bpath_unicode = bpath.encode('utf-16le')
            jitter.vm.add_memory_page(
                addr + offset_path,
                PAGE_READ | PAGE_WRITE,
                bpath_unicode + b"\x00" * 2,
                "Module path %r" % bname_str
            )

        return modules_info


    def set_link_list_entry(self, jitter, loaded_modules, modules_info, offset):
        PEB_LDR_DATA = self.PEB_LDR_DATA

        for i, module in enumerate(loaded_modules):
            cur_module_entry = modules_info.module2entry[module]
            prev_module = loaded_modules[(i - 1) % len(loaded_modules)]
            next_module = loaded_modules[(i + 1) % len(loaded_modules)]
            prev_module_entry = modules_info.module2entry[prev_module]
            next_module_entry = modules_info.module2entry[next_module]
            if i == 0:
                prev_module_entry = peb_ldr_data_address + PEB_LDR_DATA.get_offset("InLoadOrderModuleList")
            if i == len(loaded_modules) - 1:
                next_module_entry = peb_ldr_data_address + PEB_LDR_DATA.get_offset("InLoadOrderModuleList")

            list_entry = self.ListEntry(jitter.vm, cur_module_entry + offset)
            list_entry.flink = next_module_entry + offset
            list_entry.blink = prev_module_entry + offset


    def fix_module_list_order(self, jitter, modules_info, order, offset):
        """Fix InXXXOrderModuleList double link list. First module is the main pe,
        then ntdll, kernel32 except it's an InInitializationOrderModuleList

        @jitter: the jitter instance
        @modules_info: the LoadedModules instance
        @order : specify the order in which the modules are linked
        @offset : offset of the module list link in an LdrDataEntry
        """

        log.debug("Fix In%sOrderModuleList", order)
        main_pe = modules_info.name2module.get(main_pe_name, None)
        kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
        ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
        special_modules = [main_pe, kernel32_pe, ntdll_pe]
        if not all(special_modules):
            log.warn(
                'No main pe, ldr data will be unconsistant %r', special_modules)
            loaded_modules = modules_info.modules
        else:
            loaded_modules = [module for module in modules_info.modules
                            if module not in special_modules]
            if order == "Initialization":
                loaded_modules[0:0] = [ntdll_pe]
                loaded_modules[1:1] = [kernel32_pe]
            else : 
                loaded_modules[0:0] = [main_pe]
                loaded_modules[1:1] = [ntdll_pe]
                loaded_modules[2:2] = [kernel32_pe]
        
        self.set_link_list_entry(jitter, loaded_modules, modules_info, offset)


    def add_process_env(self, jitter):
        """
        Build a process environment structure
        @jitter: jitter instance
        """

        env_unicode = 'ALLUSEESPROFILE=C:\\Documents and Settings\\All Users\x00'.encode('utf-16le')
        env_unicode += b"\x00" * self.PEB.get_offset("ProcessParameters")
        jitter.vm.add_memory_page(
            process_environment_address,
            PAGE_READ | PAGE_WRITE,
            env_unicode,
            "Process environment"
        )
        jitter.vm.set_mem(process_environment_address, env_unicode)

    def add_process_parameters(self, jitter):
        """
        Build a process parameters structure
        @jitter: jitter instance

        _RTL_USER_PROCESS_PARAMETERS 
        +0x48 : void* Environment

        64 bits :
        +0x80 : void* Environment
        """

        o = b""
        o += self.pck(0x1000)  # size
        if self.arch=="x86_64": 
            o += b"E" * (0x80 - len(o))
        else: 
            o += b"E" * (0x48 - len(o))

        o += self.pck(process_environment_address)
        
        # PEB -> ProcessParameters -> RTL_USER_PROCESS_PARAMETERS -> Environment -> ALLUSEESPROFILE=...\0\0
        jitter.vm.add_memory_page(
            process_parameters_address,
            PAGE_READ | PAGE_WRITE,
            o, "Process parameters"
        )


    def init_seh(self, jitter):

        global seh_count
        seh_count = 0

        self.build_teb(jitter, self.tib_ad)
        self.build_peb(jitter, peb_address)
        modules_info = self.create_modules_chain(jitter, name2module)

        self.fix_module_list_order(
            jitter,
            modules_info,
            "Load",
            self.LOAD_ORDER
        )

        self.fix_module_list_order(
            jitter,
            modules_info,
            "Memory",
            self.MEMORY_ORDER
        )

        self.fix_module_list_order(
            jitter,
            modules_info,
            "Initialization",
            self.INIT_ORDER
        )

        self.build_ldr_data(jitter, modules_info)
        self.add_process_env(jitter)
        self.add_process_parameters(jitter)


def regs2ctxt(jitter, context_address):
    """
    Build x86_32 cpu context for exception handling
    @jitter: jitload instance
    """

    ctxt = ContextException(jitter.vm, context_address)
    ctxt.memset(b"\x00")
    # ContextFlags
    # XXX

    # DRX
    ctxt.dr0 = 0
    ctxt.dr1 = 0
    ctxt.dr2 = 0
    ctxt.dr3 = 0
    ctxt.dr4 = 0
    ctxt.dr5 = 0

    # Float context
    # XXX

    # Segment selectors
    ctxt.gs = jitter.cpu.GS
    ctxt.fs = jitter.cpu.FS
    ctxt.es = jitter.cpu.ES
    ctxt.ds = jitter.cpu.DS

    # Gpregs
    ctxt.edi = jitter.cpu.EDI
    ctxt.esi = jitter.cpu.ESI
    ctxt.ebx = jitter.cpu.EBX
    ctxt.edx = jitter.cpu.EDX
    ctxt.ecx = jitter.cpu.ECX
    ctxt.eax = jitter.cpu.EAX
    ctxt.ebp = jitter.cpu.EBP
    ctxt.eip = jitter.cpu.EIP

    # CS
    ctxt.cs = jitter.cpu.CS

    # Eflags
    # XXX TODO real eflag

    # ESP
    ctxt.esp = jitter.cpu.ESP

    # SS
    ctxt.ss = jitter.cpu.SS


def ctxt2regs(jitter, ctxt_ptr):
    """
    Restore x86_32 registers from an exception context
    @ctxt: the serialized context
    @jitter: jitload instance
    """

    ctxt = ContextException(jitter.vm, ctxt_ptr)

    # Selectors
    jitter.cpu.GS = ctxt.gs
    jitter.cpu.FS = ctxt.fs
    jitter.cpu.ES = ctxt.es
    jitter.cpu.DS = ctxt.ds

    # Gpregs
    jitter.cpu.EDI = ctxt.edi
    jitter.cpu.ESI = ctxt.esi
    jitter.cpu.EBX = ctxt.ebx
    jitter.cpu.EDX = ctxt.edx
    jitter.cpu.ECX = ctxt.ecx
    jitter.cpu.EAX = ctxt.eax
    jitter.cpu.EBP = ctxt.ebp
    jitter.cpu.EIP = ctxt.eip

    # CS
    jitter.cpu.CS = ctxt.cs

    # Eflag
    # XXX TODO

    # ESP
    jitter.cpu.ESP = ctxt.esp
    # SS
    jitter.cpu.SS = ctxt.ss


def fake_seh_handler(jitter, except_code, previous_seh=None):
    """
    Create an exception context
    @jitter: jitter instance
    @except_code: x86 exception code
    @previous_seh: (optional) last SEH address when multiple SEH are used
    """
    global seh_count
    log.info('Exception at %x %r', jitter.cpu.EIP, seh_count)
    seh_count += 1

    # Get space on stack for exception handling
    new_ESP = jitter.cpu.ESP - 0x3c8
    exception_base_address = new_ESP
    exception_record_address = exception_base_address + 0xe8
    context_address = exception_base_address + 0xfc
    fake_seh_address = exception_base_address + 0x14

    # Save a CONTEXT
    regs2ctxt(jitter, context_address)
    jitter.cpu.ESP = new_ESP

    # Get current seh (fs:[0])
    tib = NT_TIB(jitter.vm, tib_address)
    seh = tib.ExceptionList.deref
    if previous_seh:
        # Recursive SEH
        while seh.get_addr() != previous_seh:
            seh = seh.Next.deref
        seh = seh.Next.deref

    log.debug(
        'seh_ptr %x { old_seh %r eh %r} ctx_addr %x',
        seh.get_addr(),
        seh.Next,
        seh.Handler,
        context_address
    )

    # Write exception_record
    except_record = EXCEPTION_RECORD(jitter.vm, exception_record_address)
    except_record.memset(b"\x00")
    except_record.ExceptionCode = except_code
    except_record.ExceptionAddress = jitter.cpu.EIP

    # Prepare the stack
    jitter.push_uint32_t(context_address)               # Context
    jitter.push_uint32_t(seh.get_addr())                # SEH
    jitter.push_uint32_t(except_record.get_addr())      # ExceptRecords
    jitter.push_uint32_t(return_from_exception)         # Ret address

    # Set fake new current seh for exception
    log.debug("Fake seh ad %x", fake_seh_address)
    fake_seh = EXCEPTION_REGISTRATION_RECORD(jitter.vm, fake_seh_address)
    fake_seh.Next.val = tib.ExceptionList.val
    fake_seh.Handler = 0xaaaaaaaa
    tib.ExceptionList.val = fake_seh.get_addr()
    dump_seh(jitter)

    # Remove exceptions
    jitter.vm.set_exception(0)
    jitter.cpu.set_exception(0)

    # XXX set ebx to nul?
    jitter.cpu.EBX = 0

    log.debug('Jumping at %r', seh.Handler)
    return seh.Handler.val


def dump_seh(jitter):
    """
    Walk and dump the SEH entries
    @jitter: jitter instance
    """
    log.debug('Dump_seh. Tib_address: %x', tib_address)
    cur_seh_ptr = NT_TIB(jitter.vm, tib_address).ExceptionList
    loop = 0
    while cur_seh_ptr and jitter.vm.is_mapped(cur_seh_ptr.val,
                                              len(cur_seh_ptr)):
        if loop > MAX_SEH:
            log.debug("Too many seh, quit")
            return
        err = cur_seh_ptr.deref
        log.debug('\t' * (loop + 1) + 'seh_ptr: %x { prev_seh: %r eh %r }',
                 err.get_addr(), err.Next, err.Handler)
        cur_seh_ptr = err.Next
        loop += 1


def set_win_gs_0(jitter, gs=4):
    """
    Set GS segment selector and create its corresponding segment
    @jitter: jitter instance
    @fs: segment selector value
    """
    jitter.cpu.GS = gs
    jitter.cpu.set_segm_base(gs, tib_address)
    segm_to_do = set([x86_regs.GS])
    return segm_to_do

def set_win_fs_0(jitter, fs=4):
    """
    Set FS segment selector and create its corresponding segment
    @jitter: jitter instance
    @fs: segment selector value
    """
    jitter.cpu.FS = fs
    jitter.cpu.set_segm_base(fs, tib_address)
    segm_to_do = set([x86_regs.FS])
    return segm_to_do


def return_from_seh(jitter):
    """Handle the return from an exception handler
    @jitter: jitter instance"""

    # Get object addresses
    seh_address = jitter.vm.get_u32(jitter.cpu.ESP + 0x4)
    context_address = jitter.vm.get_u32(jitter.cpu.ESP + 0x8)

    # Get registers changes
    log.debug('Context address: %x', context_address)
    status = jitter.cpu.EAX
    ctxt2regs(jitter, context_address)

    # Rebuild SEH (remove fake SEH)
    tib = NT_TIB(jitter.vm, tib_address)
    seh = tib.ExceptionList.deref
    log.debug('Old seh: %x New seh: %x', seh.get_addr(), seh.Next.val)
    tib.ExceptionList.val = seh.Next.val
    dump_seh(jitter)

    # Handle returned values
    if status == 0x0:
        # ExceptionContinueExecution
        log.debug('SEH continue')
        jitter.pc = jitter.cpu.EIP
        log.debug('Context::Eip: %x', jitter.pc)

    elif status == 1:
        # ExceptionContinueSearch
        log.debug("Delegate to the next SEH handler")
        # exception_base_address: context_address - 0xfc
        # -> exception_record_address: exception_base_address + 0xe8
        exception_record = EXCEPTION_RECORD(jitter.vm,
                                            context_address - 0xfc + 0xe8)

        pc = fake_seh_handler(jitter, exception_record.ExceptionCode,
                              seh_address)
        jitter.pc = pc

    else:
        # https://msdn.microsoft.com/en-us/library/aa260344%28v=vs.60%29.aspx
        # But the type _EXCEPTION_DISPOSITION may take 2 others values:
        #  - ExceptionNestedException = 2
        #  - ExceptionCollidedUnwind = 3
        raise ValueError("Valid values are ExceptionContinueExecution and "
                         "ExceptionContinueSearch")

    # Jitter's breakpoint compliant
    return True


#=============================================================
CONTEXT64_AD = 0x7FF30000
EXCEPTION64_RECORD_AD = 0x7FF31000
DISPATCHER_CONTEXT64_AD = 0x7FF32000

MAX_UNWIND_STEPS = 32

# UNWIND_INFO Flag 
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4

# unwind opcodes
UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10


# general purpose registers table used when reading the OpInfo attribute of 
# the UnwindCode structure
GPR_FROM_OPINFO = {
    0: "RAX", 1: "RCX", 2: "RDX", 3: "RBX", 5: "RBP",
    6: "RSI", 7: "RDI", 8: "R8", 9: "R9", 10: "R10", 11: "R11",
    12: "R12", 13: "R13", 14: "R14", 15: "R15",
}

# values of the FrameRegister attribute of UNWIND_INFO
# it must be non volatile registers so RAX, RCX, RDX, R8-R11 are excluded
FRAME_REGISTERS = {
    3: "RBX",
    5: "RBP",
    6: "RSI",
    7: "RDI",
    12: "R12",
    13: "R13",
    14: "R14",
    15: "R15",
}

def regs2ctxt64(jitter, context_address):
    """
    Build x86_32 cpu context for exception handling
    @jitter: jitload instance
    """

    ctxt = ContextException(jitter.vm, context_address)
    ctxt.memset(b"\x00")

    # PxHome
    # XXX

    # ContextFlags
    # XXX

    # MxCsr
    # XXX

    ctxt.cs = jitter.cpu.CS
    ctxt.ds = jitter.cpu.DS
    ctxt.es = jitter.cpu.ES
    ctxt.fs = jitter.cpu.FS
    ctxt.gs = jitter.cpu.GS 
    ctxt.ss = jitter.cpu.SS

    # Eflags
    # XXX TODO real eflag

    ctxt.dr0 = 0
    ctxt.dr1 = 0
    ctxt.dr2 = 0
    ctxt.dr3 = 0
    ctxt.dr6 = 0
    ctxt.dr7 = 0

    ctxt.rdi = jitter.cpu.RDI
    ctxt.rsi = jitter.cpu.RSI
    ctxt.rbx = jitter.cpu.RBX
    ctxt.rdx = jitter.cpu.RDX
    ctxt.rcx = jitter.cpu.RCX
    ctxt.rax = jitter.cpu.RAX
    ctxt.rbp = jitter.cpu.RBP
    ctxt.rip = jitter.cpu.RIP

    ctxt.rsp = jitter.cpu.RSP

    ctxt.r8  = jitter.cpu.R8
    ctxt.r9  = jitter.cpu.R9
    ctxt.r10 = jitter.cpu.R10
    ctxt.r11 = jitter.cpu.R11
    ctxt.r12 = jitter.cpu.R12
    ctxt.r13 = jitter.cpu.R13
    ctxt.r14 = jitter.cpu.R14
    ctxt.r15 = jitter.cpu.R15

    # FltSave
    # XXX 

    ctxt.VectorControl = 0
    ctxt.DebugControl = 0
    ctxt.LastBranchToRip = 0
    ctxt.LastBranchFromRip = 0
    ctxt.LastExceptionToRip = 0
    ctxt.LastExceptionFromRip = 0

    return ctxt


def ctxt2regs(jitter, ctxt_ptr):
    """
    Restore x86_32 registers from an exception context
    @ctxt: the serialized context
    @jitter: jitload instance
    """

    ctxt = ContextException64(jitter.vm, ctxt_ptr)

    jitter.cpu.GS = ctxt.gs
    jitter.cpu.FS = ctxt.fs
    jitter.cpu.ES = ctxt.es
    jitter.cpu.DS = ctxt.ds
    jitter.cpu.CS = ctxt.cs
    jitter.cpu.SS = ctxt.ss

    jitter.cpu.RDI = ctxt.rdi
    jitter.cpu.RSI = ctxt.rsi
    jitter.cpu.RBX = ctxt.rbx
    jitter.cpu.RDX = ctxt.rdx
    jitter.cpu.RCX = ctxt.rcx
    jitter.cpu.RAX = ctxt.rax
    jitter.cpu.RBP = ctxt.rbp
    jitter.cpu.RSP = ctxt.rsp
    
    jitter.cpu.RIP = ctxt.rip


#TODO ctxt
def leaf_unwind_step(jitter, ctxt):
    """
    no runtime function entry for the current frame
    get the return address
    """
    ret_addr = upck64(jitter.vm.get_mem(ctxt.RSP, 8))
    ctxt.RSP += 8
    return ret_addr

def lookup_function_entry(jitter, rip, pe):
    """
    looking for a runtime function in the unwind tables in .pdata section
    that can handle the exception
    @rip: value of the RIP register when the exception is raised
    @jitter: jitload instance
    @pe: PE instance
    """

    image_base = pe.NThdr.ImageBase    
    pdata_dir = pe.NThdr.optentries[3]  # Exception Directory
    pdata_addr = image_base + pdata_dir.rva
    pdata_count = pdata_dir.size // RuntimeFunction.sizeof()

    # each runtime function covers an adress range bounded by rvas
    rva = rip - image_base
    lo, hi = 0, pdata_count - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        entry_addr = pdata_addr + mid * RuntimeFunction.sizeof()
        rf = RuntimeFunction(jitter.vm, entry_addr)
        if rf.BeginAddress <= rva < rf.EndAddress:
            return rf, entry_addr
        elif rva < rf.BeginAddress:
            hi = mid - 1
        else:
            lo = mid + 1
    return None, None


def parse_unwind_info(jitter, unwind_rva):
    """
    parse UNWIND_INFO including the UNWIND_CODE table.
    The UNWIND_CODE table is needed when no handler is found in the current
    frame
    @jitter: jitload instance
    @unwind_rva : UnwindData address from the runtime function found in .pdata
    """

    image_base = pe.NThdr.ImageBase 
    addr = image_base + unwind_rva

    # parse the beginning of the unwind_info
    hdr = UnwindInfoHeader(jitter.vm, addr)
    version = hdr.VersionAndFlags & 0x7
    flags = (hdr.VersionAndFlags >> 3) & 0x1F
    frame_register = hdr.FrameRegisterAndOffset & 0xF
    frame_offset = (hdr.FrameRegisterAndOffset >> 4) & 0xF

    cursor = addr + UnwindInfoHeader.sizeof()
    codes = []
    i=0
    while i < hdr.CountOfCodes:
        # parse each entry of the unwind_code table
        code = UnwindCode(jitter.vm, cursor)
        unwind_op = code.UnwindOpAndInfo & 0xF
        op_info = (code.UnwindOpAndInfo >> 4) & 0xF

        entry = {"CodeOffset": code.CodeOffset, "UnwindOp": unwind_op, "OpInfo": op_info}
        
        codes.append(entry)
        i+=1
    
    if hdr.CountOfCodes % 2 == 1:
        cursor += 2  # TODO ? padding ?

    # TODO verif ce qui est nécessaire, partial
    parsed_unwind_info = {
        "Version": version, "Flags": flags,
        "FrameRegister": frame_register, "FrameOffset": frame_offset,
        "SizeOfProlog": hdr.SizeOfProlog,
        "UnwindCodes": codes,
        "ExceptionHandler": None, "ScopeTableAddr": None,
        "ChainedFunctionEntry": None, # ?? c'est quoi ça ?
    }    

    # variable part of the unwind_info, depends on the flag
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        handler_rva = upck32(jitter.vm.get_mem(cursor, 4))
        parsed_unwind_info["ExceptionHandler"] = image_base + handler_rva
        parsed_unwind_info["ScopeTableAddr"] = cursor + 4
    elif flags & UNW_FLAG_CHAININFO:
        parsed_unwind_info["ChainedFunctionEntry"] = RuntimeFunction(jitter.vm, cursor)

    return parsed_unwind_info



def virtual_unwind_step(jitter, unwind_info, ctx):
    """
    unwind a frame to find the caller
    update the context
    @jitter: jitter instance
    @unwind_info: parsing of the UNWIND_INFO structure
    """

    # example of stack unwind : 
    # let's say we have the following instructions in the prolog :
    # push rbx
    # sub rsp, 0x40

    # UWOP_ALLOC_SMALL : RSP += 0x40
    # UWOP_PUSH_NONVOL : RBX = [RSP], RSP +=8
    # the goal is to make RSP points to the return adress to find the caller

    # an entry in the unwind_code[] table is called a slot
    # more than one slot may be needed to cover a single instruction

    # for entry in unwind_info["UnwindCodes"]:
    i=0
    while i < len(unwind_info["UnwindCodes"]):
        entry = unwind_info["UnwindCodes"][i]
        op = entry["UnwindOp"]

        if op == UWOP_PUSH_NONVOL:
            # push reg -> reg = *(RSP) ; RSP += 8
            reg_name = GPR_FROM_OPINFO.get(entry["OpInfo"])
            if reg_name is not None:
                # val = upck64(jitter.vm.get_mem(jitter.cpu.RSP, 8))
                val = upck64(jitter.vm.get_mem(ctxt.RSP, 8))
                # setattr(jitter.cpu, reg_name, val)
                setattr(ctxt, reg_name, val)
            # jitter.cpu.RSP += 8
            ctxt.RSP +=8
            i+=1

        elif op == UWOP_ALLOC_SMALL:
            # sub rsp, n -> RSP += n
            # jitter.cpu.RSP += entry["OpInfo"] * 8 + 8
            ctxt.RSP += entry["OpInfo"] * 8 + 8
            i+=1
        
        elif op == UWOP_ALLOC_LARGE:
            if entry["OpInfo"] == 0:
                # check the next slot to recover the size of the allocation
                # jitter.cpu.RSP += unwind_info["UnwindCodes"][i+1]["OpInfo"] * 8
                ctxt.RSP += unwind_info["UnwindCodes"][i+1]["OpInfo"] * 8
                i+=2

            elif entry["OpInfo"] == 1 :
                # check the two next slots
                # TODO possibilité de pb d'endianness dans le parsing de unwind_code ?
                # TODO possibilité de mauvaise taille dans le parsing

                lo = unwind_info["UnwindCodes"][i+1]["OpInfo"]
                hi = unwind_info["UnwindCodes"][i+2]["OpInfo"]

                size = (lo & 0xFFFF) | ((hi & 0xFFFF) << 16)
                # jitter.cpu.RSP += size
                ctxt.RSP += size
                i+=3

        elif op == UWOP_SET_FPREG:
            i+=1

        elif op == UWOP_SAVE_NONVOL:
            # mov [rsp+Offset], reg 
            reg_name = GPR_FROM_OPINFO.get(entry["OpInfo"])

            if reg_name is not None:
                # offset in the next slot
                offset_scaled = unwind_info["UnwindCodes"][i+1]["OpInfo"]
                offset = offset_scaled * 8
                # val = upck64(jitter.vm.get_mem(jitter.cpu.RSP + offset, 8))
                val = upck64(jitter.vm.get_mem(ctxt.RSP + offset, 8))
                # setattr(jitter.cpu, reg_name, val) 
                setattr(ctxt, reg_name, val)       
                
            i+=2

        elif op == UWOP_SAVE_NONVOL_FAR:
            # mov [rsp+Offset], reg 
            reg_name = GPR_FROM_OPINFO.get(entry["OpInfo"])

            lo = unwind_info["UnwindCodes"][i+1]["OpInfo"]
            hi = unwind_info["UnwindCodes"][i+2]["OpInfo"]

            offset = (lo & 0xFFFF) | ((hi & 0xFFFF) << 16)
            if reg_name is not None:
                # offset in the next slot
                offset_scaled = unwind_info["UnwindCodes"][i+1]["OpInfo"]
                offset = offset_scaled * 8
                # val = upck64(jitter.vm.get_mem(jitter.cpu.RSP + offset, 8))
                val = upck64(jitter.vm.get_mem(ctxt.RSP + offset, 8))
                # setattr(jitter.cpu, reg_name, val)  
                setattr(ctxt, reg_name, val)       
                
            i+=3

        elif op in (UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR):
            #TODO
            log.debug("  UWOP_SAVE_XMM128(_FAR) ignore")

            if op == UWOP_SAVE_XMM128:
                i+=2
            else:
                i+=3

        elif op = UWOP_PUSH_MACHFRAME:
            log.error("  UWOP_PUSH_MACHFRAME : not supported")
            return False

    # ret_addr = upck64(jitter.vm.get_mem(jitter.cpu.RSP, 8))
    ret_addr = upck64(jitter.vm.get_mem(ctxt.RSP, 8))
    # jitter.cpu.RSP += 8
    ctxt.RSP += 8
    return ret_addr

def compute_establisher_frame(jitter, unwind_info, rsp_at_entry, ctxt):
    """
    The establisher frame is a stack address used to identify the frame of
    the function which has a handler.
    Its computed to fill the DispatcherContext structure used to call the handler

    The handler pass it to RtlUnwindEx as a target frame during the unwind before
    jumping in the __except bloc... à supprimer TODO
    """
    if unwind_info["FrameRegister"] == 0:
        return rsp_at_entry

    reg_num = unwind_info["FrameRegister"]
    reg = FRAME_REGISTERS.get(reg_num)
    frame = getattr(ctxt, reg) - unwind_info["FrameOffset"] * 16

    return frame

def parse_scope_table(jitter, addr):
    hdr = ScopeTableHeader(jitter.vm, addr)
    records = []
    cursor = addr + ScopeTableHeader.sizeof()
    for _ in range(hdr.Count):
        rec = ScopeRecord(jitter.vm, cursor)
        records.append(rec)
        cursor += ScopeRecord.sizeof()
    return records

def dispatcher64(jitter, exception_code):
    """
    Create an exception context
    @jitter: jitter instance
    @except_code: x86_64 exception code
    """

    log.info("Exception 0x%X a RIP=0x%X", exception_code, jitter.pc)

    # create an exception record
    rec = ExceptionRecord64(jitter.vm, EXCEPTION64_RECORD_AD)
    rec.memset(b"\x00")
    rec.ExceptionCode = exception_code
    rec.ExceptionAddress = jitter.pc

    # save a CONTEXT
    ctxt = regs2ctxt64(jitter, CONTEXT64_AD)
    # copy of the context to work on for the unwind
    ## TODO je copieça ou ? 
    copy_ctxt = regs2ctxt64(jitter, )

    cur_rip = jitter.pc
    cur_rsp = jitter.cpu.RSP
    steps = 0

    # look for a runtime fonction for the current rip
    while steps < MAX_UNWIND_STEPS:
        steps += 1
        rf, function_entry_addr = lookup_function_entry(jitter, cur_rip)

        if rf is None:
            log.info("  frame leaf (rip=0x%X), step back [rsp]", cur_rip)
            cur_rip = leaf_unwind_step(jitter, copy_ctxt)
            continue

        unwind_info = parse_unwind_info(jitter, rf.UnwindData)
        rva = cur_rip - image_base

        if not (unwind_info["Flags"] & UNW_FLAG_EHANDLER):
            # UNW_FLAG_UHANDLER or UNW_FLAG_CHAININFO
            log.info("  no handler in this frame (rip=0x%X), checking the caller", cur_rip)
            ret = virtual_unwind_step(jitter, unwind_info, copy_ctxt)
            if ret is False:
                return False
            cur_rip = ret
            continue

        ## appeler le handler ??
        ## signature cf https://github.com/reactos/reactos/blob/master/sdk/include/vcruntime/excpt.h
        # EXCEPTION_DISPOSITION
        # __cdecl
        # __C_specific_handler(
        #     _In_ struct _EXCEPTION_RECORD *_ExceptionRecord,
        #     _In_ void *_EstablisherFrame,
        #     _Inout_ struct _CONTEXT *_ContextRecord,
        #     _Inout_ struct _DISPATCHER_CONTEXT *_DispatcherContext);

        # the establisher frame is the stack address that identifies the frame
        # of the function that posesses the handler 
        frame = compute_establisher_frame()

        dc = DispatcherContext64(jitter.vm, DISPATCHER_CONTEXT64_AD)
        dc.ControlPc = ctxt.rip
        dc.ImageBase = image_base = main_pe.NThdr.ImageBase
        dc.FunctionEntry = function_entry_addr
        dc.EstablisherFrame = frame
        dc.TargetIp = 0
        dc.ContextRecord = CONTEXT64_AD  
        dc.LanguageHandler = unwind_info["ExceptionHandler"]
        dc.HandlerData = unwind_info["ScopeTableAddr"]
        dc.HistoryTable = 0
        dc.ScopeIndex = 0

        # get space on stack
        fault_rsp = jitter.cpu.RSP
        ## ??
        new_rsp = ((fault_rsp - 0x100) & ~0xf) - 8

        # prepare the arguments
        jitter.cpu.RCX = EXCEPTION_RECORD64_AD
        jitter.cpu.RDX = frame
        jitter.cpu.R8 = CONTEXT64_AD
        jitter.cpu.R9 = DISPATCHER_CONTEXT64_AD
        jitter.cpu.RSP = new_rsp


        # c'est le job du handler de parser la scope table...
        records = parse_scope_table(jitter, unwind_info["ScopeTableAddr"])
        record = None
        # find the right record in the scope table
        for rec_i in records:
            if rec_i.BeginAddress <= rva < rec_i.EndAddress:
                record = rec_i
                break

        if record is None:
            log.info("  no scope record for rva=0x%X, unwind", rva)
            ret = virtual_unwind_step(jitter, unwind_info, copy_ctxt)
            if ret is False:
                return False
            cur_rip = ret
            continue

        if record.HandlerAddress == 1:
            # parfois c'est un nb parfois il faut exec le filtre pr avoir le nb ? 
            # __except(EXCEPTION_EXECUTE_HANDLER) 
            disposition = EXCEPTION_EXECUTE_HANDLER
        else:
            log.warning("  filter at 0x%X not emulated, EXCEPTION_EXECUTE_HANDLER by default",
                        image_base + record.HandlerAddress)
            disposition = EXCEPTION_EXECUTE_HANDLER

        if disposition == EXCEPTION_CONTINUE_SEARCH:
            ret = virtual_unwind_step(jitter, unwind_info, copy_ctxt)
            if ret is False:
                return False
            cur_rip = ret
            continue

        # RtlUnwindEx -> RTlpUnwindInternal
        # https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/amd64/unwind.c#L721
        # RtlUnwindEx(
        #     _In_opt_ PVOID TargetFrame,
        #     _In_opt_ PVOID TargetIp,
        #     _In_opt_ PEXCEPTION_RECORD ExceptionRecord,
        #     _In_ PVOID ReturnValue,
        #     _In_ PCONTEXT ContextRecord,
        #     _In_opt_ struct _UNWIND_HISTORY_TABLE *HistoryTable)        
        
        target_ip = image_base + record.JumpTarget
        establisher_frame = compute_establisher_frame(jitter, unwind_info, cur_rsp)
        log.info("  EXECUTE_HANDLER : unwind -> 0x%X, jump __except=0x%X",
                  establisher_frame, target_ip)

        jitter.cpu.RSP = establisher_frame # insuffisant pr recréer l'environnement
        #où doit s'exécuter le bloc except il faut unwind
        # il faut re chercher la runtime function pr le unwindcontext.rip 
        #(copie du context), pr chaque frame jusqu'à arriver à la targetframe en
        # en appliquant les unwindcode, 
        # target frame = establisher frame
        # donc ensuite je peux juste retablir dans le cpu le contexte simulé
        # et faire pc = jump target
        # qd on fait l'unwind ya des handler terminaux à prendre en compte ? 
        jitter.pc = target_ip
        return True

    log.error("SEH x64 : aucun handler trouve pour 0x%X, arret", exception_code)
    return False