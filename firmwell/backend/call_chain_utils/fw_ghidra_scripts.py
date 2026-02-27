import os
from ghidra.program.model.data import StringDataType, PointerDataType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.block import BasicBlockModel, PartitionCodeSubModel
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException

# Functions to analyze
TARGET_FUNCS = [
                "execve",
                "execvp",
                "execl",
                "execv",
                "execlp",
                "execle",
                "_eval",
                "system",
                "doSystem",
                "SYSTEM", # AC2100_V1.2.0.62_1.0.1
                "os_taskCreate", # Archer_MR200,
                "eval", # FW_RT_ACRH12_300438252272
                ]

syms = {}
analyzer = None

spec = currentProgram.getCompilerSpec()
convention = spec.getDefaultCallingConvention()


def is_string_data(data):
    """
    Determine if 'data' is recognized as a string, either by type or value.
    """
    if not data:
        return False
    dt = data.getDataType()
    if isinstance(dt, StringDataType):
        return True
    if data.hasStringValue():
        return True
    return False


def get_string_value(data):
    """
    Retrieve a string from the given data if possible.
    """
    if data is None:
        return None
    if data.hasStringValue():
        return str(data.getValue())
    dt = data.getDataType()
    if isinstance(dt, StringDataType):
        return str(data)
    return None


def get_strings_from_instruction(insn):
    """
    Scan all operand references of 'insn' for data references to strings.
    Return a list of (dataAddress, stringValue).
    """
    results = []
    if not insn:
        return results

    num_ops = insn.getNumOperands()
    for op_index in range(num_ops):
        op_refs = insn.getOperandReferences(op_index)
        for ref in op_refs:
            if ref.getReferenceType().isData():
                data_addr = ref.getToAddress()
                data_obj = getDataAt(data_addr)
                if data_obj and is_string_data(data_obj):
                    s = get_string_value(data_obj)
                    if s:
                        results.append((data_addr, s))
    return results


def get_callsite_strings(caller_func, call_insn_addr):
    """
    Given a caller function and the address of the callsite instruction,
    gather string references from the same basic block or a close proximity
    to the callsite instruction.
    """
    references = []
    body = caller_func.getBody()
    listing = currentProgram.getListing()
    insn_iter = listing.getInstructions(body, True)

    # Collect all strings in the function
    func_str_map = {}
    while insn_iter.hasNext():
        insn = insn_iter.next()
        insn_addr = insn.getMinAddress()
        found_strs = get_strings_from_instruction(insn)
        if found_strs:
            if insn_addr not in func_str_map:
                func_str_map[insn_addr] = []
            func_str_map[insn_addr].extend(found_strs)

    # Use Ghidra's BasicBlockModel to find the block containing `call_insn_addr`
    bb_model = BasicBlockModel(currentProgram)
    call_block = bb_model.getFirstCodeBlockContaining(call_insn_addr, monitor)
    if not call_block:
        print("[!] Could not find the basic block for callsite at 0x{}".format(call_insn_addr))
        return []

    # Collect references within the basic block
    block_strs = []
    block_min = call_block.getMinAddress()
    block_max = call_block.getMaxAddress()

    # Iterate over the instructions in the block and collect strings
    block_insn_iter = listing.getInstructions(block_min, True)
    while block_insn_iter.hasNext():
        insn = block_insn_iter.next()
        insn_addr = insn.getMinAddress()
        if insn_addr > block_max:
            break
        if insn_addr in func_str_map:
            block_strs.extend(func_str_map[insn_addr])

    return block_strs

# def get_callsite_strings(caller_func, call_insn_addr):
#     """
#     Given a caller function and the address of the callsite instruction,
#     gather string references from the instructions that are likely associated
#     with this call.
#
#     Approach 1 (simple):
#       - We just scan the entire caller function and collect all strings.
#         Then we filter or group them by block/instruction proximity if desired.
#
#     Approach 2 (more advanced):
#       - We only collect references from the same basic block or a small
#         window of instructions around 'call_insn_addr'.
#
#     Here, we do Approach 1 for simplicity, then optionally filter
#     by basic block or window size.
#     """
#     # 1) Gather all instructions in the caller function,
#     #    collect the strings from each.
#     references = []
#     body = caller_func.getBody()
#     listing = currentProgram.getListing()
#     insn_iter = listing.getInstructions(body, True)
#
#     # We'll keep track of addresses -> list of (stringAddr, stringVal)
#     func_str_map = {}
#
#     while insn_iter.hasNext():
#         insn = insn_iter.next()
#         insn_addr = insn.getMinAddress()
#         found_strs = get_strings_from_instruction(insn)
#         if found_strs:
#             if insn_addr not in func_str_map:
#                 func_str_map[insn_addr] = []
#             func_str_map[insn_addr].extend(found_strs)
#
#     # 2) You can filter the instructions by block or a small
#     #    address range around the call instruction.
#     #    For now, let's gather everything in the same basic block.
#     #    If that's too broad/narrow, adjust as needed.
#
#     # Identify the basic block containing call_insn_addr
#     fm = currentProgram.getFunctionManager()
#     bfmodel = fm.getBasicBlockModel()
#     block_iter = bfmodel.getCodeBlocksContaining(call_insn_addr, monitor)
#     call_block = None
#     if block_iter.hasNext():
#         call_block = block_iter.next()
#
#     # If we found the block, gather all instructions in that block
#     # that reference strings
#     block_strs = []
#     if call_block:
#         # We'll define the block by (minAddr, maxAddr)
#         block_min = call_block.getMinAddress()
#         block_max = call_block.getMaxAddress()
#         # Collect references that appear within this block
#         block_body_iter = listing.getInstructions(block_min, True)
#         while block_body_iter.hasNext():
#             i = block_body_iter.next()
#             i_addr = i.getMinAddress()
#             if i_addr > block_max:
#                 break
#             if i_addr in func_str_map:
#                 block_strs.extend(func_str_map[i_addr])
#
#     # Return block_strs as the "associated" strings for that callsite
#     return block_strs

def getAnalyzer():
    """
    Retrieve and cache the ConstantPropagationAnalyzer instance,
    which is used to drive SymbolicPropogator flow.
    """
    global analyzer
    if analyzer is not None:
        return analyzer

    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        raise Exception("Could not find suitable ConstantPropagationAnalyzer!")
    return analyzer

def get_register_offset_by_idx(index):
    """Get the register offset for a function argument at the given index."""
    data_type = PointerDataType()
    reg = convention.getArgLocation(index, None, data_type, currentProgram).getRegister()
    return reg.getOffset() # int

def get_register_name_by_idx(index):
    """Get the register name for a function argument at the given index."""
    data_type = PointerDataType()
    reg = convention.getArgLocation(index, None, data_type, currentProgram).getRegister()
    return reg.toString()

def getFunction(name):
    """Find a function by name in the current program."""
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() == name:
            print("\nFound '{}' @ 0x{}".format(name, func.getEntryPoint()))
            return func
    return None

def setUpDecompiler():
    """Initialize and configure the Ghidra decompiler interface."""
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    decomp_interface = decomp_interface

    options = DecompilerUtils.getDecompileOptions(state.getTool(), currentProgram)
    decomp_interface.setOptions(options)
    decomp_interface.toggleCCode(True)
    decomp_interface.toggleSyntaxTree(True)
    decomp_interface.setSimplificationStyle("decompile")

    return decomp_interface

def getAddress_obj(offset):
    """Convert a numeric offset to a Ghidra Address object in the default address space."""
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# def getStr(memAddr):
#     """
#     Read bytes from memory, starting at 'memAddr', until a null terminator.
#     Return the collected string (Python str), or None on error.
#     """
#
#     if memAddr is None:
#         return None
#
#     result = None
#     try:
#         while True:
#             b = getByte(memAddr)
#             if b < 0:
#                 # getByte may return -1 on error
#                 return None
#             if b == 0:
#                 # Null terminator
#                 break
#             result += chr(b & 0xff)
#             memAddr = memAddr.add(1)
#     except Exception as e:
#         print("Error: {}".format(e))
#         return None
#     return None

def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return None
    return ret[:-1]

def find_call_pcode_op_ast(high_function, call_addr):
    """
    Find the CALL Pcode operation at the specified address.
    :param high_function: The HighFunction object containing Pcode operations.
    :param call_addr: The address of the CALL operation.
    :return: The CALL Pcode operation or None if not found.
    """
    print("call_addr: ", call_addr)
    print("call_addr.getPhysicalAddress(): ", call_addr.getPhysicalAddress())

    ops = high_function.getPcodeOps(call_addr.getPhysicalAddress())
    while ops.hasNext():
        op = ops.next()
        if op.getOpcode() == PcodeOp.CALL:
            return op
    return None


def get_constant_value_by_pcode(pcode_ops, arg_idx, high_function=None):
    """
    Extract a constant value for a function argument by analyzing Pcode operations.
    Handles COPY, PTRSUB, LOAD, and INDIRECT operations.
    """
    arg_offset = get_register_offset_by_idx(arg_idx)
    print("arg_offset: ", arg_offset)

    for op in pcode_ops:
        print("op: ", op)
        if op.getOpcode() == PcodeOp.COPY and op.getOutput().getOffset() == arg_offset:
            input = op.getInput(0)
            print(input)
            if input.isAddress():
                space = input.getAddress().getAddressSpace().getName()
                print(space)
                if space == "ram":
                    return getInt(toAddr(input.getOffset())) # MIPS pointer
                else:
                    # (register, 0x20, 4) COPY (const, 0x1125d8, 4)
                    return op.getInput(0).getOffset()
            elif input.isConstant():
                return input.getOffset()
        
                # Handle PTRSUB operations that compute stack addresses
        elif op.getOpcode() == PcodeOp.PTRSUB and op.getOutput().getOffset() == arg_offset:
            # The PTRSUB operation computes a stack address
            stack_offset = op.getInput(1).getOffset() & 0xFFFFFFFF  # Convert to unsigned if negative
            print("Found stack offset: ", hex(stack_offset))
            
            # First try to find the value in the current pcode operations
            value = find_stack_stored_value(pcode_ops, stack_offset)
            if value is not None:
                return value
                
            # If not found and we have the high function, search the entire function
            if high_function is not None:
                return analyze_whole_function_for_value(high_function, stack_offset)
            
        # Handle LOAD operations that read from stack
        elif op.getOpcode() == PcodeOp.LOAD and op.getOutput().getOffset() == arg_offset:
            space_id = op.getInput(0)
            if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
                offset_expr = op.getInput(1)
                if offset_expr.isConstant():
                    stack_offset = offset_expr.getOffset() & 0xFFFFFFFF
                    print("Found stack load offset: ", hex(stack_offset))
                    
                    # First try the basic block
                    value = find_stack_stored_value(pcode_ops, stack_offset)
                    if value is not None:
                        return value
                        
                    # Then try the whole function
                    if high_function is not None:
                        return analyze_whole_function_for_value(high_function, stack_offset)
        
        # Handle INDIRECT operations
        elif op.getOpcode() == PcodeOp.INDIRECT and op.getOutput().getOffset() == arg_offset:
            input_val = op.getInput(0)
            if input_val.isAddress():
                space = input_val.getAddress().getAddressSpace().getName()
                if space == "stack":
                    stack_offset = input_val.getOffset() & 0xFFFFFFFF
                    print("Found indirect stack reference: ", hex(stack_offset))
                    if high_function is not None:
                        return analyze_whole_function_for_value(high_function, stack_offset)

    return None


def dump_all_function_pcode(high_function):
    """
    Dumps all pcode operations in a function for debugging.
    """
    print("==== DUMPING ALL FUNCTION PCODE ====")
    blocks = high_function.getBasicBlocks()
    for block in blocks:
        print("--- Basic Block: {} to {} ---".format(block.getStart(), block.getStop()))
        ops_iter = block.getIterator()
        while ops_iter.hasNext():
            op = ops_iter.next()
            print(op)
    print("==== END FUNCTION PCODE DUMP ====")

def normalize_stack_offset(offset):
    """
    Normalize stack offsets to a consistent format by converting to unsigned 32-bit values.
    Both 0xffffffb4 and 0xffffffffffffffb4 will be normalized to the same value.
    """
    # Extract the lowest 32 bits and return as unsigned
    return offset & 0xFFFFFFFF

def find_stack_stored_value(pcode_ops, target_stack_offset):
    """
    Find a value stored to a specific stack offset before the function call.
    
    :param pcode_ops: List of Pcode operations in the basic block
    :param target_stack_offset: The stack offset to search for (relative to stack pointer)
    :return: The constant value stored at that stack location, or None if not found
    """
    # Normalize the target offset
    normalized_target = normalize_stack_offset(target_stack_offset)
    print("Normalized target stack offset: 0x{:x}".format(normalized_target))
    
    # First check for COPY operations that write directly to the stack variable
    for op in pcode_ops:
        print("find_stack_stored_value op", op)
        
        if op.getOpcode() == PcodeOp.COPY:
            output = op.getOutput()
            if output is not None and output.isAddress():
                addr_space = output.getAddress().getAddressSpace()
                if addr_space == currentProgram.getAddressFactory().getStackSpace():
                    # Normalize the stack offset for comparison
                    stack_offset = normalize_stack_offset(output.getOffset())
                    print("Checking COPY to stack offset: 0x{:x} vs target 0x{:x}".format(stack_offset, normalized_target))
                    if stack_offset == normalized_target:
                        print("Found COPY to target stack offset: {}".format(op))
                        input_val = op.getInput(0)
                        if input_val.isConstant():
                            return input_val.getOffset()
                        elif input_val.isAddress():
                            return input_val.getOffset()
        
        # Then check STORE operations
        elif op.getOpcode() == PcodeOp.STORE:
            print("STORE op: ", op)
            
            # Check if this is a store to stack
            space_id = op.getInput(0)
            if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
                # This is a store to stack
                offset_expr = op.getInput(1)
                
                # Normalize the stack offset for comparison
                if offset_expr.isConstant():
                    stack_offset = normalize_stack_offset(offset_expr.getOffset())
                    print("Checking STORE to stack offset: 0x{:x} vs target 0x{:x}".format(stack_offset, normalized_target))
                    if stack_offset == normalized_target:
                        # Get the value being stored
                        value = op.getInput(2)
                        
                        # If it's a direct constant
                        if value.isConstant():
                            return value.getOffset()
                        
                        # If it's a register that was previously loaded with a constant
                        if value.isRegister():
                            reg_offset = value.getOffset()
                            # Look for previous operation that set this register
                            for prev_op in pcode_ops:
                                if prev_op == op:
                                    # Don't search past the current operation
                                    break
                                
                                if prev_op.getOpcode() == PcodeOp.COPY and prev_op.getOutput() is not None and prev_op.getOutput().getOffset() == reg_offset:
                                    input_val = prev_op.getInput(0)
                                    if input_val.isConstant():
                                        return input_val.getOffset()
                                    elif input_val.isAddress():
                                        return input_val.getOffset()
                        
                        # If it's an address
                        if value.isAddress():
                            return value.getOffset()
    
    return None

def analyze_whole_function_for_value(high_function, target_stack_offset):
    """
    Analyze the entire function to find values stored at a specific stack offset.
    """
    # Normalize the target offset
    normalized_target = normalize_stack_offset(target_stack_offset)
    print("Searching entire function for normalized stack offset: 0x{:x}".format(normalized_target))
    
    # Get all pcode blocks in the function
    blocks = high_function.getBasicBlocks()
    all_ops = []  # Collect all ops for analysis
    
    # First pass: collect all operations
    for block in blocks:
        ops_iter = block.getIterator()
        while ops_iter.hasNext():
            all_ops.append(ops_iter.next())
    
    # Debug: print all operations for analysis
    print("All operations in function:")

    # First, check for direct COPY operations to the target stack offset
    for op in all_ops:
        
        if op.getOpcode() == PcodeOp.COPY:
            output = op.getOutput()
            print("OP: {}".format(op), output)
            # if output is not None and output.isAddress():
            if output is not None:
                addr_space = output.getAddress().getAddressSpace()
                print("addr_space", addr_space)
                if addr_space == currentProgram.getAddressFactory().getStackSpace():
                    # Normalize the stack offset for comparison
                    stack_offset = normalize_stack_offset(output.getOffset())
                    print("Checking COPY to stack offset: 0x{:x} vs target 0x{:x}".format(stack_offset, normalized_target))
                    if stack_offset == normalized_target:
                        print("Found direct COPY to target stack offset: {}".format(op))
                        input_val = op.getInput(0)
                        if input_val.isConstant():
                            const_val = input_val.getOffset()
                            print("Direct constant value: {}".format(hex(const_val)))
                            return const_val
                        elif input_val.isAddress():
                            addr_val = input_val.getOffset()
                            print("Address value: {}".format(hex(addr_val)))
                            return addr_val

    
    # Then check for STORE operations to the target stack offset
    # untested
    # for op in all_ops:
    #     if op.getOpcode() == PcodeOp.STORE:
    #         space_id = op.getInput(0)
    #         if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
    #             offset_expr = op.getInput(1)
    #             if offset_expr.isConstant():
    #                 # Normalize the stack offset for comparison
    #                 stack_offset = normalize_stack_offset(offset_expr.getOffset())
    #                 print("Checking STORE to stack offset: 0x{:x} vs target 0x{:x}".format(stack_offset, normalized_target))
    #                 if stack_offset == normalized_target:
    #                     print("Found STORE to target offset: {}".format(op))
    #                     value = op.getInput(2)
                        
    #                     # Handle direct constant
    #                     if value.isConstant():
    #                         const_val = value.getOffset()
    #                         print("Direct constant: {}".format(hex(const_val)))
    #                         return const_val
                        
    #                     # Handle register value
    #                     if value.isRegister():
    #                         reg_offset = value.getOffset()
    #                         print("Register value, offset: {}".format(hex(reg_offset)))
    #                         reg_value = find_register_value_in_function(all_ops, reg_offset, op)
    #                         if reg_value is not None:
    #                             print("Register value resolved: {}".format(hex(reg_value)))
    #                             return reg_value
                        
    #                     # Handle address value
    #                     if value.isAddress():
    #                         addr_val = value.getOffset()
    #                         print("Address value: {}".format(hex(addr_val)))
    #                         return addr_val
    
    # # Look for data references relevant to this stack offset
    # data_refs = find_data_refs_in_function(high_function)
    # print("All data references in function:", data_refs)
    
    # # Additional debugging - print any other stack operations we can find
    # print("Checking all stack operations in the function:")
    # for op in all_ops:
    #     if op.getOpcode() == PcodeOp.COPY:
    #         output = op.getOutput()
    #         if output is not None and output.isAddress():
    #             addr_space = output.getAddress().getAddressSpace()
    #             if addr_space == currentProgram.getAddressFactory().getStackSpace():
    #                 stack_offset = normalize_stack_offset(output.getOffset())
    #                 print("Found COPY to stack: {} offset 0x{:x}".format(op, stack_offset))
                    
    #     elif op.getOpcode() == PcodeOp.STORE:
    #         space_id = op.getInput(0)
    #         if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
    #             offset_expr = op.getInput(1)
    #             if offset_expr.isConstant():
    #                 stack_offset = normalize_stack_offset(offset_expr.getOffset())
    #                 print("Found STORE to stack: {} offset 0x{:x}".format(op, stack_offset))
    
    return None

# def find_data_refs_in_function(high_function):
#     """
#     Find all data references in a function.
#     Returns a list of (instruction_addr, data_addr) tuples.
#     """
#     result = []
#     func = high_function.getFunction()
#     listing = currentProgram.getListing()
#     ref_mgr = currentProgram.getReferenceManager()
    
#     instructions = listing.getInstructions(func.getBody(), True)
#     for instr in instructions:
#         refs = ref_mgr.getReferencesFrom(instr.getMinAddress())
#         for ref in refs:
#             if ref.getReferenceType().isData():
#                 result.append((instr.getMinAddress(), ref.getToAddress().getOffset()))
    
#     return result

def find_register_value_in_function(all_ops, reg_offset, before_op=None):
    """
    Attempt to find the value of a register by analyzing operations.
    
    :param all_ops: List of all operations in the function
    :param reg_offset: The register offset to search for
    :param before_op: Only consider operations before this one (if provided)
    :return: The resolved constant value or None
    """
    # Search for operations that set this register
    for op in all_ops:
        if before_op and op == before_op:
            break
            
        if op.getOutput() is not None and op.getOutput().getOffset() == reg_offset:
            # Found an operation that sets this register
            print("Found operation setting register: {}".format(op))
            
            # For COPY operation, try to get the value directly
            if op.getOpcode() == PcodeOp.COPY:
                input_val = op.getInput(0)
                if input_val.isConstant():
                    return input_val.getOffset()
                elif input_val.isAddress():
                    return input_val.getOffset()
            
            # For LOAD operation, try to resolve the memory address
            elif op.getOpcode() == PcodeOp.LOAD:
                # Input 1 is the address to load from
                addr_val = op.getInput(1)
                if addr_val.isConstant():
                    # This is a direct memory address
                    addr = toAddr(addr_val.getOffset())
                    try:
                        # Try to read the value at this address
                        return getInt(addr)
                    except:
                        pass
    
    return None

# def find_value_from_assembly(func, arg_idx):
#     """
#     Fallback method to examine raw assembly for clues about arguments.
#     This is architecture-specific (mainly for MIPS).
#     """
#     print("Attempting to find value from assembly analysis")
    
#     # For MIPS, the first 4 args are in registers a0-a3 ($4-$7)
#     reg_name = get_register_name_by_idx(arg_idx)
#     print("Looking for values in register: {}".format(reg_name))
    
#     reg_num = None
#     if reg_name in ["a0", "$a0", "$4", "v0", "$v0", "$2"]:
#         reg_num = 4  # a0 register number
#     elif reg_name in ["a1", "$a1", "$5"]:
#         reg_num = 5  # a1 register number
#     elif reg_name in ["a2", "$a2", "$6"]:
#         reg_num = 6  # a2 register number
#     elif reg_name in ["a3", "$a3", "$7"]:
#         reg_num = 7  # a3 register number
    
#     if reg_num is None:
#         return None
    
#     listing = currentProgram.getListing()
#     instructions = listing.getInstructions(func.getBody(), True)
#     ref_mgr = currentProgram.getReferenceManager()
    
#     # Look for li instructions or other loads to this register
#     for instr in instructions:
#         mnemonic = instr.getMnemonicString()
        
#         # li reg, value (load immediate)
#         if mnemonic == "li" and instr.getNumOperands() >= 2:
#             try:
#                 reg = instr.getRegister(0)
#                 if reg.getNumber() == reg_num:
#                     # This is loading our target register
#                     # Check if this is a reference to a string
#                     refs = ref_mgr.getReferencesFrom(instr.getAddress())
#                     for ref in refs:
#                         if ref.getReferenceType().isData():
#                             data_addr = ref.getToAddress()
#                             data = listing.getDataAt(data_addr)
#                             if data and data.hasStringValue():
#                                 print("Found string reference in li: {} -> {}".format(
#                                     hex(data_addr.getOffset()), data.getValue()))
#                                 return data_addr.getOffset()
                    
#                     # If not a reference, it might be a direct value
#                     if instr.getOperandReferences(1):
#                         val = instr.getScalar(1).getValue()
#                         print("Found immediate value: {}".format(hex(val)))
#                         return val
#             except:
#                 continue
        
#         # lw reg, offset(base) (load word)
#         if mnemonic == "lw" and instr.getNumOperands() >= 2:
#             try:
#                 reg = instr.getRegister(0)
#                 if reg.getNumber() == reg_num:
#                     # This is loading our target register from memory
#                     refs = ref_mgr.getReferencesFrom(instr.getAddress())
#                     for ref in refs:
#                         if ref.getReferenceType().isData():
#                             data_addr = ref.getToAddress()
#                             print("Found data reference in lw: {}".format(hex(data_addr.getOffset())))
#                             # Try to follow the reference
#                             data = listing.getDataAt(data_addr)
#                             if data:
#                                 if data.hasStringValue():
#                                     print("Reference is a string: {}".format(data.getValue()))
#                                 return data_addr.getOffset()
#             except:
#                 continue
    
#     return None

def get_indirect_constant_value_by_pcode(pcode_ops, arg_idx, high_function=None):
    """Extract constant values for a function argument through indirect references (INDIRECT, PTRSUB, stack ops)."""
    arg_offset = get_register_offset_by_idx(arg_idx)
    print("arg_offset: ", arg_offset)

    res_set = set()

    # Check for INDIRECT operations in the basic block
    for op in pcode_ops:
        print("op: ", op)

        if op.getOpcode() == PcodeOp.INDIRECT:
            input = op.getInput(0)
            print(input)
            
            if input.isAddress() and input.getAddress().getAddressSpace().getName() == "ram":
                try:
                    addr_val = getInt(toAddr(input.getOffset()))
                    print(hex(addr_val))
                    res_set.add(addr_val)
                except MemoryAccessException:
                    pass
            
            elif input.isAddress() and input.getAddress().getAddressSpace() == currentProgram.getAddressFactory().getStackSpace():
                stack_offset = input.getOffset()
                normalized_offset = normalize_stack_offset(stack_offset)
                print("Checking indirect stack offset: 0x{:x} (normalized from 0x{:x})".format(normalized_offset, stack_offset))
                if high_function is not None:
                    val = analyze_whole_function_for_value(high_function, normalized_offset)
                    if val is not None:
                        res_set.add(val)

    # If we didn't find anything, search the entire function for stack variable initializations
    if len(res_set) == 0 and high_function is not None:
        blocks = high_function.getBasicBlocks()
        all_ops = []
        
        # Collect all operations
        for block in blocks:
            ops_iter = block.getIterator()
            while ops_iter.hasNext():
                all_ops.append(ops_iter.next())
        
        # First check for PTRSUB operations that involve our argument register
        for op in all_ops:
            if op.getOpcode() == PcodeOp.PTRSUB and op.getOutput().getOffset() == arg_offset:
                stack_offset = normalize_stack_offset(op.getInput(1).getOffset())
                print("Found PTRSUB for our argument register, stack offset: 0x{:x}".format(stack_offset))
                
                # Now look for all operations that write to this stack offset
                for check_op in all_ops:
                    # Check for COPY operations
                    if check_op.getOpcode() == PcodeOp.COPY:
                        output = check_op.getOutput()
                        if output is not None and output.isAddress():
                            addr_space = output.getAddress().getAddressSpace()
                            if addr_space == currentProgram.getAddressFactory().getStackSpace():
                                copy_offset = normalize_stack_offset(output.getOffset())
                                if copy_offset == stack_offset:
                                    input_val = check_op.getInput(0)
                                    if input_val.isConstant():
                                        print("Found constant value for stack offset: 0x{:x} = 0x{:x}".format(
                                            stack_offset, input_val.getOffset()))
                                        res_set.add(input_val.getOffset())
                                    elif input_val.isAddress():
                                        print("Found address value for stack offset: 0x{:x} = 0x{:x}".format(
                                            stack_offset, input_val.getOffset()))
                                        res_set.add(input_val.getOffset())
                    
                    # Check for STORE operations
                    elif check_op.getOpcode() == PcodeOp.STORE:
                        space_id = check_op.getInput(0)
                        if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
                            offset_expr = check_op.getInput(1)
                            if offset_expr.isConstant():
                                store_offset = normalize_stack_offset(offset_expr.getOffset())
                                if store_offset == stack_offset:
                                    value = check_op.getInput(2)
                                    if value.isConstant():
                                        print("Found constant value stored to stack offset: 0x{:x} = 0x{:x}".format(
                                            stack_offset, value.getOffset()))
                                        res_set.add(value.getOffset())
                                    elif value.isAddress():
                                        print("Found address value stored to stack offset: 0x{:x} = 0x{:x}".format(
                                            stack_offset, value.getOffset()))
                                        res_set.add(value.getOffset())
        
        # If we still haven't found anything, try searching for any COPY to stack that might contain valuable data
        if len(res_set) == 0:
            print("Searching for any stack COPY operations with constant/address values...")
            # Look for any COPY operations to stack
            for op in all_ops:
                if op.getOpcode() == PcodeOp.COPY:
                    output = op.getOutput()
                    if output is not None and output.isAddress():
                        addr_space = output.getAddress().getAddressSpace()
                        if addr_space == currentProgram.getAddressFactory().getStackSpace():
                            input_val = op.getInput(0)
                            if input_val.isConstant():
                                print("Found stack COPY with constant: {} = 0x{:x}".format(op, input_val.getOffset()))
                                # Check if this constant is a valid string address
                                try:
                                    addr = toAddr(input_val.getOffset())
                                    string = getStr(addr)
                                    if string is not None and len(string) > 0:
                                        print("Found potential string at address 0x{:x}: {}".format(input_val.getOffset(), string))
                                        res_set.add(input_val.getOffset())
                                except:
                                    pass
                            elif input_val.isAddress():
                                print("Found stack COPY with address: {} = 0x{:x}".format(op, input_val.getOffset()))
                                res_set.add(input_val.getOffset())
    
    return list(res_set)

def is_stack_arg_for_function_call(pcode_ops, stack_offset, arg_register_offset):
    """
    Check if a stack variable is used for a function argument.
    This handles the case where a value is stored to stack and then the stack address is used in a register.
    
    :param pcode_ops: List of pcode operations
    :param stack_offset: Normalized stack offset we're interested in
    :param arg_register_offset: Register offset for the function argument
    :return: True if the stack variable is used for the argument
    """
    for op in pcode_ops:
        if op.getOpcode() == PcodeOp.PTRSUB and op.getOutput().getOffset() == arg_register_offset:
            ptrsub_offset = normalize_stack_offset(op.getInput(1).getOffset())
            if ptrsub_offset == stack_offset:
                return True
    return False

def get_pcode_block(addr):
    """Find the Pcode basic block containing the given address."""
    address = addr

    func = getFunctionContaining(address)
    if func is None:
        print("No function found containing the address.")
        return None

    decompiler = setUpDecompiler()
    decomp_result = decompiler.decompileFunction(func, 60, monitor)
    if not decomp_result.decompileCompleted():
        print("Decompilation failed for function:", func.getName())
        return None

    high_func = decomp_result.getHighFunction()
    if high_func is None:
        print("Failed to retrieve HighFunction.")
        return None

    cfg = high_func.getBasicBlocks()
    from ghidra.program.model.pcode import PcodeBlockBasic

    for block in cfg:
        if isinstance(block, PcodeBlockBasic):
            start_addr = block.getStart()
            end_addr = block.getStop()

            if start_addr <= address <= end_addr:
                print("PcodeBlockBasic found:")
                print("Start Address:", start_addr)
                print("End Address:", end_addr)
                return block

    print("No PcodeBlockBasic found containing the address.")
    return None


def analyze_callsite(decomp_interface, caller_func, callsite_addr):
    """
    Analyze the `_eval` callsite to extract the first string argument.
    :param callsite_addr: The address of the function call.
    """

    print("caller_func: {}".format(caller_func))
    print("callsite_addr: {}".format(callsite_addr))

    # hf = get_high_function(caller_func)            # we need a high function from the decompiler
    # dump_refined_pcode(caller_func, hf)
    # exit(0)

    # flat_api = FlatProgramAPI(program)
    # listing = currentProgram.getListing()

    decompiled = decomp_interface.decompileFunction(caller_func, 120, monitor)

    # Locate the CALL operation at the callsite
    high_function = decompiled.getHighFunction()
    # pcode_ops = high_function.getPcodeOps(callsite_addr) # it seem like next bb pcode


    callOp = find_call_pcode_op_ast(high_function, callsite_addr)
    print("callOp: ", callOp)
    # print(dir(callOp))
    # print(callOp.getParent().getStart())
    # exit(0)

    if callOp is None:
        return []

    # get bb
    # ===========================
    paramVn = callOp.getInput(1) # execve()
    vnode = paramVn
    print("paramVn: ", paramVn)

    vnode_def = vnode.getDef()

    print("def: ", vnode_def)
    print("def.getParent().getStart(): ", vnode_def.getParent().getStart())
    print("def.getParent().getStop(): ", vnode_def.getParent().getStop())

    # basic_block = vnode_def.getParent() # R6200v2_V1.0.1.16_1.0.15, vnode_def get wrong bb
    basic_block = callOp.getParent()
    print("basic_block: ", basic_block)
    print("type(basic_block): ", type(basic_block))

    print("basic_block.getStart(): ", basic_block.getStart())
    print("basic_block.getStop(): ", basic_block.getStop())
    # Print the Pcode operations in the basic block
    pcode_ops = basic_block.getIterator()
    #
    # while pcode_ops.hasNext():
    #     print("PcodeOp: ", pcode_ops.next())


    # for some large bb, include multi call OP, filter the call OP
    filt_bb_pcode_ops = []
    for op in pcode_ops:
        filt_bb_pcode_ops.append(op)
        if op.getOpcode() == PcodeOp.CALL:
            if op.toString() == callOp.toString():
                break
            # # callOp = op
            # print("callOp: ", callOp)
            # print("callOp: ", callOp)
            # print("callOp: ", callOp)
            else:
                filt_bb_pcode_ops = []

    print("filt_bb_pcode_ops: ")
    for op in filt_bb_pcode_ops:
        print(op)

    # it will not happen
    if len(filt_bb_pcode_ops) == 0:
        filt_bb_pcode_ops = basic_block.getIterator()

    # ===========================


    # get bb new
    # block_model = BasicBlockModel(currentProgram)
    #
    # code_block_iter = block_model.getCodeBlocksContaining(callsite_addr, monitor)
    #
    # basic_block = iter(code_block_iter).next()
    # print("basic_block: ", basic_block)
    # print("basic_block.getStart(): ", basic_block.getStart())
    # print("basic_block.getStop(): ", basic_block.getStop())
    # pcode_ops = basic_block.getIterator()


    # get bb new 2
    # basic_block = get_pcode_block(callsite_addr)
    # print("basic_block: ", basic_block)
    # pcode_ops = basic_block.getIterator()
    #
    # while pcode_ops.hasNext():
    #     print("PcodeOp: ", pcode_ops.next())

    # Print the opcode of the definition
    # print("def.getOpcode(): ", vnode_def.getOpcode())


    # res = get_constant_value_by_pcode(pcode_ops, 0)
    res = get_constant_value_by_pcode(filt_bb_pcode_ops, 0, high_function)
    print("res: ", res)
    print("type(res)", type(res))

    # print("res getint ", getInt(toAddr(res)))
    # print("hex(res getint) ", hex(getInt(toAddr(res))))
    # print("str(res getint) ", getStr(toAddr(getInt(toAddr(res)))))

    tmp_res = set()
    if res is None or res == 0: # for multi-level pointer, try to get all potential value
        res_list = get_indirect_constant_value_by_pcode(filt_bb_pcode_ops, 0)
        if len(res_list) > 0:
            for r in res_list:
                s = getStr(toAddr(r))
                if s is not None:
                    tmp_res.add(s)

        if len(tmp_res) > 0:
            return list(tmp_res)

    else:
        s = getStr(toAddr(res))
        print("s: ", s)

        if s is None:
            return []
        else:
            return [s]

    return []

def get_arch():
    lang = currentProgram.getLanguage()
    processor = lang.getProcessor().toString().lower()   # "x86" / "arm" ...
    size = lang.getLanguageDescription().getSize()       # 32 or 64

    if "x86" in processor:
        if size == 64:
            return "x86_64"
        else:
            return "x86_32"
    elif "arm" in processor:
        return "arm"
    elif "mips" in processor:
        return "mips"
    else:
        return "other"

def getSymbolicRegisterValue(caller_func, callsite_addr):
    """Resolve the first argument register value at a callsite using symbolic propagation."""
    analyzer_inst = getAnalyzer()

    if caller_func in syms:
        symEval = syms[caller_func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)

        analyzer_inst.flowConstants(
            currentProgram,
            caller_func.getEntryPoint(),
            caller_func.getBody(),
            symEval,
            monitor
        )
        syms[caller_func] = symEval

    #DGN3500_V1.1.00.37NA rc
    """
    00406ecc 03 20 f8 09     jalr       t9=>SYSTEM                                       undefined SYSTEM()
    00406ed0 24 84 14 90     _addiu     a0=>s_/usr/sbin/mini_httpd_-d_/www_-r_"_004214   = "/usr/sbin/mini_httpd -d /www 
    00406ed4 8f bc 00 10     lw         gp,local_18(sp)
    """
    if "mips" in get_arch():
        callsite_addr = toAddr(callsite_addr.getOffset() + 8)

    reg_name = get_register_name_by_idx(0)
    reg = currentProgram.getRegister(reg_name)
    val = symEval.getRegisterValue(callsite_addr, reg)


    if val is None:
        return None
    if val.isRegisterRelativeValue():
        return None

    val = val.getValue()
    print("reg_name", reg_name)
    print("getSymbolicRegisterValue", "callsite_addr", callsite_addr, "val", hex(val))

    return val

def analyze_callsite_sym(caller_func, callsite_addr):
    """Analyze a callsite using symbolic propagation to extract the first string argument."""
    print("[analyze_callsite_sym] caller_func: {}, callsite_addr: {}".format(caller_func, callsite_addr))
    mem_addr = getSymbolicRegisterValue(caller_func, callsite_addr)

    if mem_addr is None:
        return None

    addr = toAddr(mem_addr)
    print("addr", addr)
    print("addr", type(addr))

    callsite_str = getStr(addr)
    return [callsite_str]

def function_references_target(func, string_value):
    """
    Check if function references the target string
    :param func: function object
    :param string_value: string to search for
    :return: bool
    """
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()
    
    instructions = listing.getInstructions(func.getBody(), True)
    for instr in instructions:
        refs = ref_mgr.getReferencesFrom(instr.getMinAddress())
        for ref in refs:
            if ref.getReferenceType().isData():
                data = listing.getDataAt(ref.getToAddress())
                if data and isinstance(data.getDataType(), StringDataType):
                    if data.getValue() == string_value:
                        return True
    return False

def should_analyze_function(caller_func, find_string_list):
    """
    Determine if we should analyze this function based on string references
    :param caller_func: function to check
    :param find_string_list: list of target strings
    :return: bool
    """
    if not find_string_list:
        return True
        
    referenced_strings = get_function_strings(caller_func)
    
    # Check if any target string is contained in any referenced string
    for ref_str in referenced_strings:
        for target in find_string_list:
            try:
                if str(target) in str(ref_str):
                    return True
            except:
                continue
                
    return False

def get_function_strings(func):
    """
    Get all string values referenced by the function
    :param func: function object
    :return: set of string values
    """
    referenced_strings = set()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    # Get all references to the function
    func_refs = ref_mgr.getReferencesTo(func.getEntryPoint())
    
    # Get all data references within the function body
    instructions = listing.getInstructions(func.getBody(), True)
    body_refs = []
    for instr in instructions:
        body_refs.extend(ref_mgr.getReferencesFrom(instr.getMinAddress()))
    
    # Combine all references
    all_refs = list(func_refs) + body_refs
    
    for ref in all_refs:
        if ref.getReferenceType().isData():
            address = ref.getToAddress()
            data = listing.getDataAt(address)
            
            # Check if data is a string
            if data and isinstance(data.getDataType(), StringDataType):
                try:
                    string_value = str(data.getValue())
                    if string_value and len(string_value) > 0:
                        referenced_strings.add(string_value)
                except:
                    continue
                    
    return referenced_strings

# def get_function_referenced_strings(func):
#     referenced_strings = []
#     instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
#     for instruction in instructions:
#         for opIndex in range(instruction.getNumOperands()):
#             operandRef = instruction.getOpObjects(opIndex)
#             for ref in operandRef:
#                 if isinstance(ref, ghidra.program.model.scalar.Scalar):
#                     scalar = ref
#                     if scalar.getValue() > 0x1000:  # Arbitrary threshold to filter out small values
#                         string = getStringAt(toAddr(scalar.getValue()))
#                         if string:
#                             referenced_strings.append(string)
#     return referenced_strings


# def analyze_function_strings(function):
#     """
#     Analyze all strings referenced within a function.
#     Returns a list of strings referenced by the function.
#     """
#     referenced_strings = set()
#     instructions = function.getBody()
#
#     for addr in instructions.getAddresses(True):
#         data = getDataAt(addr)
#
#         if data and isinstance(data.getDataType(), StringDataType):
#             string_value = data.getValue()
#             if string_value:
#                 referenced_strings.add(string_value)
#
#     return referenced_strings
def run(target_string):
    """Main analysis: find all subprocess commands invoked via exec/system calls."""
    execve_subprocess = set()

    arch = get_arch()
    print("[*] Detected architecture:", arch)
    print("[*] Target functions:", TARGET_FUNCS)

    decomp_interface = setUpDecompiler()

    # Get all strings in the binary
    find_string_list = []
    if len(target_string) > 0:
        all_strings = set()
        for data in currentProgram.getListing().getDefinedData(True):
            if isinstance(data.getDataType(), StringDataType):
                try:
                    string_val = str(data.getValue())
                    if string_val:
                        all_strings.add(string_val)
                except:
                    continue

        # Find strings that include the target string
        target_str = str(target_string)
        for s in all_strings:
            try:
                if target_str in s:
                    find_string_list.append(s)
                    print("Added string:", s)
            except:
                continue
        
        print("[*] Found strings matching target string:", target_str)
        for s in find_string_list:
            print("  - {}".format(s))


    for target_name in TARGET_FUNCS:
        tfunc = getFunction(target_name)
        if not tfunc:
            print("[!] Could not find function '{}'. Skipping.".format(target_name))
            continue

        target_addr = tfunc.getEntryPoint()
        refs = getReferencesTo(target_addr)
        callsite_count = 0

        print("[*] Searching for references to '{}' at 0x{}".format(target_name, target_addr))

        for ref in refs:
            try:
                callsite_addr = ref.getFromAddress()
                # Check if this is a call-type reference
                if not ref.getReferenceType().isCall():
                    print("skip",    hex(callsite_addr.getOffset()))
                    continue

                callsite_count += 1
                caller_func = getFunctionContaining(callsite_addr)
                if not caller_func:
                    continue

                caller_strs = get_function_strings(caller_func)

                print("caller_strs", caller_strs, should_analyze_function(caller_func, find_string_list))

                if len(target_string) > 0 and not should_analyze_function(caller_func, find_string_list):
                    continue

                print("[*] analyzing function '{}'".format(caller_func.getName()))
                # Gather strings associated with this callsite
                callsite_str = analyze_callsite_sym(caller_func, callsite_addr)
                
                if callsite_str is None:
                    callsite_str = analyze_callsite(decomp_interface, caller_func, callsite_addr)
                
                if len(callsite_str) > 0:
                    # Print each discovered string
                    print("Callsite at 0x{} -> {}:".format(callsite_addr, callsite_str))
                    execve_subprocess.update(set(callsite_str))
                else:
                    print("Callsite at 0x{} -> [UNRESOLVED]".format(callsite_addr))
            except Exception as e:
                import traceback
                print("[!] Error processing callsite at 0x{}: {}".format(callsite_addr, e))
                print("Traceback:")
                traceback.print_exc()
                continue

        print("[*] Found {} callsites for '{}'".format(callsite_count, target_name))

    print("\nDone!")
    return execve_subprocess


from ghidra.program.flatapi import FlatProgramAPI

def create_more_functions():
    """Discover and create additional function definitions at terminator boundaries."""
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(True)
    flatApi = FlatProgramAPI(currentProgram)
    monitor = flatApi.getMonitor()
    funcManager = currentProgram.getFunctionManager()

    while instructions.hasNext() and not monitor.isCancelled():
        instr = instructions.next()
        if instr.getFlowType() == RefType.TERMINATOR:
            try:
                funcAddr = instr.getMaxAddress().next()
                func = funcManager.getFunctionContaining(funcAddr)
                if func is None:
                    funcBeginInstr = listing.getInstructionAt(funcAddr)
                    if funcBeginInstr is None:
                        funcBeginInstr = listing.getInstructionAfter(funcAddr)
                        if funcBeginInstr is not None:
                            funcAddr = funcBeginInstr.getAddress()
                            if funcManager.getFunctionContaining(funcAddr) is not None:
                                continue
                    if funcBeginInstr is not None:
                        partitionBlockModel = PartitionCodeSubModel(currentProgram)
                        codeBlocks = partitionBlockModel.getCodeBlocksContaining(funcAddr, monitor)
                        if len(codeBlocks) != 1:
                            continue
                        address = codeBlocks[0].getFirstStartAddress()
                        newFunc = None
                        txId = currentProgram.startTransaction("createMoreFunc")
                        try:
                            newFunc = flatApi.createFunction(address, None)
                        except Exception as e:
                            print("Try to create function failed at 0x%x." % address.getOffset())
                        finally:
                            currentProgram.endTransaction(txId, True)
            except Exception as e:
                print(e)


if __name__ == "__main__":
    program_name = currentProgram.getName()

    args = getScriptArgs()
    print("args", args)

    result_path = list(args)[0]

    print("result_path", result_path)
    if not os.path.exists(result_path):
        os.makedirs(result_path)
    result_file = os.path.join(result_path, program_name)

    if len(args) > 1:
        target_string = list(args)[1]

    create_more_functions()

    execve_subprocess = run(target_string)

    print("\n\n")
    print("="*50)
    with open(result_file, "w") as f:
        for i in execve_subprocess:
            try:
                if all(ord(char) < 128 for char in i):  # Check if all characters are ASCII
                    print(i)
                    f.write("{}\n".format(i))
            except Exception as e:
                pass


