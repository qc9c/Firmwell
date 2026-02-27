import os
import json
from ghidra.program.model.data import StringDataType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.block import PartitionCodeSubModel

# Functions to analyze
TARGET_FUNCS = [
    "nvram_set",
    "nvram_get", 
    "nvram_safe_set",
    "nvram_safe_get",
    "nvram_match",
    "nvram_invmatch",
    "acosNvramConfig_set",
    "acosNvramConfig_get"
]

# Functions that compare nvram values
COMPARE_FUNCS = [
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp"
]

syms = {}
analyzer = None
nvram_data = {}  # Store extracted nvram key-value pairs

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
    data_type = PointerDataType()     # Set DataType as a pointer
    reg = convention.getArgLocation(index, None, data_type, currentProgram).getRegister()
    return reg.getOffset() # int


def get_register_name_by_idx(index):
    data_type = PointerDataType()     # Set DataType as a pointer
    reg = convention.getArgLocation(index, None, data_type, currentProgram).getRegister()
    return reg.toString()


def getFunction(name):
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() == name:
            print("\nFound '{}' @ 0x{}".format(name, func.getEntryPoint()))
            return func
    return None


def setUpDecompiler():
    # Initialize the decompiler interface
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    decomp_interface = decomp_interface

    # setUpDecompiler
    options = DecompilerUtils.getDecompileOptions(state.getTool(), currentProgram)
    decomp_interface.setOptions(options)
    decomp_interface.toggleCCode(True)
    decomp_interface.toggleSyntaxTree(True)
    decomp_interface.setSimplificationStyle("decompile")

    return decomp_interface


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
    """
    ops = high_function.getPcodeOps(call_addr.getPhysicalAddress())
    while ops.hasNext():
        op = ops.next()
        if op.getOpcode() == PcodeOp.CALL:
            return op
    return None


def normalize_stack_offset(offset):
    """
    Normalize stack offsets to a consistent format by converting to unsigned 32-bit values.
    """
    return offset & 0xFFFFFFFF


def find_stack_stored_value(pcode_ops, target_stack_offset):
    """
    Find a value stored to a specific stack offset before the function call.
    """
    normalized_target = normalize_stack_offset(target_stack_offset)
    
    for op in pcode_ops:
        if op.getOpcode() == PcodeOp.COPY:
            output = op.getOutput()
            if output is not None and output.isAddress():
                addr_space = output.getAddress().getAddressSpace()
                if addr_space == currentProgram.getAddressFactory().getStackSpace():
                    stack_offset = normalize_stack_offset(output.getOffset())
                    if stack_offset == normalized_target:
                        input_val = op.getInput(0)
                        if input_val.isConstant():
                            return input_val.getOffset()
                        elif input_val.isAddress():
                            return input_val.getOffset()
        
        elif op.getOpcode() == PcodeOp.STORE:
            space_id = op.getInput(0)
            if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
                offset_expr = op.getInput(1)
                if offset_expr.isConstant():
                    stack_offset = normalize_stack_offset(offset_expr.getOffset())
                    if stack_offset == normalized_target:
                        value = op.getInput(2)
                        if value.isConstant():
                            return value.getOffset()
                        if value.isRegister():
                            reg_offset = value.getOffset()
                            for prev_op in pcode_ops:
                                if prev_op == op:
                                    break
                                if prev_op.getOpcode() == PcodeOp.COPY and prev_op.getOutput() is not None and prev_op.getOutput().getOffset() == reg_offset:
                                    input_val = prev_op.getInput(0)
                                    if input_val.isConstant():
                                        return input_val.getOffset()
                                    elif input_val.isAddress():
                                        return input_val.getOffset()
                        if value.isAddress():
                            return value.getOffset()
    
    return None


def get_constant_value_by_pcode(pcode_ops, arg_idx, high_function=None):
    """
    Extract constant value for a function argument from pcode operations.
    """
    arg_offset = get_register_offset_by_idx(arg_idx)
    
    for op in pcode_ops:
        if op.getOpcode() == PcodeOp.COPY and op.getOutput().getOffset() == arg_offset:
            input = op.getInput(0)
            if input.isAddress():
                space = input.getAddress().getAddressSpace().getName()
                if space == "ram":
                    return getInt(toAddr(input.getOffset())) # MIPS pointer
                else:
                    return op.getInput(0).getOffset()
            elif input.isConstant():
                return input.getOffset()
        
        elif op.getOpcode() == PcodeOp.PTRSUB and op.getOutput().getOffset() == arg_offset:
            stack_offset = op.getInput(1).getOffset() & 0xFFFFFFFF
            value = find_stack_stored_value(pcode_ops, stack_offset)
            if value is not None:
                return value
            
        elif op.getOpcode() == PcodeOp.LOAD and op.getOutput().getOffset() == arg_offset:
            space_id = op.getInput(0)
            if space_id.isConstant() and space_id.getOffset() == currentProgram.getAddressFactory().getStackSpace().getSpaceID():
                offset_expr = op.getInput(1)
                if offset_expr.isConstant():
                    stack_offset = offset_expr.getOffset() & 0xFFFFFFFF
                    value = find_stack_stored_value(pcode_ops, stack_offset)
                    if value is not None:
                        return value

    return None


def get_arch():
    lang = currentProgram.getLanguage()
    processor = lang.getProcessor().toString().lower()
    size = lang.getLanguageDescription().getSize()

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


def getSymbolicRegisterValue(caller_func, callsite_addr, arg_idx=0):
    """
    Use symbolic propagation to get register value at callsite.
    """
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

    # Adjust for MIPS delay slot
    if "mips" in get_arch():
        callsite_addr = toAddr(callsite_addr.getOffset() + 8)

    reg_name = get_register_name_by_idx(arg_idx)
    reg = currentProgram.getRegister(reg_name)
    val = symEval.getRegisterValue(callsite_addr, reg)

    if val is None or val.isRegisterRelativeValue():
        return None

    return val.getValue()


def track_nvram_get_usage(high_function, nvram_get_call_op, key):
    """
    Track where the return value of nvram_get is used, particularly in strcmp calls.
    """
    values = []
    
    # Get the output varnode of the nvram_get call (return value)
    return_varnode = nvram_get_call_op.getOutput()
    if return_varnode is None:
        return values
    
    # Find all uses of this return value
    descendants = return_varnode.getDescendants()
    
    for desc_op in descendants:
        # Check if the return value flows into a strcmp call
        if desc_op.getOpcode() == PcodeOp.CALL:
            called_addr = desc_op.getInput(0)
            if called_addr.isAddress():
                func = getFunctionAt(called_addr.getAddress())
                if func and func.getName() in COMPARE_FUNCS:
                    # This is a strcmp-like function
                    # Check which argument position our nvram_get return value is in
                    for i in range(1, desc_op.getNumInputs()):
                        input_vn = desc_op.getInput(i)
                        if input_vn == return_varnode or is_descendant_of(input_vn, return_varnode):
                            # Our nvram_get return is argument i-1
                            # Get the other argument (comparison string)
                            other_idx = 2 if i == 1 else 1
                            if other_idx < desc_op.getNumInputs():
                                other_arg = desc_op.getInput(other_idx)
                                # Try to resolve the constant value
                                const_val = resolve_varnode_to_constant(other_arg, high_function)
                                if const_val:
                                    try:
                                        compare_str = getStr(toAddr(const_val))
                                        if compare_str:
                                            values.append(compare_str)
                                    except:
                                        pass
    
    return values


def is_descendant_of(varnode, ancestor):
    """
    Check if varnode is derived from ancestor through data flow.
    """
    if varnode == ancestor:
        return True
    
    def_op = varnode.getDef()
    if def_op is None:
        return False
    
    for i in range(def_op.getNumInputs()):
        input_vn = def_op.getInput(i)
        if is_descendant_of(input_vn, ancestor):
            return True
    
    return False


def resolve_varnode_to_constant(varnode, high_function):
    """
    Try to resolve a varnode to a constant value.
    """
    if varnode.isConstant():
        return varnode.getOffset()
    
    if varnode.isAddress():
        return varnode.getOffset()
    
    # Check if it's defined by a COPY from a constant
    def_op = varnode.getDef()
    if def_op and def_op.getOpcode() == PcodeOp.COPY:
        input_vn = def_op.getInput(0)
        if input_vn.isConstant():
            return input_vn.getOffset()
        elif input_vn.isAddress():
            return input_vn.getOffset()
    
    return None


def analyze_nvram_callsite(decomp_interface, caller_func, callsite_addr, target_name):
    """
    Analyze a callsite to extract nvram key-value information.
    """
    decompiled = decomp_interface.decompileFunction(caller_func, 120, monitor)
    high_function = decompiled.getHighFunction()
    
    callOp = find_call_pcode_op_ast(high_function, callsite_addr)
    if callOp is None:
        return None
    
    # Get the basic block containing the call
    basic_block = callOp.getParent()
    pcode_ops = []
    
    # Collect pcode ops up to the call
    ops_iter = basic_block.getIterator()
    while ops_iter.hasNext():
        op = ops_iter.next()
        pcode_ops.append(op)
        if op == callOp:
            break
    
    # Extract arguments based on function type
    if "set" in target_name.lower():
        # nvram_set(key, value) - extract both arguments
        key_val = get_constant_value_by_pcode(pcode_ops, 0, high_function)
        value_val = get_constant_value_by_pcode(pcode_ops, 1, high_function)
        
        if key_val is None:
            key_val = getSymbolicRegisterValue(caller_func, callsite_addr, 0)
        if value_val is None:
            value_val = getSymbolicRegisterValue(caller_func, callsite_addr, 1)
        
        if key_val and value_val:
            try:
                key_str = getStr(toAddr(key_val))
                value_str = getStr(toAddr(value_val))
                if key_str and value_str:
                    return ("set", key_str, value_str)
            except:
                pass
    
    elif "get" in target_name.lower():
        # nvram_get(key) - extract key and track usage
        key_val = get_constant_value_by_pcode(pcode_ops, 0, high_function)
        
        if key_val is None:
            key_val = getSymbolicRegisterValue(caller_func, callsite_addr, 0)
        
        if key_val:
            try:
                key_str = getStr(toAddr(key_val))
                if key_str:
                    # Track where the return value is used
                    compared_values = track_nvram_get_usage(high_function, callOp, key_str)
                    return ("get", key_str, compared_values)
            except:
                pass
    
    return None


def create_more_functions():
    """
    Create functions at addresses that appear to be function starts.
    """
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


def run():
    """
    Main analysis function.
    """
    global nvram_data
    nvram_data = {}
    
    arch = get_arch()
    print("[*] Detected architecture:", arch)
    print("[*] Target functions:", TARGET_FUNCS)
    
    decomp_interface = setUpDecompiler()
    
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
                    continue
                
                callsite_count += 1
                caller_func = getFunctionContaining(callsite_addr)
                if not caller_func:
                    continue
                
                print("[*] Analyzing callsite at 0x{} in function '{}'".format(
                    callsite_addr, caller_func.getName()))
                
                # Analyze the callsite
                result = analyze_nvram_callsite(decomp_interface, caller_func, callsite_addr, target_name)
                
                if result:
                    if result[0] == "set":
                        _, key, value = result
                        if key not in nvram_data:
                            nvram_data[key] = []
                        if value not in nvram_data[key]:
                            nvram_data[key].append(value)
                        print("  Found nvram_set: {} = {}".format(key, value))
                    
                    elif result[0] == "get":
                        _, key, compared_values = result
                        if key not in nvram_data:
                            nvram_data[key] = []
                        for val in compared_values:
                            if val not in nvram_data[key]:
                                nvram_data[key].append(val)
                        print("  Found nvram_get: {} compared with {}".format(key, compared_values))
                
            except Exception as e:
                import traceback
                print("[!] Error processing callsite at 0x{}: {}".format(callsite_addr, e))
                traceback.print_exc()
                continue
        
        print("[*] Found {} callsites for '{}'".format(callsite_count, target_name))
    
    print("\nDone!")
    return nvram_data


if __name__ == "__main__":
    from ghidra.program.flatapi import FlatProgramAPI
    
    program_name = currentProgram.getName()
    
    args = getScriptArgs()
    print("args", args)
    
    result_path = list(args)[0] if args else "/tmp/ghidra_nvram_result"
    
    print("result_path", result_path)
    if not os.path.exists(result_path):
        os.makedirs(result_path)
    
    result_file = os.path.join(result_path, program_name + "_nvram.json")
    
    # Create more functions if needed
    create_more_functions()
    
    # Run the analysis
    nvram_data = run()
    
    # Save results as JSON
    print("\n\n")
    print("="*50)
    print("Extracted NVRAM data:")
    
    # Filter out non-ASCII keys/values
    clean_nvram_data = {}
    for key, values in nvram_data.items():
        try:
            if all(ord(char) < 128 for char in key):
                clean_values = []
                for val in values:
                    if all(ord(char) < 128 for char in val):
                        clean_values.append(val)
                if clean_values:
                    clean_nvram_data[key] = clean_values
        except:
            pass
    
    # Print and save results
    for key, values in clean_nvram_data.items():
        print("{}: {}".format(key, values))
    
    with open(result_file, "w") as f:
        json.dump(clean_nvram_data, f, indent=2)
    
    print("\nResults saved to: {}".format(result_file))