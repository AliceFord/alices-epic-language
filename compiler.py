import re
import enum
import binascii
from sys import byteorder

class InstructionTypes(enum.Enum):
    FunctionStart = 1
    FunctionCall = 2
    FunctionEnd = 3
    VariableDef = 4
    VariableMod = 5
    VariableOperatorPlusEquals = 6
    ReturnFromFunc = 7


def parseLine(line):
    if "->" in line:  # function definition
        print(line)
        expr = "([a-zA-Z]*[0-9]+)([a-zA-Z][a-zA-Z0-9]*):(?:([a-zA-Z]*[0-9]+)([a-zA-Z][a-zA-Z0-9]*),)*(?:([a-zA-Z]*[0-9]+)([a-zA-Z][a-zA-Z0-9]*))?->{"
        matches = re.match(expr, line).groups()
        rtype = matches[0]
        funcname = matches[1]
        args = [*matches[2:]]
        for i in range(len(args)-1, -1, -1):
            if args[i] is None:
                args.pop(i)
        argsPaired = []
        for i in range(0, len(args), 2):
            argsPaired.append({"rtype": args[i], "varname": args[i+1]})
        return {
            "type": InstructionTypes.FunctionStart,
            "fname": funcname, 
            "rtype": rtype,
            "args": argsPaired
        }
    elif "=" in line and "==" not in line and "+=" not in line and "<=" not in line and ">=" not in line and "!=" not in line:
        if re.match(r"[a-zA-Z]*[0-9]+[a-zA-Z][a-zA-Z0-9]*=", line) is not None:  # variable definition
            expr = "([a-zA-Z]*[0-9]+)([a-zA-Z][a-zA-Z0-9]*)=(.*)"
            matches = re.match(expr, line).groups()
            vartype = matches[0]
            varname = matches[1]
            varcontents = parseLiteral(matches[2])
            if varcontents is None:
                varcontents = parseLine(matches[2])
            return {
                "type": InstructionTypes.VariableDef,
                "vartype": vartype,
                "name": varname,
                "contents": varcontents
            }
        else:  # variable modification
            expr = "([a-zA-Z]+)=(.*)"
            matches = re.match(expr, line).groups()
            varname = matches[0]
            return {
                "type": InstructionTypes.VariableMod,
                "name": varname,
                "contents": parseLiteral(matches[1])
            }
    
    elif "+=" in line:  # add to variable
        expr = "([a-zA-Z][a-zA-Z0-9]*)\+=(.*)"
        matches = re.match(expr, line).groups()
        return {
            "type": InstructionTypes.VariableOperatorPlusEquals,
            "name": matches[0],
            "contents": parseLiteral(matches[1])
        }

    elif "(" in line and ")" in line:  #TODO: use regex
        expr = "([a-zA-Z][a-zA-Z0-9]*)\((.*)\)"
        matches = re.match(expr, line).groups()
        funcname = matches[0]
        arguments = matches[1].split(",")
        parsedArgs = []
        for arg in arguments:
            parsedArgs.append(parseLiteral(arg))
        
        return {
            "type": InstructionTypes.FunctionCall,
            "fname": funcname,
            "args": parsedArgs
        }
    
    elif line[0] == "}":
        return {
            "type": InstructionTypes.FunctionEnd,
            "fname": line[1:]
        }
    
    elif line.startswith("return"):
        line = line[6:]
        return {
            "type": InstructionTypes.ReturnFromFunc,
            "contents": parseLiteral(line)
        }


def parseLiteral(arg):
    intExpr = "^(\d+)$"
    charExpr = "^'(.+)'$"
    varExpr = "^([a-zA-Z][a-zA-Z0-9_]*)$"
    operationExpr = r"(.+?)(\+)(.+)"
    logicalExpr = r"^(.+?)(<|<=|>|>=|==)([a-zA-Z0-9']+)$"
    functionExpr = r"([a-zA-Z][a-zA-Z0-9_]*)\((.*?)\)"
    if (result := re.match(intExpr, arg)) is not None:
        return {"type": "int", "value": result.group(1)}
    if (result := re.match(charExpr, arg)) is not None:
        c = result.group(1)
        if c == "\\n":
            return {"type": "int", "value": 0x0a}
        else:
            if len(c) > 1: raise Exception(f"[***] Not a single character")
            return {"type": "int", "value": ord(result.group(1))}
    if (result := re.match(varExpr, arg)) is not None:
        return {"type": "var", "value": result.group(1)}
    if (result := re.match(operationExpr, arg)) is not None:
        return {"type": "operation", "optype": result.group(2), "v1": parseLiteral(result.group(1)), "v2": parseLiteral(result.group(3))}
    if (result := re.match(logicalExpr, arg)) is not None:
        return {"type": "logical_op", "optype": result.group(2), "v1": parseLiteral(result.group(1)), "v2": parseLiteral(result.group(3))}
    if (result := re.match(functionExpr, arg)) is not None:
        argsParsed = []
        for currentArg in result.group(2).split(","):
            argsParsed.append(parseLiteral(currentArg))
        
        return {"type": "func", "fname": result.group(1), "args": argsParsed}


def increaseVarMemoryPosition(ignore, increaseAmount):
    global varMemoryPositions
    print(ignore)
    for k, v in varMemoryPositions.items():
        if k != currentFunc + ignore and k.startswith(currentFunc):
            varMemoryPositions[k] += increaseAmount

    return varMemoryPositions


def if_statement(condition, jmpFunc):
    global varMemoryPositions, currentFunc
    rval = b""
    if condition["type"] != "logical_op": raise Exception("While loop should be run with logical operator")
    #if condition["v1"]["type"] != "var": raise Exception("First item in while loop conditional should be variable")
    # rval += b"\x48\x89\xe0"  # mov rax, rsp
    # addAmount = varMemoryPositions[currentFunc + condition["v1"]["value"]]
    # if addAmount > 0:
    #     rval += b"\x48\x83\xc0" + int(addAmount).to_bytes(1, byteorder="little") # add rax, {addAmount}
    # rval += b"\x48\xc7\xc3" + int(condition["v2"]["value"]).to_bytes(4, byteorder="little")  # mov rbx, {value}
    # rval += b"\x66\x39\x18"  # cmp word [rax], bx
    rval += handle_arg(condition["v1"], ret=True)
    rval += b"\x48\x89\xc3"  # mov rbx, rax
    rval += handle_arg(condition["v2"], ret=True)
    rval += b"\x48\x39\xc3"  # cmp rbx, rax
    if condition["optype"] == "<":
        rval += b"\x0f\x8c"  # jl
    elif condition["optype"] == "<=":
        rval += b"\x0f\x8e"  # jle
    elif condition["optype"] == ">":
        rval += b"\x0f\x8f"  # jg
    elif condition["optype"] == ">=":
        rval += b"\x0f\x8d"  # jge
    elif condition["optype"] == "==":
        rval += b"\x0f\x84"  # je
    elif condition["optype"] == "!=":
        rval += b"\x0f\x85"  # jne
    else:
        rval += b"\xe9"  # unconditional jump if no valid condition is given 
    
    rval += jmpFunc(len(rval))
    return rval


def divide_base(arg):
    global textSection
    handle_arg(arg["args"][1])
    textSection += b"\x48\x89\xc3"  # mov rbx, rax
    handle_arg(arg["args"][0])
    textSection += b"\x48\x31\xd2"  # xor rdx, rdx (set to 0)
    textSection += b"\x48\xf7\xf3"  # div rbx


def handle_arg(arg, push=False, ret=None):  # pushes the argument and moves rax to its position on the stack
    global textSection
    output = b""
    if arg["type"] == "int":
        if push:
            output += b"\x6a" + int(arg["value"]).to_bytes(1, byteorder="little") # push {val}
            output += b"\x48\x89\xe0"  # mov rax, rsp
        else:
            output += b"\x48\xc7\xc0" + int(arg["value"]).to_bytes(4, byteorder="little")  # mov rax, {val}
    elif arg["type"] == "var":
        output += b"\x48\x89\xE0"  # mov rax, rsp

        addAmount = varMemoryPositions[currentFunc + arg["value"]]
        if addAmount > 0:
            output += b"\x48\x83\xc0" + int(addAmount).to_bytes(1, byteorder="little") # add rax, {addAmount}

        output += b"\x48\x8b\x00"  # mov rax, [rax]
        if push:
            output += b"\x50"  # push rax
    elif arg["type"] == "func":
        if arg["fname"] == "mod":
            divide_base(arg)
            output += b"\x48\x89\xd0"  # mov rax, rdx  ; mod value is stored in rdx
            if push:
                output += b"\xff\x30"  # push [rax]
        elif arg["fname"] == "div":
            divide_base(arg)  # result already stored in rax
            if push:
                output += b"\xff\x30"  # push [rax]
        else:  # custom function
            for funcArg in arg["args"]:
                handle_arg(funcArg, push=True)  # push

            output += b"\xe8" + (0xffffffff - len(textSection) - len(output) - functionDefBlocks[arg["fname"]]).to_bytes(4, byteorder="little")  # call {func}
            for funcArg in arg["args"]:
                output += b"\x58"  # pop rax
            
            output += b"\x48\x89\xd0"  # mov rax, rdx
            if push:
                output += b"\x50"  # push rax
        
    if ret:
        return output
    else:
        textSection += output

def set_rbx_to_var_loc(varname):
    global textSection
    textSection += b"\x48\x89\xe3"  # mov rbx, rsp
    addAmount = varMemoryPositions[currentFunc + varname]
    if addAmount > 0:
        textSection += b"\x48\x83\xc3" + int(addAmount).to_bytes(1, byteorder="little") # add rbx, {addAmount}


varMemoryPositions = {}
varTypes = {}
whileBlocks = {}
ifBlocks = {}
functionDefBlocks = {}
functionArgs = {}
memPointer = 0  # in bits
currentFunc = ""

textSection = b""

def main():
    global varMemoryPositions, varTypes, whileBlocks, ifBlocks, functionDefBlocks, functionArgs, memPointer, textSection, currentFunc
    with open("itoa.tpl") as f:
        code = f.read()

    code = code.replace("\n", "").replace(" ", "")
    code = code.split(";")
    newCode = []
    for line in code:
        if not line.startswith("#"):
            newCode.append(line)
    print(newCode)

    
    ### TOKENISE FIRST :)


    instructions = []

    for linenum, line in enumerate(newCode):
        linenum = linenum + 1
        instructions.append(parseLine(line))
        
    print(instructions)

    ### WRITING INTO BINARY

    for ins in instructions:
        if ins["type"] == InstructionTypes.FunctionStart:
            currentFunc = ins["fname"] + "_"

            if ins["fname"] == "main":
                textSection = b"\xe9" + (len(textSection)).to_bytes(4, byteorder="little") + textSection  # add jump to main function
                for block in functionDefBlocks.keys():
                    functionDefBlocks[block] -= 1
            else:  # custom function
                functionDefBlocks[ins["fname"]] = len(textSection)
                functionArgs[ins["fname"]] = ins["args"]

                for arg in ins["args"]:
                    varTypes[arg["varname"]] = arg["rtype"]
                    varMemoryPositions[currentFunc + arg["varname"]] = 8
                    varMemoryPositions = increaseVarMemoryPosition(arg["varname"], 8)
        elif ins["type"] == InstructionTypes.FunctionEnd:
            if ins["fname"] == "main":
                textSection += b"\xB8\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05" # mov rax, 60 ; xor rdi, rdi ; syscall
            elif ins["fname"].startswith("while"):
                print(whileBlocks)

                condition = whileBlocks[ins["fname"]][0]
                #textSection += (0xff - len(textSection) -  int(whileBlocks[ins["fname"]][1]) + 4).to_bytes(1, byteorder="little")
                print(hex(len(textSection)), hex(int(whileBlocks[ins["fname"]][1])))
                textSection += if_statement(condition, lambda addLen: (0xffffffff - addLen - len(textSection) + int(whileBlocks[ins["fname"]][1]) - 3).to_bytes(4, byteorder="little"))
            elif ins["fname"].startswith("if"):
                print(ifBlocks)

                textSection = textSection[:ifBlocks[ins["fname"]][1] - 4] + (len(textSection) - ifBlocks[ins["fname"]][1]).to_bytes(4, byteorder="little") + textSection[ifBlocks[ins["fname"]][1]:]
            else:  # it is a custom function definition
                for arg in functionArgs[ins["fname"]]:
                    toRemove = []
                    for memPos in varMemoryPositions.keys():
                        if memPos.startswith(currentFunc):
                            isArg = False
                            for arg in functionArgs[ins["fname"]]:
                                if memPos == currentFunc + arg["varname"]:
                                    isArg = True
                            if not isArg:
                                textSection += b"\x58"  # pop rax
                                toRemove.append(memPos)

                    for pos in toRemove:
                        del varMemoryPositions[pos]

                textSection += b"\xc3"  # ret
        elif ins["type"] == InstructionTypes.FunctionCall:
            if ins["fname"] == "putc":
                if len(ins["args"]) > 1: raise Exception(f"[{linenum}] Too many arguments for builtin function `putc`")
                handle_arg(ins["args"][0], push=True)
                textSection += b"\x48\x89\xe6"  # mov rsi, rsp
                textSection += b"\xB8\x01\x00\x00\x00"  # mov rax, 1
                textSection += b"\xBF\x01\x00\x00\x00"  # mov rdi, 1
                textSection += b"\xBA\x01\x00\x00\x00"  # mov rdx, 1 ;

                textSection += b"\x0F\x05"  # syscall
                textSection += b"\x58"  # pop rax
            elif ins["fname"].startswith("while"):
                whileBlocks[ins["fname"]] = (ins["args"][0], len(textSection))  # condition for loop continuation and where to jump to
            elif ins["fname"].startswith("if"):
                # Jump if condition is NOT true (swap condition to opposite and jump if true)
                if ins["args"][0]["optype"] == "==":
                    ins["args"][0]["optype"] = "!="
                elif ins["args"][0]["optype"] == "!=":
                    ins["args"][0]["optype"] = "=="
                elif ins["args"][0]["optype"] == "<":
                    ins["args"][0]["optype"] = ">="
                elif ins["args"][0]["optype"] == ">":
                    ins["args"][0]["optype"] = "<="
                elif ins["args"][0]["optype"] == ">=":
                    ins["args"][0]["optype"] = "<"
                elif ins["args"][0]["optype"] == "<=":
                    ins["args"][0]["optype"] = ">"
                textSection += if_statement(ins["args"][0], lambda addLen: addLen.to_bytes(4, byteorder="little"))
                ifBlocks[ins["fname"]] = (ins["args"][0], len(textSection))
            else:  # custom function call
                for arg in ins["args"]:
                    handle_arg(arg, push=True)  # push

                textSection += b"\xe8" + (0xffffffff - len(textSection) - functionDefBlocks[ins["fname"]]).to_bytes(4, byteorder="little")  # call {func}
                for arg in ins["args"]:
                    textSection += b"\x58"  # pop rax
        elif ins["type"] == InstructionTypes.VariableDef:  # todo: broken for variables
            if ins["vartype"] == "i8":
                varTypes[ins["name"]] = ins["vartype"]
                handle_arg(ins["contents"], push=True)

                varMemoryPositions[currentFunc + ins["name"]] = 0
                varMemoryPositions = increaseVarMemoryPosition(ins["name"], 8)
                memPointer += 8
        elif ins["type"] == InstructionTypes.VariableMod:
            if varTypes[ins["name"]] == "i8":
                
                handle_arg(ins["contents"])
                set_rbx_to_var_loc(ins["name"])
                textSection += b"\x48\x89\x03"  # mov [rbx], rax
        elif ins["type"] == InstructionTypes.VariableOperatorPlusEquals:
            if varTypes[ins["name"]] == "i8":
                if ins["contents"]["type"] == "int":
                    set_rbx_to_var_loc(ins["name"])
                    handle_arg(ins["contents"])
                    textSection += b"\x48\x01\x03"  # add [rbx], rax
        elif ins["type"] == InstructionTypes.ReturnFromFunc:
            # todo: use return type of function for something
            handle_arg(ins["contents"])
            textSection += b"\x48\x89\xc2"  # mov rdx, rax

    print(varMemoryPositions)
    headerSection = b""

    ## FILE HEADER

    #textSection = b"\xB8\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05"  # TODO: remove this obviously

    headerSection += b"\x7fELF"  # magic number
    headerSection += b"\x02"  # 64-bit mode
    headerSection += b"\x01"  # little endian
    headerSection += b"\x01"  # v1 of elf
    headerSection += b"\x00"  # system v (basic linux)
    headerSection += b"\x00"  # os version
    headerSection += b"\0\0\0\0\0\0\0"  # padding (7 bytes)
    headerSection += b"\x02\x00"  # file type = executable file
    headerSection += b"\x3e\x00"  # machine type = AMD x86-64
    headerSection += b"\x01\x00\x00\x00"  # v1 of elf
    headerSection += b"\x80\x00\x40\x00\0\0\0\0"  # memory entry point
    headerSection += b"\x40\0\0\0\0\0\0\0"  # start of header table (end of this header)
    headerSection += b"\0\0\0\0\0\0\0\0"  # start of section header table (this is moved later)
    headerSection += b"\0\0\0\0"  # flags
    headerSection += b"\x40\x00"  # header size (64 bytes)
    headerSection += b"\x38\x00"  # size of program header table entry
    headerSection += b"\x01\x00"  # number of program headers in table
    headerSection += b"\x40\x00"  # size of section header table entry
    headerSection += b"\x05\x00"  # number of section headers in table
    headerSection += b"\x04\x00"  # index of section header table with section names

    ## PROGRAM HEADER (starts at 0x40)

    headerSection += b"\x01\x00\x00\x00"  # type of segment = loadable segment
    headerSection += b"\x05\x00\x00\x00"  # flags i dont understand
    headerSection += b"\0\0\0\0\0\0\0\0"  # offset of segment in file image
    headerSection += b"\0\0\x40\x00\0\0\0\0"  # virtual address of segment in memory
    headerSection += b"\0\0\x40\x00\0\0\0\0"  # segment's physical address
    headerSection += (0x80 + len(textSection)).to_bytes(8, byteorder="little")  # size of segment in file
    headerSection += (0x80 + len(textSection)).to_bytes(8, byteorder="little")  # size of segment in memory
    headerSection += b"\x00\x00\x20\x00\0\0\0\0"  # alignment
    headerSection += b"\0\0\0\0\0\0\0\0"  # idk what this padding is for, probably alignment or smth


    ## PROGRAM DATA AND PADDING


    fileData = headerSection + textSection
    fileData += b"\0" * (16 - (len(fileData) % 16))


    ## SYMBOL TABLE

    # 0
    fileData += b"\0\0\0\0"  # .shstrtab string offset
    fileData += b"\0"  # info (none)
    fileData += b"\0"  # other
    fileData += b"\0\0"  # meaning of symbol (no meaning)
    fileData += b"\0\0\0\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 1
    fileData += b"\0\0\0\0"  # .shstrtab string offset
    fileData += b"\x03"  # info (section)
    fileData += b"\0"  # other
    fileData += b"\x01\0"  # meaning of symbol (idk)
    fileData += b"\x80\x00\x40\x00\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 2
    fileData += b"\x01\0\0\0"  # .shstrtab string offset (main.asm)
    fileData += b"\x04"  # info (file)
    fileData += b"\0"  # other
    fileData += b"\xf1\xff"  # meaning of symbol (absolute)
    fileData += b"\0\0\0\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 3
    fileData += b"\x0f\0\0\0"  # .shstrtab string offset (_start)
    fileData += b"\x10"  # info (global notype)
    fileData += b"\0"  # other
    fileData += b"\x01\0"  # meaning of symbol (idk)
    fileData += b"\x80\0\x40\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 4
    fileData += b"\x0a\0\0\0"  # .shstrtab string offset (__bss_start)
    fileData += b"\x10"  # info (global notype)
    fileData += b"\0"  # other
    fileData += b"\x01\0"  # meaning of symbol (idk)
    fileData += b"\x8a\0\x60\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 5
    fileData += b"\x16\0\0\0"  # .shstrtab string offset (_edata)
    fileData += b"\x10"  # info (global notype)
    fileData += b"\0"  # other
    fileData += b"\x01\0"  # meaning of symbol (idk)
    fileData += b"\x8a\0\x60\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)

    # 6
    fileData += b"\x1d\0\0\0"  # .shstrtab string offset (_end)
    fileData += b"\x10"  # info (global notype)
    fileData += b"\0"  # other
    fileData += b"\x01\0"  # meaning of symbol (idk)
    fileData += b"\x90\0\x60\0\0\0\0\0"  # value (load location)
    fileData += b"\0\0\0\0\0\0\0\0"  # size (unused)


    ## SYMBOL TABLE

    fileData += b"\0"
    fileData += b"main.asm\0"
    fileData += b"__bss_start\0"
    fileData += b"_edata\0"
    fileData += b"_end\0"

    
    ## SECTION STRING TABLE

    fileData += b"\0"
    fileData += b".symtab\0"
    fileData += b".strtab\0"
    fileData += b".shstrtab\0"
    fileData += b".text\0"
    fileData += b"\0" * (16 - (len(fileData) % 16))  # padding


    ## SECTION HEADER TABLE


    fileData = fileData[:40] + len(fileData).to_bytes(8, byteorder="little") + fileData[48:]  # set offset
    
    # 0
    fileData += b"\0\0\0\0"  # .shstrtab offset (none)
    fileData += b"\0\0\0\0"  # type = NULL
    fileData += b"\0\0\0\0\0\0\0\0"  # attributes = none
    fileData += b"\0\0\0\0\0\0\0\0"  # virtual address
    fileData += b"\0\0\0\0\0\0\0\0"  # offset of section in file
    fileData += b"\0\0\0\0\0\0\0\0"  # size of section in file
    fileData += b"\0\0\0\0"  # section index
    fileData += b"\0\0\0\0"  # extra info
    fileData += b"\0\0\0\0\0\0\0\0"  # alignment of section
    fileData += b"\0\0\0\0\0\0\0\0"  # size of each entry

    # 1
    fileData += b"\x1b\0\0\0"  # .shstrtab offset (.text)
    fileData += b"\x01\0\0\0"  # type = program bits
    fileData += b"\x06\0\0\0\0\0\0\0"  # attributes = alloc | exec
    fileData += b"\x80\0\x40\0\0\0\0\0"  # virtual address
    fileData += b"\x80\0\0\0\0\0\0\0"  # offset of section in file
    fileData += len(textSection).to_bytes(8, byteorder="little")  # size of section in file #TODO: this
    fileData += b"\0\0\0\0"  # section index
    fileData += b"\0\0\0\0"  # extra info
    fileData += b"\x10\0\0\0\0\0\0\0"  # alignment of section
    fileData += b"\0\0\0\0\0\0\0\0"  # size of each entry

    startOfSymtab = (len(textSection) + 0x80 + (16 - (len(fileData) % 16)))

    # 2
    fileData += b"\x01\0\0\0"  # .shstrtab offset (.symtab)
    fileData += b"\x02\0\0\0"  # type = SYMTAB
    fileData += b"\0\0\0\0\0\0\0\0"  # attributes = none
    fileData += b"\0\0\0\0\0\0\0\0"  # virtual address
    fileData += startOfSymtab.to_bytes(8, byteorder="little")  # offset of section in file
    fileData += b"\xa8\0\0\0\0\0\0\0"  # size of section in file
    fileData += b"\x03\0\0\0"  # section index
    fileData += b"\x03\0\0\0"  # extra info
    fileData += b"\x08\0\0\0\0\0\0\0"  # alignment of section
    fileData += b"\x18\0\0\0\0\0\0\0"  # size of each entry

    # 3
    fileData += b"\x09\0\0\0"  # .shstrtab offset (.strtab)
    fileData += b"\x03\0\0\0"  # type = STRTAB
    fileData += b"\0\0\0\0\0\0\0\0"  # attributes = none
    fileData += b"\0\0\0\0\0\0\0\0"  # virtual address
    fileData += (startOfSymtab + 0xa8).to_bytes(8, byteorder="little")  # offset of section in file
    fileData += b"\x22\0\0\0\0\0\0\0"  # size of section in file
    fileData += b"\0\0\0\0"  # section index
    fileData += b"\0\0\0\0"  # extra info
    fileData += b"\x01\0\0\0\0\0\0\0"  # alignment of section
    fileData += b"\0\0\0\0\0\0\0\0"  # size of each entry

    # 4
    fileData += b"\x11\0\0\0"  # .shstrtab offset (.shstrtab)
    fileData += b"\x03\0\0\0"  # type = STRTAB
    fileData += b"\0\0\0\0\0\0\0\0"  # attributes = none
    fileData += b"\0\0\0\0\0\0\0\0"  # virtual address
    fileData += (startOfSymtab + 0xca).to_bytes(8, byteorder="little")  # offset of section in file
    fileData += b"\x21\0\0\0\0\0\0\0"  # size of section in file
    fileData += b"\0\0\0\0"  # section index
    fileData += b"\0\0\0\0"  # extra info
    fileData += b"\x01\0\0\0\0\0\0\0"  # alignment of section
    fileData += b"\0\0\0\0\0\0\0\0"  # size of each entry


    with open("compiled", "wb") as f:
        f.write(fileData)


    #print(binascii.hexlify(bytearray(textSection)))


if __name__ == "__main__":
    main()
