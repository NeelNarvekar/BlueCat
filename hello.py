import idaapi
import idautils
import string
from ida_funcs import *
from idaapi import *
from idautils import *
from idc import *

InstructionLineSet = []
AllFunctionsSet = set()
JumpInstructions = {'jo', 'jno', 'js', 'jns',
                    'je', 'jz', 'jne', 'jnz',
                    'jb', 'jnae', 'jc', 'jnb', 
                    'jae', 'jnc', 'jbe', 'jna',
                    'ja', 'jnbe', 'jl', 'jnge',
                    'jge', 'jnl', 'jle', 'jng',
                    'jg', 'jnle', 'jp', 'jpe',
                    'jnp', 'jpo', 'jcxz', 'jecxz'}

# Custom class I made to store all relevant information related to an instruction
class InstructionLine:

    def __init__(self, functionName, address, instruction):
        self.functionName = functionName
        self.address = address
        self.instruction = instruction

    # overriding equality operator for custom class
    def __eq__(self, other):
        return (isinstance(other, self.__class__) and getattr(other, 'functionName', None) == self.functionName and getattr(other, 'address', None) == self.address) and getattr(other, 'instruction', None) == self.instruction

    # overriding hash for custom class
    def __hash__(self):
        return hash(self.functionName + self.address + self.instruction)

def removeDup(a):
    b = list(set(a.split(",")))
    d = ""
    for c in b:
        d = d + c + ","
    if d[0] == ",":
        d = d[1:]
    return d[:-1]

def brakL(a):
    U = ""
    if "[" in a:
        a = a.replace(',', '')
        a = a.replace('[', '')
        a = a.replace(']', '')
        a = a.split('+')
        for element in a:
            if (element[0] == 'E' and len(element) == 3) or (element[0] == 'D' and len(element) == 2):
                U += element + ","
    return U[:-1]



class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    # this is a helper function to find the node where the instruction is jumping to
    def extractJumpAddress(self, instruction, function):
        jumpAddressSplit = instruction.split("_")
        jumpAddress = jumpAddressSplit[-1].lower()
        jumpAddress = "0x00" + jumpAddress
        functionItems = [instructionLine for instructionLine in InstructionLineSet if instructionLine.functionName == function]

        for i in range(0, len(functionItems)):
            if jumpAddress == functionItems[i].address:
                return str(i+1)
        # theoretically this should never run, more of a debugging statement if it does execute
        return "n50"

    def processInstructions(self):
        hexset = string.hexdigits + "H"
        # creating dot graph for one function at a time
        for function in AllFunctionsSet:
            with open(function + '.dot', 'w') as f:
                sys.stdout = f
                # initial text to set up file
                print("// " + function)
                print("digraph {")
                # getting all instructionLines for the function we are working on
                functionItems = [instructionLine for instructionLine in InstructionLineSet if instructionLine.functionName == function] 

                # for each instruction add a node
                for i in range(0, len(functionItems)):
                    splitInstruction = functionItems[i].instruction.split()
                    
                    splitInstruction = [instruction.replace(";", "").upper() for instruction in splitInstruction]
                    D = ""
                    U = ""
                    if splitInstruction[0] == 'PUSH':
                        D = "[ESP],ESP,"
                        if not all(c in hexset for c in splitInstruction[1]) and splitInstruction[1] != "OFFSET":
                            U = splitInstruction[1] + ",ESP"
                        else: 
                            U = "ESP"
                    elif splitInstruction[0] == 'MOV' or splitInstruction[0] == "MOVSX" or splitInstruction[0] == "MOVZX":
                        D = splitInstruction[1]
                        if not all(c in hexset for c in splitInstruction[2]) and splitInstruction[2] != "OFFSET":
                            U = splitInstruction[2]
                        else: 
                            U = ""
                    elif splitInstruction[0] == "SUB" or splitInstruction[0] == "ADD":
                        D = splitInstruction[1] + "EFLAGS,"
                        if not all(c in hexset for c in splitInstruction[2]):
                            U = splitInstruction[1] + splitInstruction[2]
                        else: 
                            U = splitInstruction[1].replace(',','')
                    elif splitInstruction[0] == "CALL":
                        if splitInstruction[1][0:3] == "DS:":
                            D = "ESP,"
                            U = "ESP"
                        else:
                            D = "EAX,ESP,"
                            U = "ESP"
                    elif splitInstruction[0] == "INC" or splitInstruction[0] == "DEC":
                        D = splitInstruction[1] + ",EFLAGS,"
                        U = splitInstruction[1]
                    elif splitInstruction[0] == "XOR":
                        firstOperand = splitInstruction[1].replace(',', '')
                        secondOperand = splitInstruction[2].replace(',', '')
                        if firstOperand == secondOperand:
                            D = splitInstruction[1] + "EFLAGS,"
                            U = firstOperand
                        else:
                            D = splitInstruction[1] + "EFLAGS,"
                            U = splitInstruction[1] + splitInstruction[2]
                    elif splitInstruction[0] == "POP":
                        D = splitInstruction[1] + ",ESP,"
                        U = "[ESP],ESP"
                    elif splitInstruction[0] == "CMP":
                        D = "EFLAGS,"
                        U = splitInstruction[1] + splitInstruction[2]
                    elif splitInstruction[0] == "JNZ" or splitInstruction[0] == "JZ" or splitInstruction[0] == "JL" or splitInstruction[0] == "JA" or splitInstruction[0] == "JG" or splitInstruction[0] == "JLE" or splitInstruction[0] == "JNB":
                        D = ""
                        U = "EFLAGS"
                    elif splitInstruction[0] == "JMP":
                        D = ""
                        U = ""
                    elif splitInstruction[0] == "JBE":
                        D = ""
                        U = "EFLAGS"
                    elif splitInstruction[0] == "SAR" or splitInstruction[0] == "SHR":
                        D = splitInstruction[1] + "EFLAGS,"
                        if not all(c in hexset for c in splitInstruction[2]):
                            U = splitInstruction[1] + splitInstruction[2]
                        else: 
                            U = splitInstruction[1].replace(',','')

                    elif splitInstruction[0] == "AND" or splitInstruction[0] == "OR":
                        D = splitInstruction[1] + "EFLAGS,"
                        if not all(c in hexset for c in splitInstruction[2]):
                            U = splitInstruction[1] + splitInstruction[2]
                        else: 
                            U = splitInstruction[1].replace(',','')
                    elif splitInstruction[0] == "JB":
                        D = ""
                        U = "CF"
                    elif splitInstruction[0] == "LEA":
                        D = splitInstruction[1]
                        U = ""
                        parsed = splitInstruction[2]
                        if "[" in parsed:
                            parsed = parsed.replace(',', '')
                            parsed = parsed.replace('[', '')
                            parsed = parsed.replace(']', '')
                            parsed = parsed.split('+')
                            for element in parsed:
                                if (element[0] == 'E' and len(element) == 3) or (element[0] == 'D' and len(element) == 2):
                                    U += element + ","
                        else:
                            U = splitInstruction[2]
                    elif splitInstruction[0] == "TEST":
                        D = "EFLAGS"
                        U = splitInstruction[1] + splitInstruction[2]
                    elif splitInstruction[0] == "IMUL":
                        D = splitInstruction[1] + "EFLAGS,"
                        if not all(c in hexset for c in splitInstruction[2]):
                            U = splitInstruction[1] + splitInstruction[2]
                        else: 
                            U = splitInstruction[1].replace(',','')
                    elif splitInstruction[0] == "LEAVE":
                        D = "ESP,EBP,"
                        U = "EBP"
                    elif splitInstruction[0] == "RETN":
                        D = "ESP,EIP"
                        U = "ESP"
                    elif splitInstruction[0] == "REP":
                        D = "EAX,ESP,"
                        U = "ESP,EFLAGS"
                    elif splitInstruction[0] == "SETNZ":
                        D = splitInstruction[1]
                        U = "EFLAGS"

                    if (len(splitInstruction) > 1 and splitInstruction[0] != "CMP" and splitInstruction[0] != "ADD" and splitInstruction[0] != "SUB"):
                        U += "," + brakL(splitInstruction[1]) if len(brakL(splitInstruction[1])) != 0 else ""

                    if 'DWORD' in U:
                        output = ""
                        a = ""
                        U = U.split(",")
                        for element in U:
                            if 'DWORD' in element:
                                a = "[" + element + "]"
                                output += a + ","
                            else:
                                output += element + ","
                        # for element in U:
                        #     output = output + element + ","
                        U = output

                    if 'DWORD' in D:
                        output = ""
                        a = ""
                        D = D.split(",")
                        for element in D:
                            if 'DWORD' in element:
                                a = "[" + element + "]"
                                output += a + ","
                            else:
                                output += element + ","
                        # for element in U:
                        #     output = output + element + ","
                        D = output

                    print(" n" + str(i+1) + " [label=\"" + (functionItems[i].address)[2:] + "; " + "D:" + removeDup(D) + ("," if len(D) != 0 else "") + " U:" + removeDup(U) + "\"]")

                # now that we have all the nodes check for the control flow
                for i in range(0, len(functionItems)-1):
                    # extracting the instruction type i.e. jmp, cmp, add, etc.
                    splitInstruction = functionItems[i].instruction.split()
                    # if the instruction type is a jmp, there is no branch it exclusively jumps to the new address
                    if splitInstruction[0] == 'jmp':
                        jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                        print(" n" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                    else:
                        # if the instruction type is another kind of jump, it splits into the jump taken and not taken
                        if splitInstruction[0] in JumpInstructions:
                            # if the jump is taken figure out which node it jumps to.
                            jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                            print(" n" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                        # this accounts for the jump not taken case
                        print(" n" + str(i+1) + " -> " + "n" + str(i+2))
                print("}")
            f.close()

    # this is a debugging function I made to print all instructions out to a text file
    def printInstructionLineSet(self, instructionLineSet):
        with open("InstructionLineSet.txt", 'w') as f:
            sys.stdout = f
            for instruction in InstructionLineSet:
                print(instruction.functionName + ": " + instruction.address + ": " + instruction.instruction)


    # MAIN ENTRY POINT!#################################
    def run(self, arg):
        # iterating over all functions
        for funcea in idautils.Functions():
            functionName = get_func_name(funcea)
            AllFunctionsSet.add(functionName)
            # iterating over all basic blocks
            for (startea, endea) in Chunks(funcea):
                # iterating over each instruction
                for head in Heads(startea, endea):
                    InstructionLineSet.append(InstructionLine(functionName, "0x%08x"%(head), GetDisasm(head)))
        # this is a debug statement
        # self.printInstructionLineSet(InstructionLineSet)

        # this will start creating the .dot file
        self.processInstructions()

    def term(self):
        pass



def PLUGIN_ENTRY():
    return myplugin_t()

