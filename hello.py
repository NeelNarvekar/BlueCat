import idaapi
import idautils
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

class InstructionLine:

    def __init__(self, functionName, address, instruction):
        self.functionName = functionName
        self.address = address
        self.instruction = instruction

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and getattr(other, 'functionName', None) == self.functionName and getattr(other, 'address', None) == self.address) and getattr(other, 'instruction', None) == self.instruction

    def __hash__(self):
        return hash(self.functionName + self.address + self.instruction)


class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def extractJumpAddress(self, instruction, function):
        jumpAddressSplit = instruction.split("_")
        jumpAddress = jumpAddressSplit[-1].lower()
        jumpAddress = "0x00" + jumpAddress
        functionItems = [instructionLine for instructionLine in InstructionLineSet if instructionLine.functionName == function]

        for i in range(0, len(functionItems)):
            if jumpAddress == functionItems[i].address:
                return str(i+1)
        return "--No jump found--"

    def processInstructions(self):
        for function in AllFunctionsSet:
            with open(function + '.dot', 'w') as f:
                sys.stdout = f
                print("// " + function)
                print("digraph {")
                functionItems = []
                functionItems = [instructionLine for instructionLine in InstructionLineSet if instructionLine.functionName == function] 

                for i in range(0, len(functionItems)):
                    print("\tn" + str(i+1) + " [label= \"" + (functionItems[i].address)[2:] + "; " + "D: " + "U: " + "\"]")

                for i in range(0, len(functionItems)-1):
                    splitInstruction = functionItems[i].instruction.split()
                    if splitInstruction[0] == 'jmp':
                        jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                        print("\tn" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                    else:
                        if splitInstruction[0] in JumpInstructions:
                            jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                            print("\tn" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                        print("\tn" + str(i+1) + " -> " + "n" + str(i+2))
                print("}")
            f.close()

    def printInstructionLineSet(self, instructionLineSet):
        with open("InstructionLineSet.txt", 'w') as f:
            sys.stdout = f
            for instruction in InstructionLineSet:
                print(instruction.functionName + ": " + instruction.address + ": " + instruction.instruction)


    def run(self, arg):
        for funcea in idautils.Functions():
            functionName = get_func_name(funcea)
            AllFunctionsSet.add(functionName)
            for (startea, endea) in Chunks(funcea):
                for head in Heads(startea, endea):
                    InstructionLineSet.append(InstructionLine(functionName, "0x%08x"%(head), GetDisasm(head)))
        # self.printInstructionLineSet(InstructionLineSet)
        self.processInstructions()

    def term(self):
        pass



def PLUGIN_ENTRY():
    return myplugin_t()

