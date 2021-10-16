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
        return "--No jump found--"

    def processInstructions(self):
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
                    print("\tn" + str(i+1) + " [label= \"" + (functionItems[i].address)[2:] + "; " + "D: " + "U: " + "\"]")

                # now that we have all the nodes check for the control flow
                for i in range(0, len(functionItems)-1):
                    # extracting the instruction type i.e. jmp, cmp, add, etc.
                    splitInstruction = functionItems[i].instruction.split()
                    # if the instruction type is a jmp, there is no branch it exclusively jumps to the new address
                    if splitInstruction[0] == 'jmp':
                        jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                        print("\tn" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                    else:
                        # if the instruction type is another kind of jump, it splits into the jump taken and not taken
                        if splitInstruction[0] in JumpInstructions:
                            # if the jump is taken figure out which node it jumps to.
                            jumpNodeNumber = self.extractJumpAddress(splitInstruction[-1], function)
                            print("\tn" + str(i+1) + " -> " + "n" + jumpNodeNumber)
                        # this accounts for the jump not taken case
                        print("\tn" + str(i+1) + " -> " + "n" + str(i+2))
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

