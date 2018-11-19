from idautils import *
from idc import *

heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
antiVM = []
for i in heads:
	if (GetMnem(i) == "sidt" or GetMnem(i) == "sgdt" or GetMnem(i) == "sldt" or GetMnem(i) == "smsw" or GetMnem(i) == "str" or GetMnem(i) == "in" or GetMnem(i) == "cpuid"):
		antiVM.append(i)

#Calls to specific functions need to be checked: VirtualProtect,GetCursorPosition() 
'''
for functionAddr in Functions():    
    # Check each function to look for strcpy        
    if "GetCursorPosition" in GetFunctionName(functionAddr):    #Might be worth iterating through a dictionary 
        xrefs = CodeRefsTo(functionAddr, False)                
        # Iterate over each cross-reference
        for xref in xrefs:                            
            # Check to see if this cross-reference is a function call                            
            if GetMnem(xref).lower() == "call":           
                print hex(xref)
'''
#Calls to specific registry keys: \Registry\Machine\HARDWARE\ACPI\DSDT\VBOX__\VBOXBIOS,
#Calls to autorun/autorunsc -- these hide signed MS entries!!
#Any Modification ot %SystemRoot% directory

print "Number of potential Anti-VM instructions: %d" % (len(antiVM))

for i in antiVM:
	SetColor(i, CIC_ITEM, 0x0000ff)
	Message("Anti-VM: %08x\n" % i)
