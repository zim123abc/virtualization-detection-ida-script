from idautils import *
from idc import *

heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

#Calls to autorun/autorunsc -- these hide signed MS entries!!
basic_check = ['sidt', 'sgdt', 'sldt', 'smsw', 'str', 'in', 'cpuid', 'cmd', 'xor']
vmware_check = ['Vmtoolsd', 'Vmwaretrat', 'Vmwareuser', 'Vmacthlp']
vbox_check = ['vboxservice', 'vboxtray', 'VBOXBIOS']
hostname_check = ['brbrb-d8fb22af1']
env_check = ['KVMKVMKVM', 'prl hyperv', 'Microsoft Hv', 'autorun', 'autorunsc']

antiVM = []
for i in heads:
        for x in basic_check,vmware_check,vbox_check,hostname_check,env_check:
                if GetMnem(i) in x: 
	                antiVM.append(i)
			
#Check out Hex View-A for I/O ports
for i in heads:
        if GetMnem(i) == "mov" and "eax" in GetOpnd(i, 0) and GetMnem(i) == "0x564D5868" in GetOpnd(i, 1):
                if GetMnem(i + 1) == "mov" and "edx" in GetOpnd(i + 1, 0) and GetMnem(i + 1) == "0x5658" in GetOpnd(i + 1, 1):
                        if GetMnem(i + 2) == "in" and "eax" in GetOpnd(i + 2, 0) and GetMnem(i + 2) == "DX" in GetOpnd(i + 2, 1):
                                antiVM.append(i) #Should recheck this, might be repeatvitive
                                antiVM.append(i + 1)
                                antiVM.append(i + 2)


'''
#Calls to specific functions need to be checked: VirtualProtect,GetCursorPosition() 
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
#Any Modification ot %SystemRoot% directory
#base64 decode - ?

for i in antiVM:
	SetColor(i, CIC_ITEM, 0x0000ff)
	Message("Anti-VM: %08x\n" % i)
        
print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
