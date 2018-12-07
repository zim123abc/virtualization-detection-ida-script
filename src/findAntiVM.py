from idautils import *
from idc import *

heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

#Calls to autorun/autorunsc -- these hide signed MS entries!!
pill_check = ['sidt', 'sgdt', 'sldt', 'smsw', 'str', 'in']
malicious_check = ['cmd','cpuid','autorun', 'autorunsc']
vmware_check = ['Vmtoolsd', 'Vmwaretrat', 'Vmwareuser', 'Vmacthlp']
vbox_check = ['vboxservice', 'vboxtray', 'VBOXBIOS']
hostname_check = ['brbrb-d8fb22af1','KVMKVMKVM', 'prl hyperv', 'Microsoft Hv', 'XenVMMXenVMM']
env_check = ['dmesg', 'kmods', 'pcidevs',' dmidecode','sysfs','procfs', 'dashXmstdout']
antiVM = []

for i in heads:
        for x in pill_check,vmware_check,vbox_check,hostname_check,env_check,malicious_check:
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
        if GetMnem(i) == "call" and "RtlGetNativeSystemInformation" in GetOpnd(i, 0):
                antiVm.append(i)


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

for i in antiVM:
	SetColor(i, CIC_ITEM, 0x0000ff)
	Message("Anti-VM: %08x\n" % i)
        
print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
