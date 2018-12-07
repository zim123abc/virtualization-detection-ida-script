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

#reset head to beginning of instructions
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

#Check out Hex View-A for I/O ports
for x in heads:
        if GetMnem(x) == "mov" and "eax" in GetOpnd(x, 0) and "564D5868h" in GetOpnd(x, 1):
                if GetMnem(x + 1) == "mov" and "edx" in GetOpnd(x + 1, 0) and "5658h" in GetOpnd(x + 1, 1):
                        if GetMnem(x + 2) == "in" and "eax" in GetOpnd(x + 2, 0) and "dx" in GetOpnd(x + 2, 1):
                                antiVM.append(x)

        elif GetMnem(x) == "call" and "RtlGetNativeSystemInformation" in GetOpnd(x, 0):
                antiVM.append(x)

        if "564D5868h" in GetOpnd(x, 1) or "5658h" in GetOpnd(x, 1):
                antiVM.append(x)

for i in antiVM:
	SetColor(i, CIC_ITEM, 0x0000ff)
        instruction = GetMnem(i)
	Message("Anti-VM: %08x >>" % i)
        Message(" %s\n" % instruction)
        
print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
