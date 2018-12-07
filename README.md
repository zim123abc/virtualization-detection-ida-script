# virtualization-detection-ida-script
Python Script for IDA that displays virtualization detection specific code in a binary

Installation
 - Copy findAntiVM.py file to the plugins directory of IDA (%IDAPATH%\plugins) and start IDA.
 

 - TODO: create detection for string 'vmware' and 'virtualbox'

*Base64 all strings*
<<<<<<< HEAD
   
=======

  - check for these strings:
   - Intel CPU version - cpuid
>>>>>>> jordan
   - KVMKVMKVM
   - prl hyperv
   - Microsoft Hv

 - Even more strings:
  - cmd.exe && hex version
  - 0x564D5868 - VMXh for VMWare I/O port
  - 0x5658 - VX(port) for VMWare I/O port
  - VMWare processes: Vmtoolsd.exe, Vmwaretrat.exe, Vmwareuser.exe, Vmacthlp.exe
  - Vbox processes: vboxservice.exe, vboxtray.exe

- Check for Mac addresses:
 - VMWare: 00:05:69, 00:0C:29, 00:1C:14, 00:50:56:??
 - Vbox: 08:00:27
  
 - Check for signatures:
  - mov eax, 0x564D5868
    mov edx, 0x5658
    in eax, DX

 - look for this call; might be malicious
  - RtlGetNativeSystemInformation
