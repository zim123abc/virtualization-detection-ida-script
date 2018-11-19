# virtualization-detection-ida-script
Python Script for IDA that displays virtualization detection specific code in a binary

 - TODO: create detection for string 'vmware' and 'virtualbox'
  - check for these strings:
   - Intel(R) Xeon(R) CPU
   - Common KVM processor
   - Common 32-bit KVM
   - Virtual CPU
   - Intel Celeron_4x0 (Conroe/Merom Class Core 2)
   - Westmere E56xx/L56xx/X56xx (Nehalem-C)
   - Intel Core 2 Duo P9xxx (Penryn Class Core 2)
   - Intel Core i7 9xx (Nehalem Class Core i7)
   - Intel Xeon E312xx (Sandy Bridge)
   - AMD Opteron 240 (Gen 1 Class Opteron)
   - AMD Opteron 22xx (Gen 2 Class Opteron)
   - AMD Opteron 23xx (Gen 3 Class Opteron)
   - AMD Opteron 62xx class CPU
   - Intel CPU version
   - VMwareVMware
   - XenVMMXenVMM
   - KVMKVMKVM
   - prl hyperv
   - Microsoft Hv

 - Hostname Check: search for these strings
  - brbrb-d8fb22af1
  - jonathan-c561e0
  - avreview1-VMXP
  - vwinxp-maltest
  - avreview-VMSunbox
  - infected-system

 - Even more strings:
  - malware.exe
  - \virus\
  - admin\downloads\samp1e_
  - sample_execution
  - mlwr_smpl.exe

 - look for this call; might be malicious
  - RtlGetNativeSystemInformation

 - and many more...,