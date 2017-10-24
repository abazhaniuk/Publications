# PUBLICATIONS
  
* [“Discovering vulnerable UEFI BIOS firmware at scale”](https://github.com/abazhaniuk/Publications/blob/master/2017/44CON_2017/Bulygin_Bazhaniuk_44con.pdf), 44CON 2017
* [“Attacking hypervisors through hardware emulation”](https://github.com/abazhaniuk/Publications/blob/master/2017/Troopers_2017/TR17_Attacking_hypervisor_through_hardwear_emulation.pdf), Troopers 2017
* [“BARing the System New vulnerabilities in Coreboot & UEFI based systems”](https://github.com/abazhaniuk/Publications/blob/master/2017/REConBrussels_2017/REConBrussels2017_BARing_the_system.pdf), Recon Brussels 2017
* [“Digging Into The Core of Boot”](https://github.com/abazhaniuk/Publications/blob/master/2017/RECon_2017/DiggingIntoTheCoreOfBoot.pdf), Recon 2017
* [“Driving Down the Rabbit Hole”](https://github.com/abazhaniuk/Publications/blob/master/2017/DEFCON25/DC25_Driving%20down%20the%20rabbit%20hole-Mickey_Jesse_Oleksander.pdf), DEF CON 25
* [“Exploring Your System Deeper \[with CHIPSEC\] is Not Naughty”](https://github.com/abazhaniuk/Publications/blob/master/2017/CanSecWest_2017/csw2017_ExploringYourSystemDeeper_updated.pdf), CanSecWest 2017
* [“Fractured Backbone: Breaking Modern OS Defenses with Firmware Attacks”](https://github.com/abazhaniuk/Publications/blob/master/2017/BlackHat_USA_2017/us-17-Bulygin-Fractured-Backbone-Breaking-Modern-OS-Defenses-With-Firmware-Attacks.pdf), Black Hat 2017
* [“Blue Pill for Your Phone”](https://github.com/abazhaniuk/Publications/blob/master/2017/Ekoparty13_2017/us-17-Bazhaniuk-Bulygin-BluePill-for-Your-Phone.pdf), Black Hat 2017
* [“Different methods of BIOS analysis: Static, Dynamic and Symbolic execution”](https://github.com/abazhaniuk/Publications/blob/master/2016/analyze.cc_2016/Different_methods_of_BIOS_analysis.pdf), Analyze 2016
* [“Symbolic execution for BIOS security”](https://github.com/abazhaniuk/Publications/blob/master/2015/USENIX_WOOT_2015/woot15_slides_bazhaniuk.pdf), USENIX WOOT 2015
* [“Reaching the far corners of MATRIX: generic VMM fingerprinting”](https://github.com/abazhaniuk/Publications/blob/master/2015/SOURCE_2015/source-seattle-2015-generic_vmm_fingerprinting.pdf), SOURCE 2015
* [“Attacking and Defending BIOS in 2015”](https://github.com/abazhaniuk/Publications/blob/master/2015/RECon_2015/AttackingAndDefendingBIOS-RECon2015.pdf), Recon 2015
* [“ASN.1 parsing in crypto libraries: what could go wrong?”](https://github.com/abazhaniuk/Publications/blob/master/2015/Latincrypt_2015/ASN1_parsing_issues_in_crypto_Latincrypt2015.pdf), Latincrypt 2015
* [“A New Class of Vulnerabilities in SMI Handlers”](https://github.com/abazhaniuk/Publications/blob/master/2015/CanSecWest_2015/ANewClassOfVulnInSMIHandlers_csw2015.pdf), CanSecWest 2015
* [“Attacking Hypervisors via Firmware and Hardware”](https://github.com/abazhaniuk/Publications/blob/master/2015/BlackHat_DEFCON_2015/AttackingHypervisorsViaFirmware_bhusa15_dc23.pdf), Black Hat 2015 and DEF CON 23
* [“BERserk: New RSA Signature Forgery Attack”](https://github.com/abazhaniuk/Publications/blob/master/2014/Ekoparty10/eko10-BERserk_New_RSA_Signature_Forgery_Attack.pdf), Ekoparty 2014
* [“Summary of Attacks Against BIOS and Secure Boot”](https://github.com/abazhaniuk/Publications/blob/master/2014/DEFCON22/DEFCON22-BIOSAttacks.pdf), DEF CON 22
* [“All Your Boot Are Belong To Us”](https://github.com/abazhaniuk/Publications/blob/master/2014/CanSecWest_2014/AllYourBoot_csw14-intel-final.pdf), CanSecWest 2014
* [“A Tale of One Software Bypass of Windows 8 Secure Boot”](https://github.com/abazhaniuk/Publications/blob/master/2013/BlackHat_USA_2013/Windows8SecureBoot_Bulygin-Furtak-Bazhniuk_BHUSA2013.pdf), Black Hat USA 2013
* [“HI-CFG: Construction by Binary Analysis, and Application to Attack Polymorphism”](https://github.com/abazhaniuk/Publications/blob/master/2013/ESORICS_2013/caselden13esorics.pdf), ESORICS 2013
* [“Automatically Searching for Vulnerabilities: How to Use Taint Analysis to Find Security Bugs”](https://github.com/abazhaniuk/Publications/blob/master/2012/HITBsecconf2012ams/D2T1%20-%20Alex%20Bazhanyuk%20and%20Nikita%20Tarakanov%20-%20Automatically%20Searching%20for%20Vulnerabilities.pdf), Hack In The Box 2012
* [“The System of Automatic Searching for Vulnerabilities or how to use Taint Analysis to find security bugs”](https://github.com/abazhaniuk/Publications/blob/master/2012/HackitoErgoSum_2012/HES2012-ntarakanov-SASV_ABazhanyuk.pdf), Hackito Ergo Sum 2012
* Winner of the competition Hack2Own at Positive Hack Days 2011. Coworker and I demonstrated 0day vulnerability (CVE-2011-0222) in the latest version of Safari for Windows and took the first prize

# CVEs:

* **CVE-2017-9633** – An attacker with a physical connection to the TCU may exploit a buffer overflow condition that exists in the processing of AT commands. This may allow arbitrary code execution on the baseband radio processor of the TCU
https://ics-cert.us-cert.gov/advisories/ICSA-17-208-01
* **CVE-2017-9647** – A vulnerability in the temporary mobile subscriber identity (TMSI) may allow an attacker to access and control memory. This may allow remote code execution on the baseband radio processor of the TCU
https://ics-cert.us-cert.gov/advisories/ICSA-17-208-01 <br>
 **AFFECTED PRODUCTS**<br>
 All telematics control modules (TCUs) built by Continental AG that contain the S-Gold 2 (PMB 8876) cellular baseband chipset are affected. The S-Gold 2 (PMB 8876) is found in the following vehicles:<br>
 \- BMW several models produced between 2009-2010<br>
 \- Ford - program to update 2G modems has been active since 2016 and impact is restricted to the limited number of P-HEV vehicles equipped with this older technology that remain in service<br>
 \- Infiniti 2013 JX35, Infiniti 2014-2016 QX60, Infiniti 2014-2016 QX60 Hybrid, Infiniti 2014-2015 QX50, Infiniti 2014-2015 QX50 Hybrid, Infiniti 2013 M37/M56, Infiniti 2014-2016 Q70, Infiniti 2014-2016 Q70L, Infiniti 2015-2016 Q70 Hybrid, Infiniti 2013 QX56, Infiniti 2014-2016 QX 80<br>
 \- Nissan 2011-2015 Leaf<br>
* **CVE-2016-4002** – Buffer overflow in the mipsnet_receive function in hw/net/mipsnet.c in QEMU, when the guest NIC is configured to accept large packets, allows remote attackers to cause a denial of service (memory corruption and QEMU crash) or possibly execute arbitrary code via a packet larger than 1514 bytes
* **CVE-2016-4001** – Buffer overflow in the stellaris_enet_receive function in hw/net/stellaris_enet.c in QEMU, when the Stellaris ethernet controller is configured to accept large packets, allows remote attackers to cause a denial of service (QEMU crash) via a large packet
* **CVE-2015-0427** – Integer overflow causes memory corruption in VMSVGAFIFOGETCMDBUFFER in Oracle VirtualBox prior to 4.3.20
* **CVE-2015-0418** – VirtualBox guest crashes when execute INVEPT/INVVPID instructions in user mode application
* **CVE-2015-4856** (2 vulnerability) - Read un-initialization memory at in Oracle VirtualBox prior to 4.0.30, 4.1.38, 4.2.30, 4.3.26, 5.0.0 by overlapping MMIO BARs with each other
* **CVE-2014-6588** – Memory corruption in VMSVGAGMRTRANSFER in Oracle VirtualBox
* **CVE-2014-6589** – Memory corruptions in VMSVGAFIFOLOOP in Oracle VirtualBox
* **CVE-2014-6590** – Memory corruptions in VMSVGAFIFOLOOP in Oracle VirtualBox
* **CVE-2014-3689** (3 vulnerability) – The vmware-vga driver (hw/display/vmware_vga.c) in QEMU allows local guest users to write to qemu memory locations and gain privileges via unspecified parameters related to rectangle handling
* **CVE-2014-3645** – QEMU guest crashes when execute INVEPT instructions in user mode application
* **CVE-2014-3646** – QEMU guest crashes when execute INVVPID instructions in user mode application
* **CVE-2011-0222** – Remotely exploitable memory corruption vulnerability in WebKit, as included with multiple vendors' browsers, could allow an attacker to execute arbitrary code with the privileges of the current user
 Links: http://support.apple.com/kb/ht4808 , http://seclists.org/fulldisclosure/2011/Jul/302

# VULNIRABILITIES (without CVE):
* Privilege escalation vulnerability from Android Kernel to Hypervisor on phones based on Qualcomm Snapdragon 808 and 810 SoC. Presented at Black Hat 2017: https://www.blackhat.com/docs/us-17/wednesday/us-17-Bazhaniuk-BluePill-For-Your-Phone.pdf  
* Number of vulnerabilities in EDK2 open source firmware reference implementation. Advisories: http://sourceforge.net/projects/edk2/files/Security_Advisory/EDK%20II%20Security%20Advisory%20Log%20002.pdf/download<br>
 http://www.tianocore.org/security/<br>
 Presented at RECon 2015:  [“Attacking and Defending BIOS in 2015”](https://github.com/abazhaniuk/Publications/blob/master/2015/RECon_2015/AttackingAndDefendingBIOS-RECon2015.pdf)<br>
* Number of vulnerabilities in open source firmware implementation for Minnowboard systems:<br>
 Release Notes: http://firmware.intel.com/sites/default/files/MinnowBoard_MAX-Rel_0.81-ReleaseNotes.txt 
* Bypass Windows 10 Virtualization Based Technology: <br>
 Presented at Black Hat 2017: https://www.blackhat.com/docs/us-17/wednesday/us-17-Bulygin-Fractured-Backbone-Breaking-Modern-OS-Defenses-With-Firmware-Attacks.pdf
* Privilege escalation vulnerability from Dom0 or Root Partition to Hypervisor on Xen and Microsoft Hyper-V systems:<br>
 Presented at Black Hat 2015: [“Attacking and Defending BIOS in 2015”](https://github.com/abazhaniuk/Publications/blob/master/2015/RECon_2015/AttackingAndDefendingBIOS-RECon2015.pdf) 
* Firmware S3 Boot Script vulnerability: <br>
 http://www.kb.cert.org/vuls/id/976132<br>
 ["Technical Details of the S3 Resume Boot Script Vulnerability"](https://github.com/abazhaniuk/Publications/blob/master/2015/WP_Intel_ATR_S3_ResBS_Vuln.pdf)
* RSA Padding check vulnerability in WolfSSL:<br>
 http://www.kb.cert.org/vuls/id/772676<br>
 http://www.wolfssl.com/yaSSL/Blog/Entries/2014/9/12_CyaSSL_3.2.0_Released.html
