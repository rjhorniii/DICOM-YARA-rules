rule Part10_DCM_OK
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detect basic DICOM Part10 files"
		method = "Look for empty prefix, and DICM at 128"
		threat = "none, this is normal DICOM"

  	condition:
		uint32(128) == 0x4D434944 and for all i in (0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120) :  (uint32(i)==0x00000000 )
}
rule Part10_with_low_risk_extra
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detect basic DICOM Part10 files"
		method = "Look for empty prefix, and DICM at 128"
		threat = "low, this is normal DICOM plus some extra content"

  	condition:
		uint32(128) == 0x4D434944 and uint32(0)==0x00000000 
}
rule Part10_with_unknown_risk_extra
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detect basic DICOM Part10 files"
		method = "Look for empty prefix, and DICM at 128"
		threat = "unknown, this is DICOM with an unknown prefix"

  	condition:
		uint32(128) == 0x4D434944 and uint32(0)!=0x00000000
}
rule Part10_TIFF_OK
{
	meta:
		author = "Rob Horn"
		date = "2019-09-30"
		description = "Detects DICOM Part10 files with TIFF personality"
		method = "Look for TIFF ID at beginning, DICM at 128"
		threat = "none, this is normal DICOM-TIFF"

  	condition:
		uint32(128) == 0x4D434944 and (uint16(0) == 0x4D4D or uint16(0) == 0x4949) 
}
rule Part10_ELF_malware
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detects DICOM Part10 files that contain ELF"
		method = "Look for ELF ID at beginning, and DICM at 128"
		threat = "HIGH.  DICOM files should never be executable"


  	condition:
		uint32(128) == 0x4D434944 and uint32(0) == 0x464C457F 
}
rule Part10_java_mac_malware
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detect DICOM Part10 files that contain Java or MacOS executeable"
		method = "Look for 0xcafe or 0xfeedface at beginning, and DICM at 128"
		threat = "HIGH. Dicom files should never be executable"

  	condition:
		uint32(128) == 0x4D434944 and ((uint16(0)== 0xFECA or uint32(0)==0xCEFAEDFE))
}
rule Part10_PE_malware
{
	meta:
		author = "Rob Horn"
		date = "2019-10-03"
		description = "Detect DICOM Part10 files that contain PE or DOS executable content"
		method = "Look for MZ at beginning, and DICM at 128"
		threat = "HIGH. Dicom files should never be executable"

  	condition:
		 uint32(128) == 0x4D434944 and uint16(0) == 0x5A4D
}
