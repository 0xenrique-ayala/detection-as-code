rule CISA_251165_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 
exfiltrates_data 
{
meta: 
	author = "CISA Code & Media Analysis" 
	incident = "251165" 
	date = "2025-09-29" 
	last_modified = "202051001_1008" 
	actor = "n/a" 
	family = "BRICKSTORM" 
	capabilities = "installs-other-components communicates-with-c2 exfiltrates-data" 
	malware_type = "backdoor" 
	tool_type = "unknown" 
	description = "Detects Go-Based BRICKSTORM backdoor samples" 
	sha256_1 = "aaf5569c8e349c15028bc3fac09eb982efb06eabac955b705a6d447263658e38" 
strings: 
	$s0 = { 6D 61 69 6E 2E 73 74 61 72 74 4E 65 77 } 
	$s1 = { 6D 61 69 6E 2E 73 65 6C 66 57 61 74 63 68 65 72 } 
	$s2 = { 6D 61 69 6E 2E 73 65 74 53 65 72 76 69 63 65 43 66 67 } 
	$s3 = { 73 6F 63 6B 73 2E 48 61 6E 64 6C 65 53 6F 63 6B 73 52 65 71 75 65 73 74 } 
	$s4 = { 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 } 
	$s5 = { 63 6F 6D 6D 61 6E 64 2E 48 61 6E 64 6C 65 54 54 59 52 65 71 75 65 73 74 } 
	$s6 = { 77 65 62 73 6F 63 6B 65 74 2E 28 2A 57 53 43 6F 6E 6E 65 63 74 6F 72 29 2E 43 6F 6E 6E 65 63 74 }
	$s7 = { 66 73 2E 28 2A 57 65 62 53 65 72 76 65 72 29 2E 52 75 6E 53 65 72 76 65 72 } 
	$s8 = { 68 74 74 70 73 3A 2F 2F 31 2E 30 2E 30 2E 31 2F 64 6E 73 2D 71 75 65 72 79 } 
	$s9 = { 68 74 74 70 73 3A 2F 2F 31 2E 31 2E 31 2E 31 2F 64 6E 73 2D 71 75 65 72 79 } 
	$s10 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 34 2E 34 2F 64 6E 73 2D 71 75 65 72 79 } 
	$s11 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 38 2E 38 2F 64 6E 73 2D 71 75 65 72 79 } 
	$s12 = { 68 74 74 70 73 3A 2F 2F 39 2E 39 2E 39 2E 39 2F 64 6E 73 2D 71 75 65 72 79 } 
condition: 
8 of them 
}
