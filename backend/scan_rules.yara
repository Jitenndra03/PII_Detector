// File: scan_rules.yara
// This file contains YARA rules for detecting potentially malicious content in PDFs

rule Suspicious_JavaScript_PDF {
  meta:
    description = "Detects suspicious JavaScript in PDF files"
    severity = "high"
  strings:
    $js = "JavaScript" nocase
    $eval = "eval(" nocase
    $exec = "exec(" nocase
    $payload = /(%[0-9a-fA-F]{2}){4,}/ // Detect potential encoded content
  condition:
    $js and ($eval or $exec or $payload)
}

rule Malicious_PDF_URI {
  meta:
    description = "Detects suspicious URIs in PDF"
    severity = "medium"
  strings:
    $uri = /URI\s*\((http|https|ftp).+\)/ nocase
    $suspicious_domain1 = /(\.ru|\.cn|\.su|\.io)\s*\)/i
    $suspicious_tld = /(\.xyz|\.top|\.club|\.cc)\s*\)/i
  condition:
    $uri and ($suspicious_domain1 or $suspicious_tld)
}

rule PDF_Embedded_File {
  meta:
    description = "Detects embedded files in PDF which could contain malware"
    severity = "medium"
  strings:
    $embed1 = "/EmbeddedFile" nocase
    $embed2 = "/Filespec" nocase
    $exe = ".exe" nocase
    $dll = ".dll" nocase
    $js = ".js" nocase
    $bat = ".bat" nocase
    $bin = ".bin" nocase
  condition:
    ($embed1 or $embed2) and ($exe or $dll or $js or $bat or $bin)
}

rule PDF_Obfuscation {
  meta:
    description = "Detects PDF obfuscation techniques"
    severity = "medium"
  strings:
    $filter = "/Filter" nocase
    $ascii85 = "/ASCII85Decode" nocase
    $asciihex = "/ASCIIHexDecode" nocase
    $flate = "/FlateDecode" nocase
    $lzw = "/LZWDecode" nocase
    $multiple_filters = /\/Filter\s*\[\s*[^\]]+\]/
  condition:
    $filter and (($ascii85 and $flate) or ($asciihex and $flate) or $multiple_filters)
}

rule PDF_Shellcode {
  meta:
    description = "Detects potential shellcode in PDF"
    severity = "high"
  strings:
    $shellcode1 = { 90 90 90 } // NOP sled
    $shellcode2 = { 31 c0 50 68 } // Common shellcode starter
    $shellcode3 = { 68 ?? ?? ?? ?? 58 } // PUSH address, POP eax
  condition:
    any of them
}

rule PDF_Suspicious_Launch_Actions {
  meta:
    description = "Detects suspicious launch actions in PDF"
    severity = "high"
  strings:
    $launch = "/Launch" nocase
    $action = "/Action" nocase
    $openaction = "/OpenAction" nocase
    $javascript = "/JavaScript" nocase
    $submenu = "/SubmitForm" nocase
  condition:
    ($launch or $action or $openaction) and ($javascript or $submenu)
}