rule Obfuscation_Webshell_1 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/helper.php"
        author = "Farhan Faisal"
        date = "2018/07/17"
        score = 60
		hash = "316c188bbbf34d92c840e32f7c1b148f"
	strings:
		$ss1 = "foreach(array"
		$ss2 = "''.''."
		$ss3 = "()"
	condition:
		filesize > 110KB and filesize < 130KB and (#ss1 > 1) and (#ss2 > 8) and $ss3
}

rule Obfuscation_Webshell_2 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/decode.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "d8577ec2847469fefcfb6839af524166"
	strings:
		$ss1 = "GLOBALS"
		$ss2 = "]."
		$aa1 = "foreach ($_POST"
		$aa2 = "str_split"
		$aa3 = "rawurldecode"
		$aa4 = "str_rot13"
		$aa5 = "phpversion"
		$aa6 = "is_writable"
		$aa7 = "file_put_contents"
	condition:
		(#ss1 > 1) and (#ss2 > 90) and (all of ($aa*))
}



rule Obfuscation_Webshell_5_GLOBAL_sort {
	meta:
		description = "Webshell-obfuscated 5. Use GLOBAL and sort. Need further analysis /missed/db_connector.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "e1cf9ccce21bb609ba3c19cc6a7d0b80"
	strings:
		$s1 = "GLOBALS"
		$s2 = "eval"
		$xx1 = "]["
		$xx2 = "\\x"
	condition:
		(all of ($s*)) and (#xx1 > 30) and (#xx2 > 20) and (filesize < 30KB)
}


rule Obfuscation_obfuscated_6_weirdChar {
	meta:
		description = "Webshell-obfuscated 6. weird char. Need further analysis /missed/baklswty.php"
        author = "Farhan Faisal"
        date = "2018/07/22"
        score = 60
        hash = "3454e48b6d84b816c0dcd6abd79ad05a"
	strings:
		$s1 = "php"
		$s2 = "function"
		$s3 = "rawurl"
		$s4 = "decode"
		$s5 = "eval"
		$xx1 = "=>"
	condition:
		(all of ($s*)) and (#xx1 > 40) and filesize < 8KB
}






rule Obfuscation_Webshell_Unknown_1 {
	meta:
		description = "mix obfuscated code and base64 encoding. cache-hsjwqftqbcdhfogq.php.suspected"
        author = "Farhan Faisal"
        date = "2020/01/25"
        score = 60
        hash = "27ae2a14b7d70badc45747ddc6162b20"
	strings:
		$s1 = "function"
		$s2 = "php"
		$obs1 = /\/\*([A-Za-z0-9]{10,60})\*\//
		$xx1 = "]."
		$zz1 = "echo"
		$zz2 = "print"
		$zz3 = "jpeg"
		$zz4 = "webpack"
		$zz5 = "swfobject"
		$zz6 = "window."
		$zz7 = "getid3"
		$zz8 = "jQuery"
		$zz9 = "Superfish"
		$zz10 = "WordPress"
		$zz11 = "Flexslider"
		$zz12 = "framework"
	condition:
		filesize < 30KB and (#xx1 > 3) and (all of ($s*)) and not (any of ($zz*)) and $obs1
}
/*
	this is the difficult one. Not much pattern to search for, except base64, which makeit slow.
	sample in sample_heavily_obfuscated/cache-hsjwqftqbcdhfogq.php.suspected
*/







rule Obfuscation_no_detectable_Call_base64_n_encoding {
	meta:
		description = "mix obfuscated code and base64 encoding"
        author = "Farhan Faisal"
        date = "2020/01/24"
        score = 60
        hash = "27ae2a14b7d70badc45747ddc6162b20"
	strings:
		$ch1 = "<?php"
		$ch2 = "_)"			/* Any of these, having more than 1 time.  */
		$ch3 = ");$"
		$ss = "],"			/* More than 10 */
		/*   $obs1 = /\/\*([A-Za-z0-9]{1,30})\*\//  */
		/*  $obs2 = /([A-Za-z0-9]{100,})/   */
		/*  $xx1 = "eval"	// any exception needed */
	condition:
		filesize < 30KB  and ((#ch1 > 1) and (#ch2 > 1) and (#ch3 > 1) ) and (#ss > 40)
		/* and (
				magic.mime_type() == "text/x-php" or
				magic.mime_type() == "text/x-c++"
				)*/
		/* and not (any of ($xx*)) */
}
/* TOO MANY FALSE POSITIVE */



/*rule Obfuscation_Unknown_ICO_1 {
	meta:
		description = "Obfuscated code. Found as ico file. sample_heavily_obfuscated/.872eb066.ico"
        author = "Farhan Faisal"
        date = "2020/01/25"
        score = 60
        hash = "31c55d6125fcbcb74ab18f8b70d26c57"
	strings:
		$s1 = "basename"
		$s2 = "rawurldecode"
		$s3 = "__FILE__"
		$s4 = "<?php"
		$s5 = "strlen"
		$s6 = "preg_replace"
		$xx1 = "%"
	condition:
		(#xx1 > 100) and (all of ($s*))
}*/




/*rule Obfuscation_small_GenericPHPWebshell______xor {
			meta:
						description = "asdsa"
						author = "Farhan Faisal"
						date = "2021/06/25"
						score = 60
						hash = "asdasd"
			strings:
						$s1 = "<?php"
						$s2 = /\^/
						$s3 = /\$[a-zA-Z0-9]{3,30}\(\);/
						$s4 = "('',"
			condition:
						filesize < 2200 and (all of ($s*))
}*/

rule Obfuscation_small_GenericPHPWebshell______xor {
			/*
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/fpxrmucy.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/u81s35c0.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/ehnxwpfa.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/0x5bsjf6.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/nwaku5e6.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/iumehqkg.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/cp9052ad.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/vyfuofqq.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/qrwzoges.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/generic_tiny/ndqirbsj.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/esdindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/nbtindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/filerun-wl-mrozjq18.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/filerun-weblinks-tdg21q4f.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/zreindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_small_unknown/xor_bracket/scpuibrn.php
			Obfuscation_small_GenericPHPWebshell______xor .//tests/wordpress-site/wp-content/plugins/wordfence/lib/wfCurlInterceptor.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_done_analysis/esdindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_done_analysis/nbtindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_missed/jscmle1z.php
			Obfuscation_small_GenericPHPWebshell______xor .//sample_done_analysis/zreindex.php
			Obfuscation_small_GenericPHPWebshell______xor .//repo/malwares/webshell-sample/php/7fca0ae0441bfb996544e9781c6d92a1f7dc3fab.php
			Obfuscation_small_GenericPHPWebshell______xor .//repo/malwares/webshell-sample/php/bc9c4a049e3d4d0fbde64c3f4e2cacab831c248a.php
			Obfuscation_small_GenericPHPWebshell______xor .//repo/malwares/webshell-sample/php/b91e5ff3894664bb45a77d88670c8cf90b6480e3.php
			*/
			meta:
						description = "asdsa"
						author = "Farhan Faisal"
						date = "2021/06/25"
						score = 60
						hash = "asdasd"
			strings:
						$s1 = "<?php"
						/*  $s2 = /\^\$[a-zA-Z0-9]{6-15}\)/  doesntwork */
						$s3 = /\$[a-zA-Z0-9]{6,15}\(\);/
						$n1 = /(new\ |return\ |-\>)\$[a-zA-Z0-9]{6,15}\(\);/
						/*$s4 = "('',"*/
						$n2 = "namespace"
						$n3 = "use "
						$n4 = "opyright"
						$n5 = "icensing"
			condition:
						filesize < 2200 and (all of ($s*)) and not (any of ($n*))
			}   	/* This seems works better now, capturing all files matching BRACKET rule.
						FP - wp-content/plugins/wordfence/lib/wfCurlInterceptor.php
						*/







rule Obfuscation_GENERIC_small_hex_____________2KB {
			/*
					Obfuscation_GENERIC_small_hex_____________2KB .//sample_small_unknown/unique/gfbuild.php
					Obfuscation_GENERIC_small_hex_____________2KB .//sample_small_unknown/unique/gffind.php
					Obfuscation_GENERIC_small_hex_____________2KB .//sample_small_unknown/unique/gf_gate.php.decoded.php
					Obfuscation_GENERIC_small_hex_____________2KB .//sample_small_unknown/unique/gf_gate.php
					Obfuscation_GENERIC_small_hex_____________2KB .//sample_done_analysis/gffind.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/malwares/webshell-sample/php/eb22df511d87d657dceefbc9d18e371de7383116.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/malwares/Sender-Office365/Sender-Office365/setting/phpmailer/PHPMailerAutoload.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/malwares/Sender-Office365/Sender-Office365/setting/idn.settings.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/malwares/Sender-Office365/setting/phpmailer/PHPMailerAutoload.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/malwares/Sender-Office365/setting/idn.settings.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/rules/Web-Shell-Yara/b374k_webshells.yara
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/rules/php-malware-finder/php-malware-finder/samples/obfuscators/online_php_obfuscator.php
					Obfuscation_GENERIC_small_hex_____________2KB .//repo/rules/php-malware-finder/php-malware-finder/samples/real/include.php
			*/
			meta:
						description = "Webshell-obfuscated. Need further analysis /sample_missed/prv8.php"
						author = "Farhan Faisal"
						date = "2018/07/21"
						score = 60
						hash = "994efbd230e21cc85a5acf39652cee26"
			strings:
						$s1 = "\\x"
						$n1 = "namespace"
						$n2 = "use "
						$n3 = "opyright"
						$n4 = "icensing"
			condition:
						#s1 > 20 and filesize < 2KB and not (any of ($n*))
}
