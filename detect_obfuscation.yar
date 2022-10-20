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


rule Obfuscation_Webshell_3 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/baer.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "f2d7553b97d8e0a0258e48c3ca42a7d2"
	strings:
		$bb = /[0-9a-zA-Z]{80,}/
		$aa1 = "array"
		$aa2 = "();"
		$xx1 = "TextareaAutosize.prototype.componentDidMount"
		$xx2 = "ZoneScore.prototype.scoreOffsetAt"
		$xx3 = "wordpress_primitives"
		$xx4 = "window.wp.primitives"
	condition:
		(#bb > 40000) and (#aa1 > 3) and ($aa2) and not (any of ($xx*))
}



rule Obfuscation_GENERIC_base64_webshell {
	meta:
		description = "Webshell-obfuscated 5. Use GLOBAL and sort. Need further analysis in /sample_heavily_obfuscated/generic/"
        author = "Farhan Faisal"
        date = "2021/06/26"
        score = 60
        hash = ""
	strings:
		$m1 = "<?php"
		$m4 = /[0-9a-zA-Z+]{200,}/

		$s1 = "eval("
		$s2 = "base64_decode"
		$s3 = "gzuncompress"
		$s4 = "gzinflate"
		$s5 = "str_rot13"
		$s6 = "assert"
		$s7 = "htmlspecialchars_decode"
		$s8 = "urldecode"

		$xx1 = "namespace"
		$xx2 = "Author"
	condition:
		(all of ($m*)) and (3 of ($s*)) and not (any of ($xx*))
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
}   /* This seems works better now, capturing all files matching BRACKET rule. */



rule Obfuscation_GENERIC_substitution_____webshell {
	meta:
		description = "Generic webshell obfuscation technique, with some other visible function call"
        author = "Farhan Faisal"
        date = "2021/06/26"
        score = 60
        hash = ""
	strings:
		$s1 = /\[[0-9]{1,3}\]/
		$s2 = /\{[0-9]{1,3}\}/
		$s3 = /\([0-9]{1,3}\)/
		$s4 = "<?php"

		$x1 = "fsockopen"
		$x2 = "curl_setopt"
		$x3 = "function_exists"
		$x4 = "base64_decode"
		$x5 = "set_time_limit"
		$x6 = "error_reporting"
		$x7 = "move_uploaded_file"
		$x8 = "$_SERVER["
		$x9 = "encode"

		$m1 = "function _"
		$m2 = "ini_set"
	condition:
		filesize < 100KB and (#s1 > 30 or #s2 > 30 or #s3 > 30) and $s4 and (7 of ($x*)) and (all of ($m*))
}


 rule Obfuscation_small_GenericPHPWebshell_brackets {
	meta:
		description = "asdsa"
        author = "Farhan Faisal"
        date = "2021/06/25"
        score = 60
        hash = "asdasd"
	strings:
		$s1 = /\[[0-9]{1,3}\]/
		$s2 = /\{[0-9]{1,3}\}/
		$s3 = /\([0-9]{1,3}\)/
		$s4 = "<?php"
		$s5 = /\$[a-zA-Z0-9]{5,20}/
		$n1 = "namespace"
		$n2 = "use "
		$n3 = "opyright"
		$n4 = "icensing"
	condition:
		filesize < 2200 and (#s1 > 40 or #s2 > 41 or #s3 > 40) and $s4 and $s5 and not (any of ($n*))
} 
		/*$s1 = /[a-zA-Z0-9]{2,20}\[[0-9]{1,3}\]/
		$s2 = /[a-zA-Z0-9]{2,20}\{[0-9]{1,3}\}/
		$s3 = /[a-zA-Z0-9]{2,20}\([0-9]{1,3}\)/*/
/** RULE ABOVE are disabled as the below rule matches them all **/

rule Obfuscation_GENERIC_tiny_shell_PHP_2______2KB {
		meta:
			description = "Small file, obfuscated.  "
			author = "Farhan Faisal"
			date = "2021/06/26"
			score = 60
			hash = ""
        strings:
			$m1 = "<?php"

			$s1 = "eval"
			$s2 = /[0-9a-zA-Z]{200,}/
			$s3 = "str_rot13"
			$s4 = "return"
			$s5 = "base64_decode"
			$s6 = "md5"

			$P1 = "].$"
			$P2 = "}.$"
			$P3 = "})"
			$P4 = "''"
			/* $P5 = "][" */
			$P6 = "))"
			/* $P7 = "%" */
			/* $P8 = "$_" */
			$P9 = ")."
			/* $P10 = " . " */
			/* $P11 = "', '" */

			$x1 = "$('"


        condition:
        	(filesize < 2KB) and (all of ($m*)) and (1 of ($s*))  and (not any of ($x*))
        	and
        	( 
        		#P1 > 10 or
        		#P2 > 9 or
        		#P3 > 15 or
        		#P4 > 28 or
        		/* #P5 > 20 or */
        		#P6 > 50 or
        		/* #P8 > 10 or */
        		#P9 > 20
        		/* #P10 > 20 or */
        		/* #P11 > 20 */
        	  )
        	/* and (#xx1 < 5) and (#xx2 > 5) */
}


rule Obfuscation_GENERIC_small_hex_____________2KB {
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
