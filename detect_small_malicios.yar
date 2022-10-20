rule Small_malicious_php_checker_php_sapi_name {
	meta:
		description = "malicious - small php checker (php_sapi_name)"
	        author = "Farhan Faisal"
	        date = "2018/07/19"
	        score = 80

	strings:
		$s1 = "error_reporting"
		$s2 = "stristr(php_sapi_name"
		$s3 = "404.html"
		$s4 = "exit();"

	condition:
		(all of ($s*)) and filesize < 300
}



rule Small_Redirector_JSfile {
	meta:
		description = "Redirector - small js redirector"
	        author = "Farhan Faisal"
	        date = "2018/07/19"
	        score = 80
        strings:
		$s1 = /^var/
		$s2 = "document["
	condition:
		(all of ($s*)) and filesize < 500
}



/* rule Small_PHP_Unknown_2 {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/opn-post.php"
	        author = "Farhan Faisal"
	        date = "2018/07/21"
	        score = 80
	strings:
		$s1 = "str_replace"
		$s2 = "php"
		$xx1 = "="
	condition:
		filesize < 350 and (all of ($s*)) and (#xx1 > 7)
} 

rule Small_PHP_unknown_3 {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/menu-getTicketAssignment.php"
	        author = "Farhan Faisal"
	        date = "2018/07/21"
	        score = 80
	strings:
		$s1 = "REQUEST"
		$s2 = "array"
		$xx1 = "("
	condition:
		filesize < 300 and (all of ($s*)) and (#xx1 > 5)
}  */


rule Small_PHP_read_suspected {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/lerbim.php"
	        author = "Farhan Faisal"
	        date = "2018/07/21"
	        score = 80
	strings:
		$s1 = "set_time_limit"
		$s2 = "php"
		$s3 = "suspected"
		$s4 = "scandir"
	condition:
		(all of ($s*)) and filesize < 350
}







rule Small_GENERIC_PHP_malicious___or________risky {
	meta:
		description = "Small file, obfuscated. sample_small_unknown/remove-add-to-cart-woocommerce-freemius-pjmbmefi.php"
	        author = "Farhan Faisal"
	        date = "2020/01/24"
	        score = 60
        	hash = "71770889e59cf3f1daef73afc9feea5b"
	strings:
		$s1 = "is_writable"
		$s2 = "$_POST"
		$s3 = "global"
		$s4 = "serialize"
		$s5 = "phpversion"
		$s6 = "create_function"
		$s7 = "str_rot13"
		$s8 = "session_get_cookie_params"
		$s9 = "function"
		$s10 = "rawurldecode"
		$m1 = "eval("
		$m2 = "base64"
		$xx2 = "<?php"
	condition:
		filesize < 2400 and ((6 of ($s*)) or (all of ($m*))) and $xx2
}


rule Small_GENERIC_PHP_malicious___or_______risky2 {
	meta:
		description = "Small file, obfuscated. sample_small_unknown/generic_tiny/temp-dfrqcntkqoqfzbuk.php.suspected"
	        author = "Farhan Faisal"
	        date = "2020/01/28"
	        score = 60
        	hash = ""
        strings:
		$s2 = "$_"
		$s3 = "function"
		$s4 = "exit"
		$s5 = "base64_decode"
		$s6 = "str_rot13"
		$s7 = "array"
		$s8 = "htmlspecialchars_decode"
		$s9 = "eval("
	condition:
		filesize < 1KB and ((5 of ($s*)))
}







/* --------------------------------------------------
rule Small_PHP_Unknown_1 {
	meta:
		description = "Small PHP - Unknown 1"
	        author = "Farhan Faisal"
	        date = "2018/07/21"
	        score = 80
	strings:
		$s1 = "]."
		$s2 = "php"
	condition:
		filesize < 2KB and (#s1 > 30) and $s2
} // This rule were replaced by Obfuscation_small_GenericPHPWebshell_(bracker|xor) rule   
--------------------------------------------------*/ 


/*  --------------------------------------------------
rule SmallPHP_Unknown_4 {
	meta:
		description = "Small PHP - Unknown 1"
	        author = "Farhan Faisal"
	        date = "2018/07/21"
	        score = 80
	strings:
		$s1 = "$_REQUEST"
		$s2 = "php"
	condition:
		filesize < 300 and ( any of ($s*) )
}   DISABLED : too many false positive detection. Mostly included files in themes files.. 
--------------------------------------------------*/


/* --------------------------------------------------
rule Small_PHP_malicious_2 {
	meta:
		description = "Small file, obfuscated.  temp-dfrqcntkqoqfzbuk.php.suspected "
	        author = "Farhan Faisal"
	        date = "2020/01/24"
	        score = 60
	        hash = "a720c3239e4d114b586a98753bef02d9"
	strings:
		$s1 = "function"
		$s2 = "base64"
		$s3 = "POST"
	condition:
		filesize < 700 and (all of ($s*))
}  -------------------------------------------------- */


/* --------------------------------------------------
rule Small_PHP_malicious_4 {
        meta:
                description = "Small file, obfuscated.  temp-dfrqcntkqoqfzbuk.php.suspected "
	        author = "Farhan Faisal"
	        date = "2021/03/06"
	        score = 60
	        hash = ""
        strings:
                $s1 = "function"
                $s2 = "return"
                $s3 = "].$"
        condition:
                filesize < 5KB and (#s1 > 1) and (#s2 > 1) and (#s3 > 10)
}  -------------------------------------------------- */

/*  --------------------------------------------------
rule Small_PHP_malicious_4_1 {
        meta:
                description = "Small file, obfuscated.  temp-dfrqcntkqoqfzbuk.php.suspected "
	        author = "Farhan Faisal"
	        date = "2021/06/24"
	        score = 60
	        hash = ""
        strings:
                $s1 = "urldecode"
                $s2 = "return"
                $s3 = "}.$"
        condition:
                filesize < 5KB and (#s1 > 0) and (#s2 > 0) and (#s3 > 5)
}  --------------------------------------------------  */


/* --------------------------------------------------
rule Small_PHP_malicious_5 {
        meta:
                description = "Small file, obfuscated.   "
	        author = "Farhan Faisal"
	        date = "2021/06/24"
	        score = 60
	        hash = "a840b07dfe2c5d1aca53060b4d00d853"
        strings:
                $s1 = "php"
                $s2 = "})"
                
        condition:
                filesize < 4KB and (#s1 == 1) and (#s2 > 15)
}  --------------------------------------------------  */

/* --------------------------------------------------
rule Small_PHP_malicious_6 {
        meta:
                description = "Small file, obfuscated.  "
	        author = "Farhan Faisal"
	        date = "2021/06/24"
	        score = 60
	        hash = "760393d0f78c0d5111c00ab0db791ab5"
        strings:
                $s1 = "php"
                $s2 = "()"
                $zz10 = "public"
		$zz11 = "namespace"
		$zz12 = "<div"
		$zz13 = "<!--"
		$zz14 = "-->"
		$zz15 = "_LANG"
		$zz16 = "</"
		$zz17 = "->"
        condition:
                filesize < 2KB and (#s1 == 1) and (#s2 == 1) and not (any of ($zz*))
} --------------------------------------------------  */  
/*Too much false positive, only 2 criteria, PHP and () */


