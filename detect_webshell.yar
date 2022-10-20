import "magic"

rule Webshell_wp_custm {
	meta:
		description = "Web Shell - wp-custm.php - Heavily obfuscated webshell"
		author = "Farhan Faisal"
		date = "2018/07/17"
		score = 70
		hash = "f85b0e08afa5d328b42d73c8f9b99c9b"
	strings:
		$s0 = "fputs"
		$s1 = "include"
		$s2 = "fclose"
		$s3 = "str_replace"
		$s4 = "fopen"
		$s5 = "<?php"
		$s6 = "\",\"w\")"
		$s7 = "str_replace("
		$s8 = "$$$$$$$"
	condition:
		all of them
}


rule Webshell_SH_uploader_cleartext {
    meta:
     	description = "Web Shell - SH file uploader (cleartext)"
        author = "Farhan Faisal"
        date = "2018/07/17"
        score = 70
        hash = "1dcc711d35772234413f54c0540efb9a"
    strings:
        $s0 = "<title>SH</title>"
        $s1 = "0x00.ath.cx"
        $s2 = "is_callable(\"posix_getuid"
        $s3 = "is_callable(\"php_uname"
        $s4 = "posix_getpwuid"
    condition:
        all of them
}

rule Webshell_simple_dama_php_cleartext {
    meta:
     	description = "Webshell - simple dama.php cleartext"
        author = "Farhan Faisal"
        date = "2018/07/17"
        score = 60
        hash = "7b19a553a5f2a61c0f9f1122c54c907c"
    strings:
        $s1 = "set_time_limit"
        $s2 = "error_reporting"
        $s3 = "get_magic_quotes_gpc"
        $s4 = "404-server"
        $s5 = "multipart/form-data"
        $s6 = "php_uname"
        $s7 = "is_readable"
    condition:
        all of them
}

rule Webshell_chinese_filebox_php_cleartext {
	meta:
		description = "Webshell - PHP Chinese webshell (cleartext)"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "67447a35d2bf604a7bb087a983553164"
	strings:
		$s1 = "Microsoft Yahei"
		$s2 = "setcookie"
		$s3 = "SHELL"
		$s4 = "宇宙无敌的"
		$s5 = "login"
		$s6 = "payload_selfshell_filename"
	condition:
		all of them and ( filesize > 38KB and filesize < 45KB )
}

rule Webshell_CMSmap_Wordpress_shellfile {
	meta:
		description = "Webshell - Wordpress shell CMSmap : https://github.com/m7x/cmsmap/"
        author = "Farhan Faisal"
        date = "2020/01/24"
        score = 60
        hash = "34a575b4fe98c883391ac14e2a82a683"
    strings:
    	$s1 = "CMSmap"
    	$s2 = "password"
        $s3 = "Class_UC_key"
        $s4 = "reate_Function("
    	/*$obs = /([A-Za-z0-9]{100,})/*/
   	condition:
   		(all of ($s*))
}

rule Webshell_CMSmap_Wordpress_include {
	meta:
		description = "Webshell - Wordpress shell CMSmap : https://github.com/m7x/cmsmap/"
        author = "Farhan Faisal"
        date = "2020/01/24"
        score = 60
        hash = "7916633ab9fd59aa6a23f09091f7fe23"
    strings:
    	$s1 = "CMSmap"
    	$s2 = "include"
    	
   	condition:
   		(all of ($s*)) and filesize < 2KB
}

/*rule Webshell_WebShellOrb {
	meta:
		description = "Webshell - WebShellOrb. Totally obfuscated."
        author = "Farhan Faisal"
        date = "2020/01/24"
        score = 60
        hash = "380fa777b8c37fb60811e5972391261b"
    strings:
    	$s1 = "WebShellOrb"
    	$s2 = "eval"
    	$s3 = "base64_decode"

    	$obs = /([A-Za-z0-9]{100,})/
   	condition:
   		(all of ($s*)) and $obs
}*/


/*  rule Webshell_SSHv1_Pure_PHP {
    meta:
        description = "Webshell - Pure_PHP implementation of SSHV1."
        author = "Farhan Faisal"
        date = "2021/06/24"
        score = 60
        hash = "3ebb5a6dd1af6b0114523bb91df2ff9b"
    strings:
        $s1 = "Pure-PHP"
        $s2 = "terrafrost"
        $s3 = "NET_SSH1_CIPHER_3DES"
        $s4 = "NET_SSH1_"
        $s5 = "getServerKeyPublicExponent"
        $s6 = "_get_channel_packet"
        $s7 = "Crypt_TripleDES"
        $s8 = "SSH_CMSG_AUTH_PASSWORD"
    condition:
        (all of ($s*))
}  */


rule Webshell_GENERIC_webshell_characteristic {
    meta:
        description = "Webshell - Generic obfuscated webshell"
        author = "Farhan Faisal"
        date = "2021/06/24"
        score = 60
        hash = "736f94bb9ec70f51d4e963c38bdc7f02"
    strings:
        $s1 = "ini_set"
        $s2 = "max_execution_time"
        $s3 = "error_reporting"
        $s4 = "set_time_limit"
        $s5 = "log_errors"
        $s6 = "urlencode"
        $s7 = "file_get_contents"
        $s8 = "curl_init"
        $s9 = "base64_decode"
        $s10 = "urldecode"
        $s11 = "eval("
        $s12 = "gzuncompress"
        $s13 = "str_rot13"
        $s14 = "assert"
        $s15 = "htmlspecialchars_decode"
        $m1 = "<?php"
    condition:
        (9 of ($s*)) and $m1
}

rule Webshell_IRCBOT_1 {
    meta:
        description = "Webshell-obfuscated 6. weird char. Need further analysis /missed/boxpeiur.php"
        author = "Farhan Faisal"
        date = "2018/07/22"
        score = 60
        hash = "18b07c5e3f4521ef7a3b141250ef9707"
    strings:
        $s1 = "gethostbyaddr"
        $s2 = "CURLOPT"
        $s3 = "chmod"
        $xx1 = "'#"
    condition:
        filesize < 8KB and (#xx1 > 10) and (all of ($s*))
}


/*rule Small_eval_for_POST_smallest_backdoor {
    meta:
        description = "Eval for post data - smallest"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 80
    strings:
        $s1 = "POST"
        $s2 = "eval"
    condition:
        all of them and filesize < 50
}*/

rule Shell_PHP_eval_oneliner_1 {
    meta:
        description = "PHP checker - one-liner"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 80
    strings:
        $s1 = "<?php"
        $s2 = "base64_decode"
        $s3 = "eval"
        $s4 = "system("
        $s5 = "exec("
        $s6 = /(_REQUEST|_GET|_POST)/

        $x1 = "evaluated"
        $x2 = "namespace"
    condition:
        (3 of ($s*)) and (not (any of ($x*))) and filesize < 300
}

rule Shell_JSP_eval_oneliner_1 {
    meta:
        description = "JPS small webshell agent - one-liner"
        author = "Farhan Faisal"
        date = "2021/06/25"
        score = 80
    strings:
        $s1 = "<%@"
        $s2 = "eval"
        $s3 = "Request.Item"
    condition:
        (2 of ($s*)) and (filesize < 200)
}

rule Shell_GENERIC_simple_plain_webshell_feature {
    meta:
        description = "Generic PHP webshell - sample_webshell/p0wny-shell.php"
        author = "Farhan Faisal"
        date = "2021/06/29"
        score = 80
    strings:
        $s1 = "system("
        $s2 = "exec("
        $s3 = "eval("
        $s4 = "chdir("
        $s5 = "<?php"
        $s6 = "compgen"
        $s7 = "bin/bash"
    condition:
        (5 of ($s*)) 
}
