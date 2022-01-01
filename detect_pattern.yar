
rule PATTERN_webshell_feature_statistically {
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
rule PATTERN_simple_plain_webshell_feature_statistically {
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



rule GENERIC_dangerous_php_call {
      meta:
            description = "Generic - dangerous file with many dangerous php call"
            author = "Farhan Faisal"
            date = "2018/07/17"
            score = 40
      strings:
            $s0 = "base64_decode"
            $s1 = "file_put_contents"
            $s2 = "is_callable"
            $s3 = "$_SERVER"
            $s4 = "move_uploaded_file"
            $s5 = "eval"
            $s6 = "gzuncompress"
            $s7 = "ini_set"
            $s8 = "set_time_limit"
            $s9 = "error_reporting"
            $s10 = "memory_limit"
            $s11 = "stream_context_create"
            $s12 = "stream_socket_client"
            $s13 = "scandir"
            $s14 = "pathinfo"
            $s15 = "php_uname"
            $s16 = "is_readable"
            $s17 = "get_magic_quotes_gpc"
            $a1 = "SMTP"  			/* exclude phpmailer */
            $a2 = "CutyCapt"		/* exclude thumb.php */
            $a3 = "HighlightRules"		/* exclude textHighlighter */
            $a4 = "array_filter"		/* exclude wpide function list js file*/
            $a5 = "preview_theme_stylesheet_filter"
            $a6 = "phpconcept.net"
            $a7 = "IWP_MMB_Backup_Options"
      condition:
            (8 of ($s*)) and not ($a1 or $a2 or $a3 or ($a4 or $a5) or $a6 or $a7)
}



rule GENERIC_obfuscated_code_PROBABLE_scan {
      meta:
            description = "Generic - detection of obfuscated code (base64_decode)"
            author = "Farhan Faisal"
            date = "2018/07/17"
            score = 60
      strings:
            $s1 = /= \"[0-9a-zA-Z]{1000-600000}/
            $s2 = /=\"[0-9a-zA-Z]{1000-600000}/
            $s3 = /[0-9a-zA-Z]{1000-600000}/
            $aa1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111222"
            $aa2 = "effgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz11223344556677889900abacbcbdcdcededfefegfgfhghgihihjijikjkjlklkmlmlnmnmononpopoqpqprqrqsrsrtstsubcbcdcdedefefgfabcadefbghicjkl"
            $bb = /[0-9a-zA-Z]{80}/
            /* exclusion list by strings content */
            /*$cc1 = "image/png;base64"
            $cc2 = "application/font-woff"
            $cc3 = "data:application/x-font-woff"
            $cc4 = "image/gif"
            $cc5 = "image/svg+xml"
            $cc6 = "data:img/png"
            $cc7 = "data:image/jpeg;base64"
            $cc8 = "data:application/json" */
      condition:
            ($s1 or $s2 or $s3) or (#bb > 10 and #bb < 600)   /*and #bb < 600  */
            /*and not ( $cc1 or $cc2 or $cc3 or $cc4 or $cc5 or $cc6 or $cc7 or $cc8 )  */
            and
                ( magic.mime_type() != "application/vnd.ms-opentype" ) and
                ( magic.mime_type() != "application/octet-stream" ) and
                ( magic.mime_type() != "image/png" ) and
                ( magic.mime_type() != "image/jpeg" ) and
                ( magic.mime_type() != "application/pdf" ) and
                ( magic.mime_type() != "image/vnd.adobe.photoshop" )
            and not
                ($aa1 or $aa2)
            and
            (
                magic.mime_type() == "text/x-php" or
                magic.mime_type() == "text/x-c++"
            )
}

rule GENERIC_long_base64code {
      meta:
            description = "Webshell-GENERIC. Obfuscated/long base46 code."
            author = "Farhan Faisal"
            date = "2018/07/21"
            score = 60
      strings:
            $s1 = /= \"[0-9a-zA-Z]{10000-600000}/
            $s2 = /=\"[0-9a-zA-Z]{10000-600000}/
            $s3 = /[0-9a-zA-Z]{10000-600000}/
            $bb = /[0-9a-zA-Z]{80}/
            $xx1 = "image/svg+xml;base64"
            $xx2 = "image/png;base64"
      condition:
            ($s1 or $s2 or $s3) or (#bb > 600) and not (#bb < 599) and not (any of ($xx*))
            and
            (
                magic.mime_type() == "text/x-php" or
                magic.mime_type() == "text/x-c++"
            )
}

rule GENERIC_OBFUSCATION_TOO_BROAD_SCAN_possible_false_positive {
      meta:
            description = "mix obfuscated code and base64 encoding"
            author = "Farhan Faisal"
            date = "2020/01/24"
            score = 60
            hash = "27ae2a14b7d70badc45747ddc6162b20"
      strings:
            $a = /([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
      condition:
            $a
}



// ---------------------------------------------------------------------------------------------------

rule PATTERN_obfuscation_base64_webshell {
      meta:
            description = "Webshell-obfuscated 5. Use GLOBAL and sort. Need further analysis in /sample_heavily_obfuscated/generic/"
            author = "Farhan Faisal"
            date = "2021/06/26"
            score = 60
            hash = ""
      strings:
            $m1 = "<?php"
            $m4 = /[0-9a-zA-Z+]{200,}/    // slowing down

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



rule PATTERN_Obfuscation_substitution_____webshell {
      meta:
            description = "Generic webshell obfuscation technique, with some other visible function call"
            author = "Farhan Faisal"
            date = "2021/06/26"
            score = 60
            hash = ""
      strings:
            $s1 = /\[[0-9]{1,3}\]/      // slowing down
            $s2 = /\{[0-9]{1,3}\}/      // slowing down
            $s3 = /\([0-9]{1,3}\)/      // slowing down
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



rule PATTERN_Obfuscation_Webshell_3 {
      meta:
            description = "Webshell-obfuscated. Need further analysis /missed/baer.php"
            author = "Farhan Faisal"
            date = "2018/07/21"
            score = 60
            hash = "f2d7553b97d8e0a0258e48c3ca42a7d2"
      strings:
            $bb = /[0-9a-zA-Z]{80,}/    // slowing down
            $aa1 = "array"
            $aa2 = "();"
            $xx1 = "TextareaAutosize.prototype.componentDidMount"
            $xx2 = "ZoneScore.prototype.scoreOffsetAt"
            $xx3 = "wordpress_primitives"
            $xx4 = "window.wp.primitives"
      condition:
            (#bb > 40000) and (#aa1 > 3) and ($aa2) and not (any of ($xx*))
}

rule PATTERN_Obfuscation_small_PHPWebshell_brackets {
      meta:
            description = "asdsa"
            author = "Farhan Faisal"
            date = "2021/06/25"
            score = 60
            hash = "asdasd"
      strings:
            $s1 = /\[[0-9]{1,3}\]/       // slowing down
            $s2 = /\{[0-9]{1,3}\}/       // slowing down
            $s3 = /\([0-9]{1,3}\)/       // slowing down
            $s4 = "<?php"                // slowing down
            $s5 = /\$[a-zA-Z0-9]{5,20}/  // slowing down
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


rule PATTERN_Obfuscation_tiny_shell_PHP_2______2KB {
      meta:
            description = "Small file, obfuscated.  "
            author = "Farhan Faisal"
            date = "2021/06/26"
            score = 60
            hash = ""
      strings:
            $m1 = "<?php"

            $s1 = "eval"
            $s2 = /[0-9a-zA-Z]{200,}/        // slowing down
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


rule PATTERN_Exploiter_or_file_dumping_capable {
      meta:
        		description = "Generic PHP exploiter - dumping .zip file."
        		author = "Farhan Faisal"
        		date = "2021/06/24"
        		score = 70
        		hash = ""
      strings:
        		$b1 = /[0-9a-zA-Z]{100,}/        // slowing down
        		$b2 = "<?php"
        		$b3 = "base64_decode"
        		$b4 = "file_put_contents"
      condition:
      		  (4 of ($b*))
}

rule PATTERN_Uploader_smallPHP_upload_capable {
			meta:
  					description = "PATTERN - Uploader - simple"
  					author = "Farhan Faisal"
  					date = "2021/06/24"
  					score = 60
  					hash = "ddc8acea01f639a64f1c24399749c9d2"
			strings:
  					$s1 = "$_GET"
  					$s2 = "$_POST"
  					$s3 = "$_REQUEST"
  					$xx1 = "file_put_contents("
  					$xx2 = "unlink("
  					$xx3 = "readfile("
  					$xx4 = "basename("
  					$xx5 = "file_get_contents("
  					$xx6 = "fwrite("
  					$xx7 = "base64_decode("
			condition:
					 (filesize < 50KB) and (1 of ($s*)) and (3 of ($xx*))
}
