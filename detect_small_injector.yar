import "magic"
/* this one have to be specific on file type. Too many false positive in CSS and JS file. Valid comments */


rule Small_Suspicious_comments_include {
			meta:
						description = "Small injected @include, in between short commented text. Sample : sample_small_injected/langkawiclimbing-index.php"
						author = "Farhan Faisal"
						date = "2020/01/24"
						score = 60
						hash = "33d0d234f35aadde3ae360e60e1ec9f9"
			strings:
						$ss1 = /\/\*([A-Za-z0-9]{1,8})\*\//
						$xx1 = "/*KB*/"
						$xx2 = "/*MB*/"
						$xx3 = "/*GB*/"
						$xx4 = "<![CDATA["
						$xx5 = "widget_price_filter"
						$xx6 = "GESHI_COMMENTS"
						$xx7 = "hasSurroundingWs"
						$xx8 = "XML_ELEMENT_NODE"
			condition:
						(#ss1 > 1) and not (any of ($xx*))
						and  (
								magic.mime_type() == "text/x-php" or
								magic.mime_type() == "text/x-c++"
						)
}
/*
	FP : app.quickprint/vendor/filp/whoops/src/Whoops/Run.php
*/


/*   rule Small_PHP_Unknown_include_1 {
			meta:
						description = "Small PHP - obfuscated include 1. Sample file in missed/index.2php and index3.php"
						author = "Farhan Faisal"
						date = "2018/07/21"
						score = 80
			strings:
						$s1 = "php"
						$s2 = "include"
						$xx1 = "\\"
			condition:
						filesize < 200 and (all of ($s*)) and (#xx1 > 10)
}  */
