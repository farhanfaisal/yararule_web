# yararule_web

This is my own rule for detecting web attacks, planted on web servers. My environment goes around 
PHP, cPanel, therefore, the detection focus on files related to this environment. 

It did detect
- js redirect
- a few webshell
- small uploader
- a few php mailer
- generic small obfuscated code


## Download the rule

``` git clone https://github.com/farhanfaisal/yararule_web.git```

## Usage 

```yara -r -w ./index.yar <path to scan> ```

## Broad scan (not precise, just to list down interesting obfucated code)

```yara -r -w ./detect_generic_maliciousness_BROAD_SCAN.yar <path>