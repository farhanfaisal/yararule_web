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

General scan
```yara -r -w ./index.yar <path to scan> ```

Broad scan (more false positive. looking for generic obfuscated code)
```yara -r -w ./index.broad.yar <path to scan> ```

## Notes

Some detections are important, such as shellcode detction, but most of them are string search. So, there will be a lot of false positive. However, the rule will be name with "GENERIC". 

Those files need further investigation. 

## Broad scan (not precise, just to list down interesting obfucated code)

```yara -r -w ./detect_generic_maliciousness_BROAD_SCAN.yar <path>```
