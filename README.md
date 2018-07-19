# dylibify
Transform any ARM macho executable to a dynamic library

# How this works?
It's my really first time playing with Mach-O's like this so don't expect top quality code/explanation, but in a nutshell here's what it does:

- Patch mach header so it is identified as a dylib instead of an executable and add MH_NO_REEXPORTED_DYLIBS flag
- Get rid of PAGEZERO since with it we can't load the dylib
- Add a LC_ID_DYLIB command where PAGEZERO previously was to identify the dylib
- Patch opcodes: Since we got rid of PAGEZERO we have one less segment thus we need to patch whatever is referencing to SEGMENT X to SEGMENT X-1.
- Look into the code comments for more details
