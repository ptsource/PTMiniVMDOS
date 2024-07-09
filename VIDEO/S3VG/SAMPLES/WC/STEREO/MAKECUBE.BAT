wcc386 example.c -zq -otexan -5r -bt=dos4g -mf -dCUBE -d2
wcc386 dosmain.c -zq -otexan -5r -bt=dos -mf -d2
wcc386 utils.c -zq -otexan -5r -bt=dos -mf -d2
wlink SYS dos4g debug all file example.obj,dosmain.obj,utils.obj libr s3dtkwrr.lib,svrdos3r.lib name cube.exe
