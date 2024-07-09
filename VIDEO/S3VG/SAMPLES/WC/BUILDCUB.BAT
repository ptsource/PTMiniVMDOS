wcc386 ..\example.c -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf -dCUBE
wcc386 ..\dosmain.c -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf
wcc386 ..\utils.c   -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf
wlink SYS dos4g op q file example.obj,dosmain.obj,utils.obj libr ..\..\lib\wc\s3dtkwrr.lib name cube.exe
