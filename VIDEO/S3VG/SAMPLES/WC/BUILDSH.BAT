wcc386 ..\showtext.c -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf
wcc386 ..\dosmain.c -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf
wcc386 ..\utils.c -i=..\ -i=..\..\h -w4 -e25 -zq -otexan -5r -bt=dos -mf
wlink SYS dos4g op q file showtext.obj,dosmain,utils.obj libr ..\..\lib\wc\s3dtkwrr.lib name showtext.exe

