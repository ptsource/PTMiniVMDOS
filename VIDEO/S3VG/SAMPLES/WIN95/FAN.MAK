# Microsoft Developer Studio Generated NMAKE File, Format Version 4.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

!IF "$(CFG)" == ""
CFG=Fan - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Fan - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Fan - Win32 Release" && "$(CFG)" != "Fan - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "Fan.mak" CFG="Fan - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Fan - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Fan - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "Fan - Win32 Debug"
MTL=mktyplib.exe
RSC=rc.exe
CPP=cl.exe

!IF  "$(CFG)" == "Fan - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "WinRel"
# PROP BASE Intermediate_Dir "WinRel"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "WinRel"
# PROP Intermediate_Dir "WinRel"
OUTDIR=.\WinRel
INTDIR=.\WinRel

ALL : "$(OUTDIR)\Fan.exe"

CLEAN : 
	-@erase ".\WinRel\Fan.exe"
	-@erase ".\WinRel\EXAMPLE.OBJ"
	-@erase ".\WinRel\WINMAIN.OBJ"
	-@erase ".\WinRel\UTILS.OBJ"
	-@erase ".\WinRel\WINEX.res"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FR /YX /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\h" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "FAN" /YX /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\..\h" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "FAN" /Fp"$(INTDIR)/Fan.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\WinRel/
CPP_SBRS=
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/WINEX.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/Fan.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
LINK32_FLAGS=ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo\
 /subsystem:windows /incremental:no /pdb:"$(OUTDIR)/Fan.pdb" /machine:I386\
 /out:"$(OUTDIR)/Fan.exe" 
LINK32_OBJS= \
	".\WinRel\EXAMPLE.OBJ" \
	".\WinRel\WINMAIN.OBJ" \
	".\WinRel\UTILS.OBJ" \
	".\WinRel\WINEX.res" \
	"..\..\Lib\Win95\Msvc\S3dtkw.lib"

"$(OUTDIR)\Fan.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Fan - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "WinDebug"
# PROP BASE Intermediate_Dir "WinDebug"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "WinDebug"
# PROP Intermediate_Dir "WinDebug"
OUTDIR=.\WinDebug
INTDIR=.\WinDebug

ALL : "$(OUTDIR)\Fan.exe"

CLEAN : 
	-@erase ".\WinDebug\vc40.pdb"
	-@erase ".\WinDebug\vc40.idb"
	-@erase ".\WinDebug\Fan.exe"
	-@erase ".\WinDebug\WINMAIN.OBJ"
	-@erase ".\WinDebug\EXAMPLE.OBJ"
	-@erase ".\WinDebug\UTILS.OBJ"
	-@erase ".\WinDebug\WINEX.res"
	-@erase ".\WinDebug\Fan.ilk"
	-@erase ".\WinDebug\Fan.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "..\..\h" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "FAN" /YX /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\..\h" /D "_DEBUG" /D "WIN32"\
 /D "_WINDOWS" /D "FAN" /Fp"$(INTDIR)/Fan.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\WinDebug/
CPP_SBRS=
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/WINEX.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/Fan.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386
LINK32_FLAGS=ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo\
 /subsystem:windows /incremental:yes /pdb:"$(OUTDIR)/Fan.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)/Fan.exe" 
LINK32_OBJS= \
	".\WinDebug\WINMAIN.OBJ" \
	".\WinDebug\EXAMPLE.OBJ" \
	".\WinDebug\UTILS.OBJ" \
	".\WinDebug\WINEX.res" \
	"..\..\Lib\Win95\Msvc\S3dtkw.lib"

"$(OUTDIR)\Fan.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "Fan - Win32 Release"
# Name "Fan - Win32 Debug"

!IF  "$(CFG)" == "Fan - Win32 Release"

!ELSEIF  "$(CFG)" == "Fan - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\WINEX.RC
DEP_RSC_WINEX=\
	".\ICON1.ICO"\
	

"$(INTDIR)\WINEX.res" : $(SOURCE) $(DEP_RSC_WINEX) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=".\..\EXAMPLE.C"
DEP_CPP_EXAMP=\
	".\..\UTILS.H"\
	".\..\S3TYPE.H"\
	".\..\..\h\ddraw.h"\
	".\..\..\h\S3DTK.H"\
	

"$(INTDIR)\EXAMPLE.OBJ" : $(SOURCE) $(DEP_CPP_EXAMP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=".\..\UTILS.C"
DEP_CPP_UTILS=\
	".\..\UTILS.H"\
	".\..\S3TYPE.H"\
	".\..\..\h\ddraw.h"\
	".\..\..\h\S3DTK.H"\
	

"$(INTDIR)\UTILS.OBJ" : $(SOURCE) $(DEP_CPP_UTILS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=".\..\WINMAIN.C"
DEP_CPP_WINMA=\
	".\..\UTILS.H"\
	".\..\S3TYPE.H"\
	".\..\..\h\ddraw.h"\
	".\..\..\h\S3DTK.H"\
	

"$(INTDIR)\WINMAIN.OBJ" : $(SOURCE) $(DEP_CPP_WINMA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=".\..\..\Lib\Win95\Msvc\S3dtkw.lib"

!IF  "$(CFG)" == "Fan - Win32 Release"

!ELSEIF  "$(CFG)" == "Fan - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
