# Microsoft Developer Studio Generated NMAKE File, Format Version 4.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

!IF "$(CFG)" == ""
CFG=Showtext - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to Showtext - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Showtext - Win32 Release" && "$(CFG)" !=\
 "Showtext - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "Showtext.mak" CFG="Showtext - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Showtext - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Showtext - Win32 Debug" (based on "Win32 (x86) Application")
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
# PROP Target_Last_Scanned "Showtext - Win32 Debug"
MTL=mktyplib.exe
RSC=rc.exe
CPP=cl.exe

!IF  "$(CFG)" == "Showtext - Win32 Release"

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

ALL : "$(OUTDIR)\Showtext.exe"

CLEAN : 
	-@erase ".\WinRel\Showtext.exe"
	-@erase ".\WinRel\SHOWTEXT.OBJ"
	-@erase ".\WinRel\WINMAIN.OBJ"
	-@erase ".\WinRel\UTILS.OBJ"
	-@erase ".\WinRel\SHOWTEXT.res"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FR /YX /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\h" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\..\h" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /D "_MBCS" /Fp"$(INTDIR)/Showtext.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\WinRel/
CPP_SBRS=
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/SHOWTEXT.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/Showtext.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
LINK32_FLAGS=ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo\
 /subsystem:windows /incremental:no /pdb:"$(OUTDIR)/Showtext.pdb" /machine:I386\
 /out:"$(OUTDIR)/Showtext.exe" 
LINK32_OBJS= \
	".\WinRel\SHOWTEXT.OBJ" \
	".\WinRel\WINMAIN.OBJ" \
	".\WinRel\UTILS.OBJ" \
	".\WinRel\SHOWTEXT.res" \
	"..\..\Lib\Win95\Msvc\S3dtkw.lib"

"$(OUTDIR)\Showtext.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Showtext - Win32 Debug"

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

ALL : "$(OUTDIR)\Showtext.exe"

CLEAN : 
	-@erase ".\WinDebug\vc40.pdb"
	-@erase ".\WinDebug\vc40.idb"
	-@erase ".\WinDebug\Showtext.exe"
	-@erase ".\WinDebug\SHOWTEXT.OBJ"
	-@erase ".\WinDebug\WINMAIN.OBJ"
	-@erase ".\WinDebug\UTILS.OBJ"
	-@erase ".\WinDebug\SHOWTEXT.res"
	-@erase ".\WinDebug\Showtext.ilk"
	-@erase ".\WinDebug\Showtext.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "..\..\h" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /YX /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\..\h" /D "WIN32" /D "_DEBUG"\
 /D "_WINDOWS" /D "_MBCS" /Fp"$(INTDIR)/Showtext.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\WinDebug/
CPP_SBRS=
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/SHOWTEXT.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/Showtext.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386
LINK32_FLAGS=ddraw.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo\
 /subsystem:windows /incremental:yes /pdb:"$(OUTDIR)/Showtext.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)/Showtext.exe" 
LINK32_OBJS= \
	".\WinDebug\SHOWTEXT.OBJ" \
	".\WinDebug\WINMAIN.OBJ" \
	".\WinDebug\UTILS.OBJ" \
	".\WinDebug\SHOWTEXT.res" \
	"..\..\Lib\Win95\Msvc\S3dtkw.lib"

"$(OUTDIR)\Showtext.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "Showtext - Win32 Release"
# Name "Showtext - Win32 Debug"

!IF  "$(CFG)" == "Showtext - Win32 Release"

!ELSEIF  "$(CFG)" == "Showtext - Win32 Debug"

!ENDIF 

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

SOURCE=".\..\SHOWTEXT.C"
DEP_CPP_SHOWT=\
	".\..\UTILS.H"\
	".\..\S3TYPE.H"\
	".\..\..\h\ddraw.h"\
	".\..\..\h\S3DTK.H"\
	

"$(INTDIR)\SHOWTEXT.OBJ" : $(SOURCE) $(DEP_CPP_SHOWT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\SHOWTEXT.RC
DEP_RSC_SHOWTE=\
	".\SHOWTEXT.ICO"\
	

"$(INTDIR)\SHOWTEXT.res" : $(SOURCE) $(DEP_RSC_SHOWTE) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=".\..\..\Lib\Win95\Msvc\S3dtkw.lib"

!IF  "$(CFG)" == "Showtext - Win32 Release"

!ELSEIF  "$(CFG)" == "Showtext - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
