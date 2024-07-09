@echo off
nmake /f cube.mak CFG="Cube - Win32 Release"
cd WinRel
del *.obj
del *.pch
del *.res
del *.pdb
del *.ilk
cd ..
nmake /f fan.mak CFG="Fan - Win32 Release"
cd WinRel
del *.obj
del *.pch
del *.res
del *.pdb
del *.ilk
cd ..
nmake /f showtext.mak CFG="Showtext - Win32 Release"
cd WinRel
del *.obj
del *.pch
del *.res
del *.pdb
del *.ilk
cd ..
nmake /f stretch.mak CFG="Stretch - Win32 Release"
cd WinRel
del *.obj
del *.pch
del *.res
del *.pdb
del *.ilk
cd ..
nmake /f strip.mak CFG="Strip - Win32 Release"
cd WinRel
del *.obj
del *.pch
del *.res
del *.pdb
del *.ilk
cd ..
