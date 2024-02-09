@ECHO OFF

if not exist "build" (
    mkdir "build"
)

:: cl.exe /EHsc /nologo /Od /MT /W0 /GS- /DNDEBUG source.cpp /link /MACHINE:x86 /SUBSYSTEM:CONSOLE /OUT:.\build\code_injector.exe

cl.exe /EHsc /nologo /Od /MT  /GS- /DNDEBUG source.cpp /link /MACHINE:x64 /SUBSYSTEM:CONSOLE /OUT:.\build\code_injector.exe

del source.obj
