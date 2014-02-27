include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\msvcrt.inc
include \masm32\include\comdlg32.inc
includelib \masm32\lib\msvcrt.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\comdlg32.lib

extrn printf :near
extrn system :near

SIZEOF_NT_SIGNATURE equ sizeof DWORD
SIZEOF_IMAGE_FILE_HEADER equ 14h