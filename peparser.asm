.386
.model flat, stdcall
option casemap :none

include peparser.inc

.data
;OpenFileName
	openFileName OPENFILENAME <>
	filterString 				db "Executable Files (*.exe, *.dll)", 0, "*.exe;*.dll", 0
								db "All Files", 0, "*.*", 0
;Strings
	;Insert db "Insert an *.exe filename: ", 0
	ErrorMsg 					db		10, 13, "[-] Error while extracting PE information!", 0
	MappedOk 					db		10, 13, "[+] The file is mapped in memory!", 10, 13, 10, 13, 0
	DOSHeader 					db		"[!] DOS Header", 10, 13, 10, 13, 0
	PEHeader 					db		10, 13, 10, 13, "[!] PE Header", 10, 13, 10, 13, 0
	OptHeader 					db		10, 13, 10, 13, "[!] Optional Header", 10, 13, 10, 13, 0
	DataDir 					db		10, 13, 10, 13, "[!] Data Directories", 10, 13, 10, 13, 0
	Sections 					db		10, 13, 10, 13, "[!] Sections", 0
	Imports 					db 		10, 13, 10, 13, "[!] Imports", 0
	Exports 					db 		10, 13, 10, 13, 10, 13, "[!] Exports", 10, 13, 10, 13, 0
	Resources 					db 		10, 13, 10, 13, "[!] Resources", 10, 13, 10, 13, 0
	sectionless 				db 		10, 13, 9, "[-] Sectionless PE", 10, 13, 0
	no_exports 					db 		9, "[-] No exports table found", 0
	cmd 						db 		"pause > NUL", 0
	Format 						db 		"%x", 0
	Format1 					db 		"%s", 10, 13, 0
;DOS Header
	e_magic_str 				db		9, "e_magic: 0x", 0
	e_lfanew_str 				db		10, 13, 9, "e_lfanew: 0x", 0
;PE Header
	signature_str 				db		9, "signature: 0x", 0
	machine_str 				db		10, 13, 9, "machine: 0x", 0
	numberOfSections_str 		db		10, 13, 9, "numberOfSections: 0x", 0
	sizeOfOptionalHeader_str 	db		10, 13, 9, "sizeOfOptionalHeader: 0x", 0
	characteristics_str 		db		10, 13, 9, "characteristics: 0x", 0
;Optional Header
	magic_str 					db		9, "magic: ", 0
	addressOfEntryPoint_str 	db		10, 13, 9, "addressOfEntryPoint: 0x", 0
	imageBase_str 				db		10, 13, 9, "imageBase: 0x", 0
	sectionAlignment_str 		db		10, 13, 9, "sectionAlignment: 0x", 0
	fileAlignment_str 			db		10, 13, 9, "fileAlignment: 0x", 0
	majorSubsystemVersion_str 	db		10, 13, 9, "majorSubsystemVersion: 0x", 0
	sizeOfImage_str 			db		10, 13, 9, "sizeOfImage: 0x", 0
	sizeOfHeaders_str 			db		10, 13, 9, "sizeOfHeaders: 0x", 0
	subsystem_str 				db		10, 13, 9, "subsystem: 0x", 0
	numberOfRvaAndSizes_str 	db		10, 13, 9, "numberOfRvaAndSizes: 0x", 0
;Data Directories
	ex_dir_rva 					db 		9, "export directory RVA: 0x", 0
	ex_dir_size 				db 		10, 13, 9, "export directory size: 0x", 0
	imp_dir_rva 				db 		10, 13, 9, "import directory RVA: 0x", 0
	imp_dir_size 				db 		10, 13, 9, "import directory size: 0x", 0
	res_dir_rva 				db 		10, 13, 9, "resource directory RVA: 0x", 0
	res_dir_size 				db 		10, 13, 9, "resource directory size: 0x", 0
	exc_dir_rva 				db 		10, 13, 9, "exception directory RVA: 0x", 0
	exc_dir_size 				db 		10, 13, 9, "exception directory size: 0x", 0
	sec_dir_rva 				db 		10, 13, 9, "security directory RVA: 0x", 0
	sec_dir_size 				db 		10, 13, 9, "security directory size: 0x", 0
	rel_dir_rva 				db 		10, 13, 9, "relocation directory RVA: 0x", 0
	rel_dir_size 				db 		10, 13, 9, "relocation directory size: 0x", 0
	debug_dir_rva 				db 		10, 13, 9, "debug directory RVA: 0x", 0
	debug_dir_size 				db 		10, 13, 9, "debug directory size: 0x", 0
	arch_dir_rva 				db 		10, 13, 9, "architecture directory RVA: 0x", 0
	arch_dir_size 				db 		10, 13, 9, "architecture directory size: 0x", 0
	reserved_dir_rva 			db 		10, 13, 9, "reserved directory RVA: 0x", 0
	reserved_dir_size 			db 		10, 13, 9, "reserved directory size: 0x", 0
	TLS_dir_rva 				db 		10, 13, 9, "TLS directory RVA: 0x", 0
	TLS_dir_size 				db 		10, 13, 9, "TLS directory size: 0x", 0
	conf_dir_rva 				db 		10, 13, 9, "configuration directory RVA: 0x", 0
	conf_dir_size 				db 		10, 13, 9, "configuration directory size: 0x", 0
	bound_dir_rva 				db 		10, 13, 9, "bound import directory RVA: 0x", 0
	bound_dir_size 				db 		10, 13, 9, "bound import directory size: 0x", 0
	IAT_dir_rva 				db 		10, 13, 9, "IAT directory RVA: 0x", 0
	IAT_dir_size 				db 		10, 13, 9, "IAT directory size: 0x", 0
	delay_dir_rva 				db 		10, 13, 9, "delay directory RVA: 0x", 0
	delay_dir_size 				db		10, 13, 9, "delay directory size: 0x", 0
	NET_dir_rva 				db 		10, 13, 9, ".NET directory RVA: 0x", 0
	NET_dir_size 				db		10, 13, 9, ".NET directory size: 0x", 0
;Section Headers
	sec_name 					db		10, 13, 10, 13, 9, "name: ", 0
	virt_size 					db 		10, 13, 9, "virtual size: 0x", 0
	virt_address 				db 		10, 13, 9, "virtual address: 0x", 0
	raw_size 					db 		10, 13, 9, "raw size: 0x", 0
	raw_address 				db 		10, 13, 9, "raw address: 0x", 0
	reloc_address 				db 		10, 13, 9, "relocation address: 0x", 0
	linenumbers 				db 		10, 13, 9, "linenumbers: 0x", 0
	reloc_number 				db 		10, 13, 9, "relocations number: 0x", 0
	linenumbers_number 			db 		10, 13, 9, "linenumbers number: 0x", 0
	characteristics 			db 		10, 13, 9, "characteristics: 0x", 0
;Imports
	dll_name 					db 		10, 13, 10, 13, 9, "DLL name: ", 0
	functions_list 				db 		10, 13, 10, 13, 9, "Functions list: ", 10, 13, 0
	hint 						db 		10, 13, 9, 9, "Hint: 0x", 0
	function_name 				db 		9, "Name: ", 0
;Exports
	numberOfFunctions 			db 		10, 13, 9, "NumberOfFunctions: 0x", 0
	nName 						db 		9, "nName: ", 0
	nBase						db		10, 13, 9, "nBase: 0x", 0
	numberOfNames				db		10, 13, 9, "numberOfNames: 0x", 0
	exportedFunctions			db		10, 13, 9, "Function list:", 10, 13, 0
	RVA							db		10, 13, 9, "RVA: 0x", 0
	ordinal						db		9, "Ordinal: 0x", 0
	funcName					db		9, "Name: ", 0
;Resources
	resource_name 				db 		9, "resource name: ", 0
	
.data?
;DOS Header
	e_lfanew 					dd 		?
;Optional Header
	addr_opt_header 			dd 		?
;Handlers
	;hConsoleIn dd ?
	hConsoleOut 				dd 		?
	hFile 						dd 		?
	hMap 						dd 		?
	pMapping 					dd 		?
	bytesWritten 				dd 		?
	;fileName dd ?
	sections_count 				dd 		?
	sizeOfOptionalHeader 		dd 		?
	;numberOfRvaAndSizes dd ?
	buffer 						db 		512 dup (?)
;vars for Import Dumping
	sectionHeaderOffset 		dd 		?
	importsRVA 					dd 		?
;vars for Export Table
	exportsRVA 					dd 		?
	exportedNamesOffset			dd		?
	exportedFunctionsOffset		dd		?
	exportedOrdinalsOffset		dd		?
	numberOfNamesValue				dd		?
	nBaseValue					dd		?
	
.code
start:
	;GetOpenFileName
	mov openFileName.lStructSize, sizeof openFileName
	mov openFileName.lpstrFilter, offset filterString
	mov openFileName.lpstrFile, offset buffer
	mov openFileName.nMaxFile, 512
	mov openFileName.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_LONGNAMES or OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetOpenFileName, addr openFileName
	
	;Getting standard console I/O
	;invoke GetStdHandle, STD_INPUT_HANDLE
	;mov hConsoleIn, eax
	invoke GetStdHandle, STD_OUTPUT_HANDLE
	mov hConsoleOut, eax

	;Get console input filename (max 100 chars)
	;push offset Insert
	;call print
	;invoke ReadConsole, hConsoleIn, addr fileName, 64h, addr bytesWritten, 0
	;Input string always contains 0xD, 0xA (13, 10) = carriage return. Little trick to NULL terminate the input string.
	;mov eax, offset fileName
	;add eax, bytesWritten
	;sub eax, 2
	;mov byte ptr [eax], 0
	
	;Loading the file
	;CONSOLE LOAD: invoke CreateFile, addr fileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	invoke CreateFile, addr buffer, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	mov hFile, eax
	
	;Check if the file handle is valid
	cmp eax, INVALID_HANDLE_VALUE
	je errorExit
	
	invoke CreateFileMapping, hFile, 0, PAGE_READONLY, 0, 0, 0
	mov hMap, eax
	
	;Check if the map handle is valid
	cmp eax, INVALID_HANDLE_VALUE
	je errorExit
	
	invoke MapViewOfFile, hMap, FILE_MAP_READ, 0, 0, 0
	mov pMapping, eax
	
	;Check if the file is correctly mapped in memory
	cmp eax, 0
	je errorExit
	
	;File correctly mapped
	push offset MappedOk
	call print
	
	;DOS HEADER EXTRACTION
	mov edi, pMapping
	assume edi: ptr IMAGE_DOS_HEADER
	
	;Check if the file is a DOS file
	cmp [edi].e_magic, IMAGE_DOS_SIGNATURE
	jne errorExit
	
	;PRINT OUT DOS HEADER INFORMATION
	push offset DOSHeader
	call print
	push offset e_magic_str
	call print
	movzx edx, [edi].e_magic
	call print_f
	push offset e_lfanew_str
	call print
	mov edx, [edi].e_lfanew
	call print_f
	
	;Check if the file is a PE file
	add edi, edx ;address of the PE Header
	assume edi: ptr IMAGE_NT_HEADERS
	cmp [edi].Signature, IMAGE_NT_SIGNATURE
	jne errorExit
	
	;PRINT OUT PE HEADER INFORMATION
	push offset PEHeader
	call print
	push offset signature_str
	call print
	mov edx, [edi].Signature
	call print_f
	add edi, SIZEOF_NT_SIGNATURE
	assume edi: ptr IMAGE_FILE_HEADER
	push offset machine_str
	call print
	movzx edx, [edi].Machine
	call print_f
	push offset numberOfSections_str
	call print
	movzx edx, [edi].NumberOfSections
	push edx
	pop sections_count
	call print_f
	push offset sizeOfOptionalHeader_str
	call print
	movzx edx, [edi].SizeOfOptionalHeader
	push edx
	pop sizeOfOptionalHeader
	call print_f
	push offset characteristics_str
	call print
	movzx edx, [edi].Characteristics
	call print_f
	
	;PRINT OUT OPTIONAL HEADER INFORMATION
	add edi, SIZEOF_IMAGE_FILE_HEADER
	assume edi: ptr IMAGE_OPTIONAL_HEADER
	
	push offset OptHeader
	call print
	push offset magic_str
	call print
	movzx edx, [edi].Magic
	call print_f
	push offset addressOfEntryPoint_str
	call print
	mov edx, [edi].AddressOfEntryPoint
	call print_f
	push offset imageBase_str
	call print
	mov edx, [edi].ImageBase
	call print_f
	push offset sectionAlignment_str
	call print
	mov edx, [edi].SectionAlignment
	call print_f
	push offset fileAlignment_str
	call print
	mov edx, [edi].FileAlignment
	call print_f
	push offset majorSubsystemVersion_str
	call print
	movzx edx, [edi].MajorSubsystemVersion
	call print_f
	push offset sizeOfImage_str
	call print
	mov edx, [edi].SizeOfImage
	call print_f
	push offset sizeOfHeaders_str
	call print
	mov edx, [edi].SizeOfHeaders
	call print_f
	push offset subsystem_str
	call print
	movzx edx, [edi].Subsystem
	call print_f
	push offset numberOfRvaAndSizes_str
	call print
	mov edx, [edi].NumberOfRvaAndSizes
	call print_f
	
	;TO BE IMPLEMENTED CHECK OF THE IMAGE_DATA_DIRECTORY
	;Even so, in the case where the size of the OH is 0, it won't work well.  In that case I think you must trust the value in NumberOfRvaAndSizes, as long as it is less than 0x10.
	;I lost the one born under the Saturn's Symbol, I really miss you.
	mov edx, sizeOfOptionalHeader
	sub edx, IMAGE_OPTIONAL_HEADER.NumberOfRvaAndSizes + 4
	cmp edx, 0
	je sections_start
	
	;IMAGE DATA DIRECTORY
	add edi, 60h ;address of the Image Data Directory Start
	
	push offset DataDir
	call print
	push offset ex_dir_rva
	call print
	mov edx, dword ptr [edi]
	mov exportsRVA, edx
	call print_f
	push offset ex_dir_size
	call print
	mov edx, dword ptr [edi + 4h]
	call print_f
	push offset imp_dir_rva
	call print
	mov edx, dword ptr [edi + 8h]
	mov importsRVA, edx
	call print_f
	push offset imp_dir_size
	call print
	mov edx, dword ptr [edi + 0Ch]
	call print_f
	push offset res_dir_rva
	call print
	mov edx, dword ptr [edi + 10h]
	call print_f
	push offset res_dir_size
	call print
	mov edx, dword ptr [edi + 14h]
	call print_f
	push offset exc_dir_rva
	call print
	mov edx, dword ptr [edi + 18h]
	call print_f
	push offset exc_dir_size
	call print
	mov edx, dword ptr [edi + 1Ch]
	call print_f
	push offset sec_dir_rva
	call print
	mov edx, dword ptr [edi + 20h]
	call print_f
	push offset sec_dir_size
	call print
	mov edx, dword ptr [edi + 24h]
	call print_f
	push offset rel_dir_rva
	call print
	mov edx, dword ptr [edi + 28h]
	call print_f
	push offset rel_dir_size
	call print
	mov edx, dword ptr [edi + 2Ch]
	call print_f
	push offset debug_dir_rva
	call print
	mov edx, dword ptr [edi + 30h]
	call print_f
	push offset debug_dir_size
	call print
	mov edx, dword ptr [edi + 34h]
	call print_f
	push offset arch_dir_rva
	call print
	mov edx, dword ptr [edi + 38h]
	call print_f
	push offset arch_dir_size
	call print
	mov edx, dword ptr [edi + 3Ch]
	call print_f
	push offset reserved_dir_rva
	call print
	mov edx, dword ptr [edi + 40h]
	call print_f
	push offset reserved_dir_size
	call print
	mov edx, dword ptr [edi + 44h]
	call print_f
	push offset TLS_dir_rva
	call print
	mov edx, dword ptr [edi + 48h]
	call print_f
	push offset TLS_dir_size
	call print
	mov edx, dword ptr [edi + 4Ch]
	call print_f
	push offset conf_dir_rva
	call print
	mov edx, dword ptr [edi + 50h]
	call print_f
	push offset conf_dir_size
	call print
	mov edx, dword ptr [edi + 54h]
	call print_f
	push offset bound_dir_rva
	call print
	mov edx, dword ptr [edi + 58h]
	call print_f
	push offset bound_dir_size
	call print
	mov edx, dword ptr [edi + 5Ch]
	call print_f
	push offset IAT_dir_rva
	call print
	mov edx, dword ptr [edi + 60h]
	call print_f
	push offset IAT_dir_size
	call print
	mov edx, dword ptr [edi + 64h]
	call print_f
	push offset delay_dir_rva
	call print
	mov edx, dword ptr [edi + 68h]
	call print_f
	push offset delay_dir_size
	call print
	mov edx, dword ptr [edi + 6Ch]
	call print_f
	push offset NET_dir_rva
	call print
	mov edx, dword ptr [edi + 70h]
	call print_f
	push offset NET_dir_size
	call print
	mov edx, dword ptr [edi + 74h]
	call print_f
	
	;SECTIONS
	sub edi, 60h
	sections_start:
		add edi, sizeof IMAGE_OPTIONAL_HEADER
		assume edi: ptr IMAGE_SECTION_HEADER
		mov sectionHeaderOffset, edi
		
		push offset Sections
		call print
		
		mov ebx, sections_count
		cmp ebx, 0
		jne sections
		push offset sectionless
		call print
		
		sections:
			cmp ebx, 0
			je imports
			sub ebx, 1
			push offset sec_name
			call print
			push edi
			call print
			push offset virt_size
			call print
			mov edx, dword ptr [edi + 8h]
			call print_f
			push offset virt_address
			call print
			mov edx, [edi].VirtualAddress
			call print_f
			push offset raw_size
			call print
			mov edx, [edi].SizeOfRawData
			call print_f
			push offset raw_address
			call print
			mov edx, [edi].PointerToRawData
			call print_f
			push offset reloc_address
			call print
			mov edx, [edi].PointerToRelocations
			call print_f
			push offset linenumbers
			call print
			mov edx, [edi].PointerToLinenumbers
			call print_f
			push offset reloc_number
			call print
			movzx edx, [edi].NumberOfRelocations
			call print_f
			push offset linenumbers_number
			call print
			movzx edx, [edi].NumberOfLinenumbers
			call print_f
			push offset characteristics
			call print
			mov edx, [edi].Characteristics
			call print_f
			add edi, 28h
			jmp sections
	
	;Imports
	imports:
		push offset Imports
		call print
		mov edi, importsRVA
		call RVAtoOffset
		mov edi, eax
		add edi, pMapping
		assume edi:ptr IMAGE_IMPORT_DESCRIPTOR
		next_import_DLL:
			cmp [edi].OriginalFirstThunk, 0
			jne extract_import
			cmp [edi].TimeDateStamp, 0
			jne extract_import
			cmp [edi].ForwarderChain, 0
			jne extract_import
			cmp [edi].Name1, 0
			jne extract_import
			cmp [edi].FirstThunk, 0
			jne extract_import
			jmp exports ;no more imports to extract, go to exports
			
			extract_import:
				push edi
				mov edi, [edi].Name1
				call RVAtoOffset
				pop edi
				mov edx, eax
				add edx, pMapping
				push offset dll_name	;DLL Name
				call print
				push edx
				call print
				cmp [edi].OriginalFirstThunk, 0
				jne useOriginalFirstThunk
				mov esi, [edi].FirstThunk
				jmp useFirstThunk
				useOriginalFirstThunk:
					mov esi, [edi].OriginalFirstThunk
				useFirstThunk:
				push edi
				mov edi, esi
				call RVAtoOffset
				pop edi
				add eax, pMapping
				mov esi, eax
				
				push offset functions_list	;functions list
				call print
				extract_functions:
					cmp dword ptr [esi], 0
					je next_DLL
					test dword ptr [esi], IMAGE_ORDINAL_FLAG32
					jnz useOrdinal
					push edi
					mov edi, dword ptr [esi]
					call RVAtoOffset
					pop edi
					mov edx, eax
					add edx, pMapping
					assume edx:ptr IMAGE_IMPORT_BY_NAME
					mov cx, [edx].Hint ;point to the Hint
					movzx ecx, cx
					push offset hint
					call print
					push edx
					mov edx, ecx
					call print_f
					pop edx
					push offset function_name
					call print
					lea edx, [edx].Name1 ;point to the function Name
					push edx
					call print
					jmp next_import
					useOrdinal:
						mov edx, dword ptr [esi]
						and edx, 0FFFFh
						call print_f
					next_import:
						add esi, 4
						jmp extract_functions
					next_DLL:
						add edi, sizeof IMAGE_IMPORT_DESCRIPTOR
						jmp next_import_DLL

	;Exports
	exports:
		push offset Exports
		call print
		
		cmp exportsRVA, 0
		jne extract_exports
		push offset no_exports
		call print
		jmp resources
		
		extract_exports:
			mov edi, exportsRVA
			call RVAtoOffset
			mov edi, eax
			add edi, pMapping
			assume edi:ptr IMAGE_EXPORT_DIRECTORY
			;nName
			push edi
			mov edi, [edi].nName
			call RVAtoOffset
			add eax, pMapping
			pop edi
			push offset nName
			call print
			push eax
			call print
			;nBase
			push offset nBase
			call print
			mov edx, [edi].nBase
			mov nBaseValue, edx
			call print_f
			;numberOfFunctions
			push offset numberOfFunctions
			call print
			mov edx, [edi].NumberOfFunctions
			call print_f
			;NumberOfNames
			push offset numberOfNames
			call print
			mov edx, [edi].NumberOfNames
			mov numberOfNamesValue, edx
			call print_f
			;exported functions
			push offset exportedFunctions
			call print
			;check for ordinal exports
			mov edx, [edi].NumberOfFunctions
			cmp edx, [edi].NumberOfNames
			;je noOrdinalExports
			;ordinal exports
			push edi
			mov edi, [edi].AddressOfNameOrdinals
			call RVAtoOffset
			add eax, pMapping
			mov exportedOrdinalsOffset, eax
			pop edi
			noOrdinalExports:
				;AddressOfFunctions
				push edi
				mov edi, [edi].AddressOfFunctions
				call RVAtoOffset
				add eax, pMapping
				mov exportedFunctionsOffset, eax
				pop edi
				;AddressOfNames
				push edi
				mov edi, [edi].AddressOfNames
				call RVAtoOffset
				add eax, pMapping
				mov exportedNamesOffset, eax
				pop edi
				next_export:
					cmp numberOfNamesValue, 0
					jle resources
					mov eax, exportedOrdinalsOffset
					mov dx, [eax]
					movzx edx, dx 
					mov ecx, edx
					shl edx, 2
					add edx, exportedFunctionsOffset
					add ecx, nBaseValue
					;RVA
					push offset RVA
					call print
					mov edx, dword ptr [edx]
					call print_f
					;Ordinal
					push offset ordinal
					call print
					mov edx, ecx
					call print_f
					;name
					push offset funcName
					call print
					mov edx, dword ptr exportedNamesOffset
					mov edi, dword ptr [edx]
					call RVAtoOffset
					add eax, pMapping
					push eax
					call print
					;increment indexes
					dec numberOfNamesValue
					add exportedNamesOffset, 4 ;point to the next name in the array
					add exportedOrdinalsOffset, 2
					jmp next_export
			
	;Resources
	resources:
		push offset Resources
		call print
	
	;Closing handles, unmap the file and exit
	invoke UnmapViewOfFile, pMapping
	invoke CloseHandle, hFile
	invoke CloseHandle, hMap
	push offset cmd
	call system
	invoke ExitProcess, EXIT_SUCCESS
	
	errorExit:
		invoke CloseHandle, hFile
		invoke CloseHandle, hMap
		push offset ErrorMsg
		call print
		push offset cmd
		call system
		invoke ExitProcess, EXIT_FAILURE
		
	;Print routine: writes a string to the console
	;1) string to write
	print proc
		pushad
		mov ebx, dword ptr [esp + 36]
		invoke lstrlen, ebx
		invoke WriteConsole, hConsoleOut, ebx, eax, addr bytesWritten, 0
		popad
		ret 4
	print endp
	
	;print_num routine: write a number to the console
	;Before calling the procedure the value has to be moved in EDX
	;1) number to write
	;2) length of the number
	print_f proc
		pushad
		push edx
		push offset Format
		call printf
		add esp, 8
		popad
		ret
	print_f endp	
	
	;Converts an RVA to an Offset
	;The RVA is received into EDI, converted and the offset is put into EAX
	RVAtoOffset proc
		mov edx, sectionHeaderOffset
		assume edx:ptr IMAGE_SECTION_HEADER
		mov ecx, sections_count
		sections_cicle:
			cmp ecx, 0
			jle end_routine
				cmp edi, [edx].VirtualAddress
				jl next_section
					mov eax, [edx].VirtualAddress
					add eax, [edx].SizeOfRawData
					cmp edi, eax
					jge next_section
						mov eax, [edx].VirtualAddress
						sub edi, eax
						mov eax, [edx].PointerToRawData
						add eax, edi
						ret
			next_section:
				add edx, sizeof IMAGE_SECTION_HEADER
				dec ecx
		jmp sections_cicle
		end_routine:
			mov eax, edi
			ret
	RVAtoOffset endp
		
end start
