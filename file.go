// Copyright 2019 The GoRE.tk Authors. All rights reserved.
// Use of this source code is governed by the license that
// can be found in the LICENSE file.

package gore

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"golang.org/x/arch/x86/x86asm"
)

var (
	elfMagic       = []byte{0x7f, 0x45, 0x4c, 0x46}
	elfMagicOffset = 0
	peMagic        = []byte{0x4d, 0x5a}
	peMagicOffset  = 0
	maxMagicBufLen = 4
	machoMagic1    = []byte{0xfe, 0xed, 0xfa, 0xce}
	machoMagic2    = []byte{0xfe, 0xed, 0xfa, 0xcf}
	machoMagic3    = []byte{0xce, 0xfa, 0xed, 0xfe}
	machoMagic4    = []byte{0xcf, 0xfa, 0xed, 0xfe}
)

// Open opens a file and returns a handler to the file.
func Open(filePath string) (*GoFile, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, maxMagicBufLen)
	n, err := f.Read(buf)
	f.Close()
	if err != nil {
		return nil, err
	}
	if n < maxMagicBufLen {
		return nil, ErrNotEnoughBytesRead
	}
	gofile := new(GoFile)
	if fileMagicMatch(buf, elfMagic) {
		elf, err := openELF(filePath)
		if err != nil {
			return nil, err
		}
		gofile.fh = elf
	} else if fileMagicMatch(buf, peMagic) {
		pe, err := openPE(filePath)
		if err != nil {
			return nil, err
		}
		gofile.fh = pe
	} else if fileMagicMatch(buf, machoMagic1) || fileMagicMatch(buf, machoMagic2) || fileMagicMatch(buf, machoMagic3) || fileMagicMatch(buf, machoMagic4) {
		macho, err := openMachO(filePath)
		if err != nil {
			return nil, err
		}
		gofile.fh = macho
	} else {
		return nil, ErrUnsupportedFile
	}
	gofile.FileInfo = gofile.fh.getFileInfo()

	buildID, err := gofile.fh.getBuildID()
	gofile.BuildID = buildID

	return gofile, err
}

// GoFile is a structure representing a go binary file.
type GoFile struct {
	// FileInfo holds information about the file.
	FileInfo *FileInfo
	// BuildID is the Go build ID hash extracted from the binary.
	BuildID      string
	fh           fileHandler
	stdPkgs      []*Package
	pkgs         []*Package
	vendors      []*Package
	unknown      []*Package
	pclntab      *gosym.Table
	initPackages sync.Once
}

func (f *GoFile) init() error {
	var returnVal error
	f.initPackages.Do(func() {
		tab, err := f.PCLNTab()
		if err != nil {
			returnVal = err
			return
		}
		f.pclntab = tab
		returnVal = f.enumPackages()
	})
	return returnVal
}

// GetCompilerVersion returns the Go compiler version of the compiler
// that was used to compile the binary.
func (f *GoFile) GetCompilerVersion() (*GoVersion, error) {
	return findGoCompilerVersion(f)
}

// SetGoVersion sets the assumed compiler version that was used. This
// can be used to force a version if gore is not able to determine the
// compiler version used. The version string must match one of the strings
// normally extracted from the binary. For example to set the version to
// go 1.12.0, use "go1.12". For 1.7.2, use "go1.7.2".
// If an incorrect version string or version not known to the library,
// ErrInvalidGoVersion is returned.
func (f *GoFile) SetGoVersion(version string) error {
	gv := ResolveGoVersion(version)
	if gv == nil {
		return ErrInvalidGoVersion
	}
	f.FileInfo.goversion = gv
	return nil
}

// GetPackages returns the go packages in the binary.
func (f *GoFile) GetPackages() ([]*Package, error) {
	err := f.init()
	return f.pkgs, err
}

// GetVendors returns the vendor packages used by the binary.
func (f *GoFile) GetVendors() ([]*Package, error) {
	err := f.init()
	return f.vendors, err
}

// GetSTDLib returns the standard library packages used by the binary.
func (f *GoFile) GetSTDLib() ([]*Package, error) {
	err := f.init()
	return f.stdPkgs, err
}

// GetUnknown returns unclassified packages used by the binary.
func (f *GoFile) GetUnknown() ([]*Package, error) {
	err := f.init()
	return f.unknown, err
}

func findFuncEndLine(entry, end uint64, lineTable *gosym.LineTable) int {
	srcStart := lineTable.PCToLine(entry)
	srcStop := lineTable.PCToLine(end)
	// XXX: This hack should be rewritten.
	if (srcStop - srcStart) <= 0 {
		i := uint64(0)
		s := entry
		e := end
		for (srcStop - srcStart) <= 0 {
			srcStop = lineTable.PCToLine(e - i)
			if (e - i) <= s {
				return srcStop
			}
			i++
		}
	}
	return srcStop
}

func (f *GoFile) enumPackages() error {
	// TODO: Rewrite this function
	tab := f.pclntab
	pkgs := make(map[string]*Package)
	allpkgs := sort.StringSlice{}

	for _, n := range tab.Funcs {
		srcStop := findFuncEndLine(n.Entry, n.End, n.LineTable)
		srcStart := n.LineTable.PCToLine(n.Entry)
		name, _, _ := tab.PCToLine(n.Entry)
		p, ok := pkgs[n.PackageName()]
		if !ok {
			p = &Package{
				Filepath:  filepath.Dir(name),
				Functions: make([]*Function, 0),
				Methods:   make([]*Method, 0),
			}
			pkgs[n.PackageName()] = p
			allpkgs = append(allpkgs, n.PackageName())
		}
		if n.ReceiverName() != "" {
			p.Methods = append(p.Methods, &Method{
				Function: &Function{
					Name:          n.BaseName(),
					SrcLineLength: (srcStop - srcStart),
					SrcLineStart:  srcStart,
					SrcLineEnd:    srcStop,
					Offset:        n.Entry,
					End:           n.End,
					Filename:      filepath.Base(name),
					PackageName:   n.PackageName(),
				},
				Receiver: n.ReceiverName(),
			})
		} else {
			p.Functions = append(p.Functions, &Function{
				Name:          n.BaseName(),
				SrcLineLength: (srcStop - srcStart),
				Offset:        n.Entry,
				End:           n.End,
				SrcLineStart:  srcStart,
				SrcLineEnd:    srcStop,
				Filename:      filepath.Base(name),
				PackageName:   n.PackageName(),
			})
		}
	}
	allpkgs.Sort()

	classifier := NewPackageClassifier(pkgs["main"].Filepath)

	for n, p := range pkgs {
		p.Name = n
		class := classifier.Classify(p)
		switch class {
		case ClassSTD:
			f.stdPkgs = append(f.stdPkgs, p)
		case ClassVendor:
			f.vendors = append(f.vendors, p)
		case ClassMain:
			f.pkgs = append(f.pkgs, p)
		case ClassUnknown:
			f.unknown = append(f.unknown, p)
		}
	}
	return nil
}

// Close releases the file handler.
func (f *GoFile) Close() error {
	return f.fh.Close()
}

// PCLNTab returns the PCLN table.
func (f *GoFile) PCLNTab() (*gosym.Table, error) {
	return f.fh.getPCLNTab()
}

// GetTypes returns a map of all types found in the binary file.
func (f *GoFile) GetTypes() ([]*GoType, error) {
	if f.FileInfo.goversion == nil {
		ver, err := f.GetCompilerVersion()
		if err != nil {
			return nil, err
		}
		f.FileInfo.goversion = ver
	}
	t, err := getTypes(f.FileInfo, f.fh)
	if err != nil {
		return nil, err
	}
	if err = f.init(); err != nil {
		return nil, err
	}
	return sortTypes(t), nil
}

// Strings returns a list of all strings referenced in the go binary.
// This is a best-effort implementation that might not catch all strings.
func (f *GoFile) Strings() ([]string, error) {

	var strings []string

	compilerVersion, err := f.GetCompilerVersion()

	before18VersionRegexp := regexp.MustCompile(`go1(\.[0-7]([^0-9].+)?)?$`)
	before111VersionRegexp := regexp.MustCompile(`go1(\.([0-9]|10)([^0-9].+)?)?$`)
	var movUsedForLea bool
	var noRdataSection bool
	if err == nil && compilerVersion != nil {
		movUsedForLea = f.FileInfo.WordSize == 4 && before18VersionRegexp.MatchString(compilerVersion.Name)
		noRdataSection = f.FileInfo.OS == "windows" && before111VersionRegexp.MatchString(compilerVersion.Name)
	}

	codeOffset, code, _ := f.fh.getCodeSection()
	dataOffset, data, _ := f.fh.getRData()
	if noRdataSection { // On windows go1.10 or earlier, there is no .rdata section. Strings are part of .text.
		dataOffset, data = codeOffset, code
	}

	type Instruction struct {
		x86asm.Inst
		InMemoryAddress uint64
	}

	var instructions []Instruction
	currentIndex := 0
	for currentIndex < len(code) {
		inst, err := x86asm.Decode(code[currentIndex:], f.FileInfo.WordSize*8)
		if err == nil {
			instructions = append(instructions, Instruction{inst, uint64(currentIndex) + codeOffset})
			currentIndex += inst.Len
		} else { // Skip invalid instruction
			currentIndex += inst.Len
		}
	}

	to64BitEquivalent := func(reg x86asm.Reg) x86asm.Reg {
		switch reg {
		case x86asm.AL:
			return x86asm.RAX
		case x86asm.AX:
			return x86asm.RAX
		case x86asm.EAX:
			return x86asm.RAX
		case x86asm.BL:
			return x86asm.RBX
		case x86asm.BX:
			return x86asm.RBX
		case x86asm.EBX:
			return x86asm.RBX
		case x86asm.CL:
			return x86asm.RCX
		case x86asm.CX:
			return x86asm.RCX
		case x86asm.ECX:
			return x86asm.RCX
		case x86asm.DL:
			return x86asm.RDX
		case x86asm.DX:
			return x86asm.RDX
		case x86asm.EDX:
			return x86asm.RDX
		case x86asm.SPB:
			return x86asm.RSP
		case x86asm.SP:
			return x86asm.RSP
		case x86asm.ESP:
			return x86asm.RSP
		case x86asm.BPB:
			return x86asm.RBP
		case x86asm.BP:
			return x86asm.RBP
		case x86asm.EBP:
			return x86asm.RBP
		case x86asm.SIB:
			return x86asm.RSI
		case x86asm.SI:
			return x86asm.RSI
		case x86asm.ESI:
			return x86asm.RSI
		case x86asm.DIB:
			return x86asm.RDI
		case x86asm.DI:
			return x86asm.RDI
		case x86asm.EDI:
			return x86asm.RDI
		case x86asm.R8B:
			return x86asm.R8
		case x86asm.R8W:
			return x86asm.R8
		case x86asm.R8L:
			return x86asm.R8
		case x86asm.R9B:
			return x86asm.R9
		case x86asm.R9W:
			return x86asm.R9
		case x86asm.R9L:
			return x86asm.R9
		case x86asm.R10B:
			return x86asm.R10
		case x86asm.R10W:
			return x86asm.R10
		case x86asm.R10L:
			return x86asm.R10
		case x86asm.R11B:
			return x86asm.R11
		case x86asm.R11W:
			return x86asm.R11
		case x86asm.R11L:
			return x86asm.R11
		case x86asm.R12B:
			return x86asm.R12
		case x86asm.R12W:
			return x86asm.R12
		case x86asm.R12L:
			return x86asm.R12
		case x86asm.R13B:
			return x86asm.R13
		case x86asm.R13W:
			return x86asm.R13
		case x86asm.R13L:
			return x86asm.R13
		case x86asm.R14B:
			return x86asm.R14
		case x86asm.R14W:
			return x86asm.R14
		case x86asm.R14L:
			return x86asm.R14
		case x86asm.R15B:
			return x86asm.R15
		case x86asm.R15W:
			return x86asm.R15
		case x86asm.R15L:
			return x86asm.R15
		case x86asm.IP:
			return x86asm.RIP
		case x86asm.EIP:
			return x86asm.RIP
		}
		return reg
	}

	isStackMove := func(inst Instruction) (placedValue x86asm.Arg, isMove bool) {
		if inst.Op != x86asm.MOV {
			return nil, false
		}
		if mem, ok := inst.Args[0].(x86asm.Mem); !ok {
			return nil, false
			// Occasionally, the go runtime stores an RSP based offset in RAX
		} else if to64BitEquivalent(mem.Base) != x86asm.RSP && to64BitEquivalent(mem.Base) != x86asm.RAX {
			return nil, false
		} else {
			return inst.Args[1], true
		}
	}
	verifyAndStoreString := func(targetAddr uint64, stringLength uint64) bool {
		// Verify that string is in correct section
		if targetAddr > dataOffset && targetAddr+uint64(stringLength) < dataOffset+uint64(len(data)) {
			str := string(data[targetAddr-dataOffset : targetAddr-dataOffset+uint64(stringLength)])
			strings = append(strings, str)
			return true
		}
		return false
	}

	referToSame := func(reg1 x86asm.Reg, reg2 x86asm.Reg) bool {
		return to64BitEquivalent(reg1) == to64BitEquivalent(reg2)
	}

	for instIndex, inst := range instructions {
		var targetAddr uint64
		if inst.Op == x86asm.LEA {
			if f.FileInfo.WordSize == 8 { // 64 bit
				if mem, ok := inst.Args[1].(x86asm.Mem); ok && mem.Base == x86asm.RIP {
					targetAddr = uint64(int64(inst.InMemoryAddress) + mem.Disp + int64(inst.Len))
				} else {
					continue
				}
			} else if f.FileInfo.WordSize == 4 { // 32 bit
				if mem, ok := inst.Args[1].(x86asm.Mem); ok && mem.Base == 0 {
					targetAddr = uint64(mem.Disp)
				} else {
					continue
				}
			} else {
				continue
			}
		} else if inst.Op == x86asm.MOV && movUsedForLea {
			if imm, ok := inst.Args[1].(x86asm.Imm); ok {
				targetAddr = uint64(imm)
			} else {
				continue
			}
		} else {
			continue
		}
		addressStoredIn := inst.Args[0]
		// First possibility of string:
		// 1st instruction after LEA stores address on the stack
		// 2nd instruction after LEA stores length on the stack
		if instIndex+2 < len(instructions) {
			nextInstr := instructions[instIndex+1]
			twoNextInstr := instructions[instIndex+2]
			if placedValue, ok := isStackMove(nextInstr); ok && placedValue == addressStoredIn {
				if placedValue, ok := isStackMove(twoNextInstr); ok {
					if stringLength, ok := placedValue.(x86asm.Imm); ok {
						if verifyAndStoreString(targetAddr, uint64(stringLength)) {
							continue
						}
					}
				}
			}
		}
		// Second one, slightly more complex:
		// 1st instruction after LEA stores length in a register
		// 2nd instruction after LEA stores address on the stack
		// 3rd instruction after LEA stores length on the stack (from the register)
		if instIndex+3 < len(instructions) {
			nextInstr := instructions[instIndex+1]
			twoNextInstr := instructions[instIndex+2]
			threeNextInstr := instructions[instIndex+3]
			if placedValue, ok := isStackMove(twoNextInstr); ok && placedValue == addressStoredIn {
				if nextInstr.Op == x86asm.MOV {
					if stringLength, ok := nextInstr.Args[1].(x86asm.Imm); ok {
						if placedLength, ok := isStackMove(threeNextInstr); ok {
							lengthMovedTo, movedToOk := nextInstr.Args[0].(x86asm.Reg)
							placedLengthReg, placedFromOk := placedLength.(x86asm.Reg)
							if placedFromOk && movedToOk && referToSame(lengthMovedTo, placedLengthReg) {
								if verifyAndStoreString(targetAddr, uint64(stringLength)) {
									continue
								}
							}
						}
					}
				}
			}
		}
		// Third one, very similar to 2nd one, but with other ordering:
		// 1st instruction before LEA stores length in a register
		// 1st instruction after LEA stores length on the stack (from the register)
		// 2nd instruction after LEA stores address on the stack
		if instIndex+2 < len(instructions) && instIndex > 0 {
			previousInstr := instructions[instIndex-1]
			nextInstr := instructions[instIndex+1]
			twoNextInstr := instructions[instIndex+2]
			if placedValue, ok := isStackMove(twoNextInstr); ok && placedValue == addressStoredIn {
				if previousInstr.Op == x86asm.MOV {
					if stringLength, ok := previousInstr.Args[1].(x86asm.Imm); ok {
						if placedLength, ok := isStackMove(nextInstr); ok {
							lengthMovedTo, movedToOk := previousInstr.Args[0].(x86asm.Reg)
							placedLengthReg, placedFromOk := placedLength.(x86asm.Reg)
							if placedFromOk && movedToOk && referToSame(lengthMovedTo, placedLengthReg) {
								if verifyAndStoreString(targetAddr, uint64(stringLength)) {
									continue
								}
							}
						}
					}
				}
			}
		}
	}
	return strings, nil
}

// Bytes returns a slice of raw bytes with the length in the file from the address.
func (f *GoFile) Bytes(address uint64, length uint64) ([]byte, error) {
	base, section, err := f.fh.getSectionDataFromOffset(address)
	if err != nil {
		return nil, err
	}
	return section[address-base : address+length-base], nil
}

func sortTypes(types map[uint64]*GoType) []*GoType {
	sortedList := make([]*GoType, len(types), len(types))

	i := 0
	for _, typ := range types {
		sortedList[i] = typ
		i++
	}
	sort.Slice(sortedList, func(i, j int) bool {
		if sortedList[i].PackagePath == sortedList[j].PackagePath {
			return sortedList[i].Name < sortedList[j].Name
		}
		return sortedList[i].PackagePath < sortedList[j].PackagePath
	})
	return sortedList
}

type fileHandler interface {
	io.Closer
	getPCLNTab() (*gosym.Table, error)
	getRData() (uint64, []byte, error)
	getCodeSection() (uint64, []byte, error)
	getSectionDataFromOffset(uint64) (uint64, []byte, error)
	getSectionData(string) (uint64, []byte, error)
	getFileInfo() *FileInfo
	getPCLNTABData() (uint64, []byte, error)
	moduledataSection() string
	getBuildID() (string, error)
}

func fileMagicMatch(buf, magic []byte) bool {
	return bytes.HasPrefix(buf, magic)
}

// FileInfo holds information about the file.
type FileInfo struct {
	// OS is the operating system the binary is compiled for.
	OS string
	// ByteOrder is the byte order.
	ByteOrder binary.ByteOrder
	// WordSize is the natural integer size used by the file.
	WordSize  int
	goversion *GoVersion
}
