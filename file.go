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
	"sort"
	"sync"
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
