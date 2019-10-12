// Copyright 2019 The GoRE.tk Authors. All rights reserved.
// Use of this source code is governed by the license that
// can be found in the LICENSE file.

package gore

import (
	"debug/gosym"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	resourceFolder = "testdata"
	fixedBuildID   = "DrtsigZmOidE-wfbFVNF/io-X8KB-ByimyyODdYUe/Z7tIlu8GbOwt0Jup-Hji/fofocVx5sk8UpaKMTx0a"
)

var dynResources = []struct {
	os   string
	arch string
}{
	{"linux", "386"},
	{"linux", "amd64"},
	{"windows", "386"},
	{"windows", "amd64"},
	{"darwin", "386"},
	{"darwin", "amd64"},
}

var dynResourceFiles *testFiles

type testFiles struct {
	files   map[string]string
	filesMu sync.RWMutex
}

func (f *testFiles) get(os, arch string) string {
	f.filesMu.Lock()
	defer f.filesMu.Unlock()
	return f.files[os+arch]
}

func TestMain(m *testing.M) {
	fmt.Println("Creating test resources, this can take some time...")
	tmpDirs := make([]string, len(dynResources), len(dynResources))
	fs := make(map[string]string)
	for i, r := range dynResources {
		fmt.Printf("Building resource file for %s_%s\n", r.os, r.arch)
		exe, dir := buildTestResource(testresourcesrc, r.os, r.arch)
		tmpDirs[i] = dir
		fs[r.os+r.arch] = exe
	}
	dynResourceFiles = &testFiles{files: fs}

	fmt.Println("Launching tests")
	code := m.Run()

	fmt.Println("Clean up test resources")
	for _, d := range tmpDirs {
		os.RemoveAll(d)
	}
	os.Exit(code)
}

func TestOpenAndCloseFile(t *testing.T) {
	for _, test := range dynResources {
		t.Run("open_"+test.os+"-"+test.arch, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			exe := dynResourceFiles.get(test.os, test.arch)

			f, err := Open(exe)
			assert.NoError(err)
			assert.NotNil(f)
			assert.NoError(f.Close())
		})
	}
}

func TestGetPackages(t *testing.T) {
	for _, test := range dynResources {
		t.Run("open_"+test.os+"-"+test.arch, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			require := require.New(t)
			exe := dynResourceFiles.get(test.os, test.arch)
			f, err := Open(exe)
			require.NoError(err)
			require.NotNil(f)
			defer f.Close()

			pkgs, err := f.GetPackages()
			assert.NoError(err)

			var mainpkg *Package
			for _, p := range pkgs {
				if p.Name == "main" {
					mainpkg = p
					break
				}
			}

			mp := false
			gd := false
			assert.NotNil(mainpkg, "Should include main package")
			for _, f := range mainpkg.Functions {
				if f.Name == "main" {
					mp = true
				} else if f.Name == "getData" {
					gd = true
				} else if f.Name == "init" {
					assert.Equal("<autogenerated>", f.Filename)
				} else {
					assert.Fail("Unexpected function")
				}
			}
			assert.True(mp, "No main function found")
			assert.True(gd, "getData function not found")
		})
	}
}

func TestGetCompilerVersion(t *testing.T) {
	expectedVersion := ResolveGoVersion(testCompilerVersion())
	for _, test := range dynResources {
		t.Run("parsing_"+test.os+"-"+test.arch, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			require := require.New(t)
			exe := dynResourceFiles.get(test.os, test.arch)
			f, err := Open(exe)
			require.NoError(err)
			require.NotNil(f)
			defer f.Close()

			// Test
			version, err := f.GetCompilerVersion()
			assert.NoError(err)
			assert.Equal(expectedVersion, version)
		})
	}
}

func TestGetBuildID(t *testing.T) {
	for _, test := range dynResources {
		t.Run("buildID_"+test.os+"-"+test.arch, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			require := require.New(t)
			exe := dynResourceFiles.get(test.os, test.arch)
			f, err := Open(exe)
			require.NoError(err)
			require.NotNil(f)
			defer f.Close()

			assert.Equal(fixedBuildID, f.BuildID, "BuildID extracted doesn't match expected value.")
		})
	}
}

func TestGoldFiles(t *testing.T) {
	goldFiles, err := getGoldenResources()
	if err != nil || len(goldFiles) == 0 {
		// Golden folder does not exist
		t.Skip("No golden files")
	}

	for _, file := range goldFiles {
		t.Run("compiler_version_"+file, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			require := require.New(t)
			// Loading resource
			resource, err := getGoldTestResourcePath(file)
			require.NoError(err)
			f, err := Open(resource)
			require.NoError(err)
			require.NotNil(f)

			// Get info from filename gold-os-arch-goversion
			fileInfo := strings.Split(file, "-")

			// If patch level is 0, it is dropped. For example. 10.0.0 is 10.0
			var actualVersion string
			verArr := strings.Split(fileInfo[3], ".")
			if len(verArr) == 3 && verArr[2] == "0" {
				actualVersion = strings.Join(verArr[:2], ".")
			} else {
				actualVersion = fileInfo[3]
			}

			// Tests
			// Not in 1.2 and 1.3
			if strings.HasPrefix(actualVersion, "1.2.") ||
				strings.HasPrefix(actualVersion, "1.3.") ||
				actualVersion == "1.2" || actualVersion == "1.3" {
				t.SkipNow()
			}
			version, err := f.GetCompilerVersion()
			assert.NoError(err)
			require.NotNil(version, "Version should not be nil")
			assert.Equal("go"+actualVersion, version.Name, "Incorrect version for "+file)

			// Clean up
			f.Close()
		})
	}
}

func TestSetGoVersion(t *testing.T) {
	assert := assert.New(t)

	t.Run("right error on wrong version string", func(t *testing.T) {
		t.Parallel()
		f := new(GoFile)
		f.FileInfo = new(FileInfo)

		err := f.SetGoVersion("invalid version string")

		assert.Error(err, "Should return an error when the version string is invalid")
		assert.Equal(ErrInvalidGoVersion, err, "Incorrect error value returned")
	})

	t.Run("should set correct version", func(t *testing.T) {
		t.Parallel()
		versionStr := "go1.12"
		expected := goversions[versionStr]
		f := new(GoFile)
		f.FileInfo = new(FileInfo)

		err := f.SetGoVersion(versionStr)

		assert.Nil(err, "Should not return an error when the version string is correct format")
		assert.Equal(expected, f.FileInfo.goversion, "Incorrect go version has be set")
	})
}

type mockFileHandler struct {
	mGetSectionDataFromOffset func(uint64) (uint64, []byte, error)
}

func (m *mockFileHandler) Close() error {
	panic("not implemented")
}

func (m *mockFileHandler) getPCLNTab() (*gosym.Table, error) {
	panic("not implemented")
}

func (m *mockFileHandler) getRData() ([]byte, error) {
	panic("not implemented")
}

func (m *mockFileHandler) getCodeSection() ([]byte, error) {
	panic("not implemented")
}

func (m *mockFileHandler) getSectionDataFromOffset(o uint64) (uint64, []byte, error) {
	return m.mGetSectionDataFromOffset(o)
}

func (m *mockFileHandler) getSectionData(string) (uint64, []byte, error) {
	panic("not implemented")
}

func (m *mockFileHandler) getFileInfo() *FileInfo {
	panic("not implemented")
}

func (m *mockFileHandler) getPCLNTABData() (uint64, []byte, error) {
	panic("not implemented")
}

func (m *mockFileHandler) moduledataSection() string {
	panic("not implemented")
}

func (m *mockFileHandler) getBuildID() (string, error) {
	panic("not implemented")
}

func TestBytes(t *testing.T) {
	assert := assert.New(t)
	expectedBase := uint64(0x40000)
	expectedSection := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}
	expectedBytes := []byte{0x2, 0x3, 0x4, 0x5}
	address := uint64(expectedBase + 2)
	length := uint64(len(expectedBytes))
	fh := &mockFileHandler{
		mGetSectionDataFromOffset: func(a uint64) (uint64, []byte, error) {
			if a > expectedBase+uint64(len(expectedSection)) || a < expectedBase {
				return 0, nil, errors.New("out of bound")
			}
			return expectedBase, expectedSection, nil
		},
	}
	f := &GoFile{fh: fh}

	data, err := f.Bytes(address, length)
	assert.NoError(err, "Should not return an error")
	assert.Equal(expectedBytes, data, "Return data not as expected")
}

func getTestResourcePath(resource string) (string, error) {
	return filepath.Abs(filepath.Join(resourceFolder, resource))
}

func getGoldTestResourcePath(resource string) (string, error) {
	return filepath.Abs(filepath.Join(resourceFolder, "gold", resource))
}

func getGoldenResources() ([]string, error) {
	folderPath, err := filepath.Abs(resourceFolder)
	if err != nil {
		return nil, err
	}
	folder, err := ioutil.ReadDir(filepath.Join(folderPath, "gold"))
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range folder {
		if f.IsDir() || !strings.HasPrefix(f.Name(), "gold-") {
			continue
		}
		files = append(files, f.Name())
	}
	return files, nil
}

func testCompilerVersion() string {
	goBin, err := exec.LookPath("go")
	if err != nil {
		panic("No go tool chain found: " + err.Error())
	}
	out, err := exec.Command(goBin, "version").CombinedOutput()
	if err != nil {
		panic("Getting compiler version failed: " + string(out))
	}
	return strings.Split(string(out), " ")[2]
}

func buildTestResource(body, goos, arch string) (string, string) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		panic("No go tool chain found: " + err.Error())
	}
	tmpdir, err := ioutil.TempDir("", "TestGORE")
	if err != nil {
		panic(err)
	}
	src := filepath.Join(tmpdir, "a.go")
	err = ioutil.WriteFile(src, []byte(body), 0644)
	if err != nil {
		panic(err)
	}
	exe := filepath.Join(tmpdir, "a")
	args := []string{"build", "-o", exe, "-ldflags", "-s -w -buildid=" + fixedBuildID, src}
	cmd := exec.Command(goBin, args...)
	gopatch := os.Getenv("GOPATH")
	if gopatch == "" {
		gopatch = tmpdir
	}
	cmd.Env = append(cmd.Env, "GOCACHE="+tmpdir, "GOARCH="+arch, "GOOS="+goos, "GOPATH="+gopatch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic("building test executable failed: " + string(out))
	}
	return exe, tmpdir
}

const testresourcesrc = `
package main

//go:noinline
func getData() string {
	return "Name: GoRE"
}

func main() {
	data := getData()
	data += " | Test"
}
`
