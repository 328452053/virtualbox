#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# $Id: configure.py 111857 2025-11-24 17:08:24Z andreas.loeffler@oracle.com $
# pylint: disable=line-too-long
# pylint: disable=too-many-lines
# pylint: disable=unnecessary-semicolon
# pylint: disable=invalid-name
__copyright__ = \
"""
Copyright (C) 2025 Oracle and/or its affiliates.

This file is part of VirtualBox base platform packages, as
available from https://www.virtualbox.org.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, in version 3 of the
License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <https://www.gnu.org/licenses>.

The contents of this file may alternatively be used under the terms
of the Common Development and Distribution License Version 1.0
(CDDL), a copy of it is provided in the "COPYING.CDDL" file included
in the VirtualBox distribution, in which case the provisions of the
CDDL are applicable instead of those of the GPL.

You may elect to license modified versions of this file under the
terms and conditions of either the GPL or the CDDL or both.

SPDX-License-Identifier: GPL-3.0-only OR CDDL-1.0
"""

import argparse
import datetime
import glob
import io
import os
import platform
import shutil
import subprocess
import sys
import tempfile

class Log(io.TextIOBase):
    """
    Duplicates output to multiple file-like objects (used for logging and stdout).
    """
    def __init__(self, *files):
        self.asFiles = files;
    def write(self, data):
        """
        Write data to all files.
        """
        for f in self.asFiles:
            f.write(data);
    def flush(self):
        """
        Flushes all files.
        """
        for f in self.asFiles:
            if not f.closed:
                f.flush();

class Ansi:
    """
    ANSI escape codes for colored terminal output.
    """
    RESET = '\033[0m';
    BOLD = '\033[1m';
    BLUE = '\033[94m';
    GREEN = '\033[92m';
    RED = '\033[91m';
    YELLOW = '\033[93m';
    WHITE = '\033[97m';
    GRAY = '\033[90m';

class BuildTargets:
    """
    Supported build targets enumeration.
    This resembles the kBuild targets.
    """
    ANY = "Any";
    LINUX = "Linux";
    WINDOWS = "Windows";
    DARWIN = "Darwin";
    SOLARIS = "Solaris";
    BSD = "BSD";
    HAIKU = "Haiku";

g_cVerbosity = 0;
g_cErrors = 0;
g_cWarnings = 0;

# Defines the host target.
g_sHostOS = platform.system();
# Map host OS to build target.
g_enmHostTarget = {
    "Linux": BuildTargets.LINUX,
    "Windows": BuildTargets.WINDOWS,
    "Darwin": BuildTargets.DARWIN,
    "SunOS": BuildTargets.SOLARIS,
    "FreeBSD": BuildTargets.BSD,
    "OpenBSD": BuildTargets.BSD,
    "NetBSD": BuildTargets.BSD,
    "Haiku": BuildTargets.HAIKU
}.get(g_sHostOS, BuildTargets.ANY);
# By default we build for the host system.
g_enmBuildTarget = g_enmHostTarget;

def printError(sMessage):
    """
    Prints an error message to stderr in red.
    """
    print(f"{Ansi.RED}*** Error: {sMessage}{Ansi.RESET}", file=sys.stderr);

def printStatus(sStatus):
    """
    Returns a colored string indicating library/tool status.
    """
    if sStatus == "yes":
        return f"{Ansi.GREEN}{sStatus}{Ansi.RESET}";
    elif sStatus == "no":
        return f"{Ansi.RED}{sStatus}{Ansi.RESET}";
    elif sStatus == "DISABLED":
        return f"{Ansi.YELLOW}{sStatus}{Ansi.RESET}";
    elif sStatus == "-":
        return f"{Ansi.GRAY}{sStatus}{Ansi.RESET}";
    return sStatus;

def printName(sName):
    """
    Returns library/tool name as colored string.
    """
    return f"{Ansi.BLUE}{sName}{Ansi.RESET}";

def printHeader(sHeader):
    """
    Returns table header colored and bolded.
    """
    return f"{Ansi.BOLD}{Ansi.WHITE}{sHeader}{Ansi.RESET}";

def printTableHeader():
    """
    Prints the table header for library/tool status.
    """
    print("{:<30} {:<18} {:<18} {}".format(
        printHeader("Library/Tool"),
        printHeader("Status"),
        printHeader("Version"),
        printHeader("Include path / Command")
    ));

def printLibRow(oLib):
    """
    Prints a formatted row for a given library.
    """
    sIncOrDash = oLib.sIncPath if oLib.fHave else "-";
    print("{:<30} {:<18} {}".format(
        printName(oLib.sName),
        printStatus(oLib.getStatusString()),
        sIncOrDash
    ));

def printToolRow(oTool, sStatus):
    """
    Prints a formatted row for a given tool.
    """
    print("{:<30} {:<18} {}".format(
        printName(oTool.sName),
        printStatus(sStatus),
        oTool.sCmdPath if getattr(oTool, 'sCmdPath', None) else "-"
    ));

def printSummaryBlock(sTitle, aPairs, iWidth1=30, iWidth2=18):
    """
    Prints a colored summary block (aligned columns).
    """
    print("\n" + printHeader(sTitle));
    for sName, sStatus in aPairs:
        print(f"{printName(sName):<{iWidth1}} {printStatus(sStatus):<{iWidth2}}");

def printPathsBlock(sTitle, asPaths, iWiidth=30):
    """
    Prints include/library path summary.
    """
    if not asPaths:
        return;
    print(printHeader(sTitle));
    for sName, sPath in asPaths:
        print(f"{printName(sName):<{iWiidth}} {sPath}");

class LibraryCheck:
    """
    Constructor.
    """
    def __init__(self, sName, asIncFiles, asLibFiles, aeTargets, sCode, aeTargetsExcluded = None, asAltIncFiles = None):
        self.sName = sName
        self.asIncFiles = asIncFiles or [];
        self.asLibFiles = asLibFiles or [];
        self.sCode = sCode;
        self.aeTargets = aeTargets;
        self.aeTargetsExcluded = aeTargetsExcluded if aeTargetsExcluded else [];
        self.asAltIncFiles = asAltIncFiles or [];
        self.fDisabled = False;
        self.sCustomPath = None;
        self.sIncPath = None;
        self.sLibPath = None;
        # Is a tri-state: None if not required (optional or not needed), False if not found, True if found.
        self.fHave = None;
        # Contains the (parsable) version string if detected.
        # Only valid if self.fHave is True.
        self.sVer = None;

    def hasCPPHeader(self):
        """
        Rough guess which headers require C++.
        """
        asCPPHdr = ["c++", "iostream", "Qt", "qt", "qglobal.h", "qcoreapplication.h"];
        return any(h for h in ([self.asIncFiles] + self.asAltIncFiles) if h and any(c in h for c in asCPPHdr));

    def getLinkerArgs(self):
        """
        Returns the linker arguments for the library as a string.
        """
        if not self.asLibFiles:
            return "";
        # Remove 'lib' prefix if present for -l on UNIX-y OSes.
        asLibArgs = [];
        for sLibCur in self.asLibFiles:
            if g_enmBuildTarget != BuildTargets.WINDOWS:
                if sLibCur.startswith("lib"):
                    sLibCur = sLibCur[3:];
                else:
                    sLibCur = ':' + sLibCur;
                asLibArgs.append(f"-l{sLibCur}");
        return asLibArgs;

    def getTestCode(self):
        """
        Return minimal program *with version print* for header check, per-library logic.
        """
        header = self.asIncFiles or (self.asAltIncFiles[0] if self.asAltIncFiles else None);
        if not header:
            return "";
        sLibName = self.sName.lower();

        if sLibName == "libstdc++":
            return '#include <iostream>\nint main() { std::cout << "Found: " << __cplusplus << std::endl; return 0; }\n'

        if self.sCode:
            return '#include <stdio.h>\n' + self.sCode if 'stdio.h' not in self.sCode else self.sCode;
        if self.hasCPPHeader():
            return f"#include <{header}>\n#include <iostream>\nint main() {{ std::cout << \"1\" << std::endl; return 0; }}\n"
        else:
            return f'#include <{header}>\n#include <stdio.h>\nint main(void) {{ printf("1"); return 0; }}\n'

    def compileAndExecute(self):
        """
        Attempts to compile and execute test code using the discovered paths and headers.
        """
        if not (self.sIncPath and self.sLibPath and self.asLibFiles):
            return;
        sCompiler = "g++" if self.hasCPPHeader() else "gcc";
        with tempfile.TemporaryDirectory() as tmpd:
            sFilePath = os.path.join(tmpd, "testlib.cpp" if sCompiler == "g++" else "testlib.c");
            sBinPath  = os.path.join(tmpd, "a.out" if platform.system() != "Windows" else "a.exe");

            with open(sFilePath, "w", encoding = 'utf-8') as fh:
                fh.write(self.getTestCode());
            fh.close();

            sIncFlags    = f"-I{self.sIncPath}";
            sLibFlags    = f"-L{self.sLibPath}";
            sLinkerFlags = self.getLinkerArgs();
            asCmd        = [sCompiler, sFilePath, sIncFlags, sLibFlags, "-o", sBinPath] + sLinkerFlags;

            try:
                # Try compiling the test source file.
                oProc = subprocess.run(asCmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, check = True, timeout = 15)
                if oProc.returncode != 0:
                    sCompilerStdErr = oProc.stderr.decode("utf-8", errors="ignore");
                    printError(sCompilerStdErr);
                else:
                    # Try executing the compiled binary and capture stdout + stderr.
                    try:
                        oProc = subprocess.run([sBinPath], stdout = subprocess.PIPE, stderr = subprocess.PIPE, check=True, timeout = 10);
                        if oProc.returncode == 0:
                            self.sVer = oProc.stdout.decode('utf-8', 'replace').strip();
                        else:
                            printError(f"Execution of test binary for {self.sName} failed with return code {oProc.returncode}:");
                            printError(oProc.stderr.decode("utf-8", errors="ignore"));
                    except subprocess.SubprocessError as ex:
                        printError(f"Execution of test binary for {self.sName} failed: {str(ex)}");
                    finally:
                        try:
                        #    os.remove(sBinPath);
                            pass;
                        except OSError as ex:
                            printError(f"Failed to remove temporary binary file {sBinPath}: {str(ex)}");
            except subprocess.SubprocessError as e:
                printError(str(e));

    def setArgs(self, args):
        """
        Applies argparse options for disabling and custom paths.
        """
        sArgKey = self.sName.replace("-", "_");
        self.fDisabled = getattr(args, f"disable_{sArgKey}", False);
        self.sCustomPath = getattr(args, f"with_{sArgKey}_path", None);

    def getLinuxGnuTypeFromPlatform(self):
        """
        Returns the Linux GNU type based on the platform.
        """
        mapPlatform2GnuType = {
            "x86_64": "x86_64-linux-gnu",
            "amd64": "x86_64-linux-gnu",
            "i386": "i386-linux-gnu",
            "i686": "i386-linux-gnu",
            "aarch64": "aarch64-linux-gnu",
            "arm64": "aarch64-linux-gnu",
            "armv7l": "arm-linux-gnueabihf",
            "armv6l": "arm-linux-gnueabi",
            "ppc64le": "powerpc64le-linux-gnu",
            "s390x": "s390x-linux-gnu",
            "riscv64": "riscv64-linux-gnu",
        };
        return mapPlatform2GnuType.get(platform.machine().lower());

    def getIncSearchPaths(self):
        """
        Returns a list of existing search directories for includes.
        """
        asPaths = [];
        if self.sCustomPath:
            asPaths = [os.path.join(self.sCustomPath, "include")];
        elif g_enmBuildTarget == BuildTargets.WINDOWS:
            root_drives = [d+":" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(d+":")];
            for r in root_drives:
                asPaths += [os.path.join(r, p) for p in [
                    "\\msys64\\mingw64\\include", "\\msys64\\mingw32\\include", "\\include"]];
                asPaths += [r"c:\\Program Files", r"c:\\Program Files (x86)"];
        else: # Linux / MacOS / Solaris
            sGnuType = self.getLinuxGnuTypeFromPlatform();
            # Sorted by most likely-ness.
            asPaths = [ "/usr/include", "/usr/local/include",
                        "/usr/include/" + sGnuType, "/usr/local/include/" + sGnuType,
                        "/usr/include/" + self.sName, "/usr/local/include/" + self.sName,
                        "/opt/include", "/opt/local/include"];
            if g_enmBuildTarget == BuildTargets.DARWIN:
                asPaths.append("/opt/homebrew/include");
        return [p for p in asPaths if os.path.exists(p)];

    def getLibSearchPaths(self):
        """
        Returns a list of existing search directories for libraries.
        """
        asPaths = [];
        if self.sCustomPath:
            asPaths = [os.path.join(self.sCustomPath, "lib")];
        elif g_enmBuildTarget == BuildTargets.WINDOWS:
            root_drives = [d+":" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(d+":")];
            for r in root_drives:
                asPaths += [os.path.join(r, p) for p in [
                    "\\msys64\\mingw64\\lib", "\\msys64\\mingw32\\lib", "\\lib"]];
                asPaths += [r"c:\\Program Files", r"c:\\Program Files (x86)"];
        else:
            if g_enmBuildTarget == BuildTargets.LINUX \
            or g_enmBuildTarget == BuildTargets.SOLARIS:
                sGnuType = self.getLinuxGnuTypeFromPlatform();
                # Sorted by most likely-ness.
                asPaths = [ "/usr/lib", "/usr/local/lib",
                            "/usr/lib/" + sGnuType, "/opt/local/lib/" + sGnuType,
                            "/usr/lib64", "/lib", "/lib64",
                            "/opt/lib", "/opt/local/lib" ];
            else: # Darwin
                asPaths.append("/opt/homebrew/lib");
        return [p for p in asPaths if os.path.exists(p)];

    def checkInc(self):
        """
        Checks for headers in standard/custom include paths.
        """
        if not self.asIncFiles and not self.asAltIncFiles:
            return True;
        asHeaderToSearch = [];
        if self.asIncFiles:
            asHeaderToSearch.extend(self.asIncFiles);
        asHeaderToSearch.extend(self.asAltIncFiles);
        asSearchPaths = self.getIncSearchPaths();
        for sCurSearchPath in asSearchPaths:
            for sCurHeader in asHeaderToSearch:
                sCur = os.path.join(sCurSearchPath, sCurHeader);
                if os.path.isfile(sCur):
                    self.sIncPath = sCurSearchPath;
                    return True;
                if os.sep == "\\":
                    sCur = os.path.join(sCurSearchPath, sCurHeader.replace("/", "\\"));
                    if os.path.isfile(sCur):
                        self.sIncPath = sCurSearchPath;
                        return True;
        return False;

    def checkLib(self):
        """
        Checks for libraries in standard/custom lib paths.
        """
        if not self.asLibFiles:
            return True;
        sBasename = self.asLibFiles;
        asLibExts = [];
        if g_enmBuildTarget == BuildTargets.WINDOWS:
            asLibExts = [".lib", ".dll", ".a", ".dll.a"];
        elif g_enmBuildTarget == BuildTargets.DARWIN:
            asLibExts = [".a", ".dylib", ".so"];
        else:
            asLibExts = [".a", ".so"];
        asSearchPaths = self.getLibSearchPaths();
        if g_cVerbosity:
            print(asSearchPaths);
        for sCurSearchPath in asSearchPaths:
            for sCurExt in asLibExts:
                sPattern = os.path.join(sCurSearchPath, f"{sBasename}*{sCurExt}");
                for sCurFile in glob.glob(sPattern):
                    if os.path.isfile(sCurFile):
                        self.sLibPath = sCurSearchPath;
                        return True;
        return False;

    def performCheck(self):
        """
        Run library detection.
        """
        if g_enmBuildTarget in self.aeTargetsExcluded:
            self.fHave = None;
            return;
        if self.fDisabled:
            self.fHave = None;
            return;
        if g_enmBuildTarget in self.aeTargets:
            self.fHave = self.checkInc() and self.checkLib();

    def getStatusString(self):
        """
        Return string indicator: yes, no, DISABLED, or - (not checked / disabled / whatever).
        """
        if self.fDisabled:
            return "DISABLED";
        elif self.fHave:
            return "yes";
        elif self.fHave is None:
            return "-";
        else:
            return "no";

    def __repr__(self):
        return f"{self.sName}: {self.getStatusString()}";

class ToolCheck:
    """
    Describes and checks for a build tool.
    """
    def __init__(self, sName, asCmds, aeTargets=''):
        """
        Constructor.
        """
        assert sName, asCmds;

        self.sName = sName;
        self.asCmds = asCmds if isinstance(asCmds, list) else [ asCmds ];
        self.aeTargets = aeTargets if isinstance(aeTargets, list) else [ aeTargets ];
        self.fDisabled = False;
        # Whether the tool is available.
        self.fHave = False;
        # Path to the found command.
        # Only valid if self.fHave is True.
        self.sCmdPath = None;

    def setArgs(self, oArgs):
        """
        Apply argparse options for disabling the tool.
        """
        sArgKey = self.sName.replace("+", "PLUS").replace("-", "_");
        self.fDisabled = getattr(oArgs, f"disable_{sArgKey}", False);

    def performCheck(self):
        """
        Performs the actual check of the tool.
        """
        if self.aeTargets:
            if (isinstance(self.aeTargets, list) and g_enmBuildTarget not in self.aeTargets) or (g_enmBuildTarget != self.aeTargets):
                self.fHave = None;
                return;
        if self.fDisabled:
            self.fHave = None;
            return;
        for sCmdCur in self.asCmds:
            sPath = shutil.which(sCmdCur);
            if sPath:
                self.fHave = True;
                self.sCmdPath = sPath;
                return;

    def getStatusString(self):
        """
        Returns a string for the tool's status: "yes", "no", "DISABLED", or "-".
        """
        if self.fDisabled:
            return "DISABLED";
        if self.fHave:
            return f"yes ({os.path.basename(self.sCmdPath)})";
        if self.fHave is None:
            return "-";
        return "no";

    def __repr__(self):
        return f"{self.sName}: {self.getStatusString()}"

def check_java():
    """
    Checks for Java via 'java -version'.
    """
    try:
        out = subprocess.check_output([ "java", "-version" ], stderr = subprocess.STDOUT).decode("utf8").lower();
        if "java" in out:
            return "yes (java)";
        ## @todo Check for minimum Java version?
    except FileNotFoundError:
        pass;
    except subprocess.SubprocessError:
        pass;
    return "no";

def check_xcode():
    """
    Checks for Xcode tools on macOS.
    """
    if g_enmBuildTarget != BuildTargets.DARWIN:
        return "-";
    try:
        out = subprocess.check_output([ "xcodebuild", "-version" ], stderr = subprocess.STDOUT ).decode("utf8").lower();
        if "xcode" in out:
            return "yes (xcodebuild)";
    except FileNotFoundError:
        pass;
    except subprocess.SubprocessError:
        pass;
    return "no";

def show_syntax_help():
    """
    Prints syntax help.
    """
    print("Supported libraries (with configure options):\n");

    for oLibCur in g_aoLibs:
        sDisable = f"--disable-{oLibCur.name}";
        sWith    = f"--with-{oLibCur.name}-path=<path>";
        onlytxt    = " (non-Windows only)" if oLibCur.only_unix else "";
        if oLibCur.asTargets:
            onlytxt += f" (only on {oLibCur.asTargets})";
        if oLibCur.exclude_os:
            onlytxt += f" (not on {','.join(oLibCur.exclude_os)})";
        print(f"    {sDisable:<30}{sWith:<40}{onlytxt}");

    print("\nSupported tools (with configure options):\n");

    for oToolCur in g_aoTools:
        sDisable = f"--disable-{oToolCur.sName.replace('+','plus').replace('-','_')}";
        onlytxt    = f" (only on {oToolCur.aeTargets})" if oToolCur.aeTargets else "";
        print(f"    {sDisable:<30}{onlytxt}");
    print("""
    --help                         Show this help message and exit

Examples:
    ./configure.py --disable-libvpx
    ./configure.py --with-libpng-path=/usr/local
    ./configure.py --disable-yasm --disable-openwatcom
    ./configure.py --disable-libstdc++
    ./configure.py --disable-qt6

Hint: Combine any supported --disable-<lib|tool> and --with-<lib>-path=PATH options.
""");

g_aoLibs = sorted([
    ## @todo
    #LibraryCheck("berkeley-softfloat-3", [ "softfloat.h" ], [ "libsoftfloat" ],
    #             '#include <softfloat.h>\nint main() { float32_t x, y; f32_add(x, y); printf("1"); return 0; }\n'),
    LibraryCheck("dmtx", [ "dmtx.h" ], [ "libdmtx" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                '#include <dmtx.h>\nint main() { dmtxEncodeCreate(); printf("%s", dmtxVersion()); return 0; }\n'),
    ## @todo
    #LibraryCheck("dxvk", [ "dxvk/dxvk.h" ], [ "libdxvk" ],
    #             '#include <dxvk/dxvk.h>\nint main() { printf("1\\n"); return 0; }\n'),
    LibraryCheck("libalsa", [ "alsa/asoundlib.h" ], [ "libasound" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <alsa/asoundlib.h>\n#include <alsa/version.h>\nint main() { snd_pcm_info_sizeof(); printf("%s", SND_LIB_VERSION_STR); return 0; }\n'),
    LibraryCheck("libcap", [ "sys/capability.h" ], [ "libcap" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <sys/capability.h>\nint main() { cap_t c = cap_init(); printf("1"); return 0; }\n'),
    LibraryCheck("libcursor", [ "X11/cursorfont.h" ], [ "libXcursor" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xcursor/Xcursor.h>\nint main() { printf("%d.%d", XCURSOR_LIB_MAJOR, XCURSOR_LIB_MINOR); return 0; }\n'),
    LibraryCheck("libcurl", [ "curl/curl.h" ], [ "libcurl" ], [ BuildTargets.ANY ],
                 '#include <curl/curl.h>\nint main() { printf("%s", LIBCURL_VERSION); return 0; }\n'),
    LibraryCheck("libdevmapper", [ "libdevmapper.h" ], [ "libdevmapper" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <libdevmapper.h>\nint main() { char v[64]; dm_get_library_version(v, sizeof(v)); printf("%s", v); return 0; }\n'),
    LibraryCheck("libjpeg-turbo", [ "turbojpeg.h" ], [ "libturbojpeg" ], [ BuildTargets.ANY ],
                 '#include <turbojpeg.h>\nint main() { tjInitCompress(); printf("0.0"); return 0; }\n'),
    LibraryCheck("liblzf", [ "lzf.h" ], [ "liblzf" ], [ BuildTargets.ANY ],
                 '#include <liblzf/lzf.h>\nint main() { printf("%d.%d", LZF_VERSION >> 8, LZF_VERSION & 0xff);\n#if LZF_VERSION >= 0x0105\nreturn 0;\n#else\nreturn 1;\n#endif\n }\n'),
    LibraryCheck("liblzma", [ "lzma.h" ], [ "liblzma" ], [ BuildTargets.ANY ],
                 '#include <lzma.h>\nint main() { printf("%s", lzma_version_string()); return 0; }\n'),
    LibraryCheck("libogg", [ "ogg/ogg.h" ], [ "libogg" ], [ BuildTargets.ANY ],
                 '#include <ogg/ogg.h>\nint main() { oggpack_buffer o; oggpack_get_buffer(&o); printf("found"); return 0; }\n'),
    LibraryCheck("libpam", [ "security/pam_appl.h" ], [ "libpam" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <security/pam_appl.h>\nint main() { \n#ifdef __LINUX_PAM__\nprintf("%d.%d", __LINUX_PAM__, __LINUX_PAM_MINOR__); if (__LINUX_PAM__ >= 1) return 0;\n#endif\nreturn 1; }\n'),
    LibraryCheck("libpng", [ "png.h" ], [ "libpng" ], [ BuildTargets.ANY ],
                 '#include <png.h>\nint main() { printf("%s", PNG_LIBPNG_VER_STRING); return 0; }\n'),
    LibraryCheck("libpthread", [ "pthread.h" ], [ "libpthread" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <unistd.h>\n#include <pthread.h>\nint main() { \n#ifdef _POSIX_VERSION\nprintf("%d", (long)_POSIX_VERSION); return 0;\n#else\nreturn 1;\n#endif\n }\n'),
    LibraryCheck("libpulse", [ "pulse/pulseaudio.h", "pulse/version.h" ], [ "libpulse" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <pulse/version.h>\nint main() { printf("%s", pa_get_library_version()); return 0; }\n'),
    LibraryCheck("libslirp", [ "slirp/libslirp.h", "slirp/libslirp-version.h" ], [ "libslirp" ], [ BuildTargets.ANY ],
                 '#include <slirp/libslirp.h>\n#include <slirp/libslirp-version.h>\nint main() { printf("%d.%d.%d", SLIRP_MAJOR_VERSION, SLIRP_MINOR_VERSION, SLIRP_MICRO_VERSION); return 0; }\n'),
    LibraryCheck("libssh", [ "libssh/libssh.h" ], [ "libssh" ], [ BuildTargets.ANY ],
                 '#include <libssh/libssh.h>\n#include <libssh/libssh_version.h>\nint main() { printf("%d.%d.%d", LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO); return 0; }\n'),
    ## @todo
    #  LibraryCheck("libstdc++", "c++/v1/iostream", "stdc++", [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ], asAltIncFiles = [ "c++/4.8.2/iostream", "c++/iostream" ]),
    LibraryCheck("libtpms", [ "libtpms/tpm_library.h" ], [ "libtpms" ], [ BuildTargets.ANY ],
                 '#include <libtpms/tpm_library.h>\nint main() { printf("%d.%d.%d", TPM_LIBRARY_VER_MAJOR, TPM_LIBRARY_VER_MINOR, TPM_LIBRARY_VER_MICRO); return 0; }\n'),
    LibraryCheck("libvncserver", [ "rfb/rfb.h", "rfb/rfbclient.h" ], [ "libvncserver" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <rfb/rfb.h>\nint main() { printf("%s", LIBVNCSERVER_PACKAGE_VERSION); return 0; }\n'),
    LibraryCheck("libvorbis", [ "vorbis/vorbisenc.h" ], [ "libvorbis", "libvorbisenc" ], [ BuildTargets.ANY ],
                 '#include <vorbis/vorbisenc.h>\nint main() { vorbis_info v; vorbis_info_init(&v); int vorbis_rc = vorbis_encode_init_vbr(&v, 2 /* channels */, 44100 /* hz */, (float).4 /* quality */); return 0; }\n'),
    LibraryCheck("libvpx", [ "vpx/vpx_decoder.h" ], [ "libvpx" ], [ BuildTargets.ANY ],
                 '#include <vpx/vpx_codec.h>\nint main() { printf("%s", vpx_codec_version_str()); return 0; }\n'),
    LibraryCheck("libxml2", [ "libxml/parser.h" ] , [ "libxml2" ], [ BuildTargets.ANY ],
                 '#include <libxml/xmlversion.h>\nint main() { printf("%s", LIBXML_DOTTED_VERSION); return 0; }\n'),
    LibraryCheck("zlib1g", [ "zlib.h" ], [ "libz" ], [ BuildTargets.ANY ],
                 '#include <zlib.h>\nint main() { printf("%s", ZLIB_VERSION); return 0; }\n'),
    LibraryCheck("lwip", [ "lwip/init.h" ], [ "lwip" ], [ BuildTargets.ANY ],
                 '#include <lwip/init.h>\nint main() { printf("%d.%d.%d", LWIP_VERSION_MAJOR, LWIP_VERSION_MINOR, LWIP_VERSION_REVISION); return 0; }\n'),
    LibraryCheck("opengl", [ "GL/gl.h" ], [ "libGL" ], [ BuildTargets.ANY ],
                 '#include <GL/gl.h>\n#include <stdio.h>\nint main() { const GLubyte *s = glGetString(GL_VERSION); printf("%s", s ? (const char *)s : "<not found>"); return 0; }\n'),
    ## @todo
    # LibraryCheck(
    #    "qt6",
    #    "QtCore/qglobal.h",
    #    "Qt6Core",
    #    asAltIncFiless = [
    #        "qt6/QtCore/qglobal.h", "qt/QtCore/qglobal.h",
    #        "QtCore/qcoreapplication.h", "qt6/QtCore/qcoreapplication.h"
    #    ]
    #),
    LibraryCheck("sdl2", [ "SDL2/SDL.h" ], [ "libSDL2" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <SDL2/SDL.h>\nint main() { printf("%d.%d.%d", SDL_MAJOR_VERSION, SDL_MINOR_VERSION, SDL_PATCHLEVEL); return 0; }\n',
                 asAltIncFiles = [ "SDL.h" ]),
    LibraryCheck("sdl2_ttf", [ "SDL2/SDL_ttf.h" ], [ "libSDL2_ttf" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <SDL2/SDL_ttf.h>\nint main() { printf("%d.%d.%d", SDL_TTF_MAJOR_VERSION, SDL_TTF_MINOR_VERSION, SDL_TTF_PATCHLEVEL); return 0; }\n',
                 asAltIncFiles = [ "SDL_ttf.h" ]),
    LibraryCheck("x11", [ "X11/Xlib.h" ], [ "libX11" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xlib.h>\nint main() { XOpenDisplay(NULL); printf("1"); return 0; }\n'),
    LibraryCheck("xext", [ "X11/extensions/Xext.h" ], [ "libXext" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xlib.h>\n#include <X11/extensions/Xext.h>\nint main() { XSetExtensionErrorHandler(NULL); printf("1"); return 0; }\n'),
    LibraryCheck("xmu", [ "X11/Xmu/Xmu.h" ], [ "libXmu" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xmu/Xmu.h>\nint main() { XmuMakeAtom("test"); printf("1"); return 0; }\n', aeTargetsExcluded=[ BuildTargets.DARWIN ]),
    LibraryCheck("xrandr", [ "X11/extensions/Xrandr.h" ], [ "libXrandr", "libX11" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xlib.h>\n#include <X11/extensions/Xrandr.h>\nint main() { Display *dpy = XOpenDisplay(NULL); Window root = RootWindow(dpy, 0); XRRScreenConfiguration *c = XRRGetScreenInfo(dpy, root); printf("1"); return 0; }\n'),
    LibraryCheck("libxinerama", [ "X11/extensions/Xinerama.h" ], [ "libXinerama", "libX11" ], [ BuildTargets.LINUX, BuildTargets.SOLARIS, BuildTargets.BSD ],
                 '#include <X11/Xlib.h>\n#include <X11/extensions/Xinerama.h>\nint main() { Display *dpy = XOpenDisplay(NULL); XineramaIsActive(dpy); printf("1"); return 0; }\n')
], key=lambda l: l.sName);

g_aoTools = sorted([
    ToolCheck("gSOAP", ["soapcpp2", "wsdl2h"]),
    ToolCheck("Java", "java"),
    ToolCheck("kBuild", ["kmk"]),
    ToolCheck("makeself", "makeself"),
    ToolCheck("openwatcom", ["wcl", "wcl386", "wlink"]),
    ToolCheck("xcode", "xcodebuild", aeTargets="Darwin"),
    ToolCheck("yasm", "yasm"),
], key=lambda t: t.sName.lower())

def write_autoconfig_kmk(aoLibs, aoTools):
    """
    Writes the AutoConfig.kmk file with SDK paths and enable/disable flags.
    Each library/tool gets VBOX_WITH_<NAME>, SDK_<NAME>_LIBS, SDK_<NAME>_INCS.
    """

    sScript = os.path.basename(__file__);

    with open("AutoConfig.kmk", "w", encoding = "utf-8") as fh:
        fh.write("""
# -*- Makefile -*-
#
# Generated by """ + sScript + """.
#
# DO NOT EDIT THIS FILE MANUALLY
# It will be completely overwritten if """ + sScript + """ is executed again.
#
# Generated on """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """
#
                \n""");

        for oLibCur in aoLibs:
            sVarBase = oLibCur.sName.upper().replace("+", "PLUS").replace("-", "_");
            fEnabled = 1 if oLibCur.fHave else 0;
            fh.write(f"VBOX_WITH_{sVarBase}={fEnabled}\n");
            if oLibCur.fHave and (oLibCur.sLibPath or oLibCur.sIncPath):
                if oLibCur.sLibPath:
                    fh.write(f"SDK_{sVarBase}_LIBS={oLibCur.sLibPath}\n");
                if oLibCur.sIncPath:
                    fh.write(f"SDK_{sVarBase}_INCS={oLibCur.sIncPath}\n");

def main():
    """
    Main entry point.
    """
    oParser = argparse.ArgumentParser(add_help=False);
    oParser.add_argument('--help', action='store_true');
    oParser.add_argument('-v', '--verbose', action='store_true', help="Enables verbose output");
    for oLibCur in g_aoLibs:
        oParser.add_argument(f'--disable-{oLibCur.sName}', action='store_true');
        oParser.add_argument(f'--with-{oLibCur.sName}-path');
        oParser.add_argument(f'--only-{oLibCur.sName}', action='store_true');
    for oToolCur in g_aoTools:
        oParser.add_argument(f'--disable-{oToolCur.sName.replace("+","plus").replace("-","_")}', action='store_true');
        oParser.add_argument(f'--only-{oToolCur.sName.replace("+","plus").replace("-","_")}', action='store_true');
    args = oParser.parse_args();

    g_cVerbosity = 1; # args.verbose

    aoOnlyLibs = [lib for lib in g_aoLibs if getattr(args, f'only_{lib.sName}', False)];
    aoOnlyTools = [tool for tool in g_aoTools if getattr(args, f'only_{tool.sName.replace("+","plus").replace("-","_")}', False)];
    aoLibsToCheck = aoOnlyLibs if aoOnlyLibs else g_aoLibs;
    aoToolsToCheck = aoOnlyTools if aoOnlyTools else g_aoTools;

    if args.help:
        show_syntax_help();
        return 2;

    logf = open("configure.log", "w", encoding="utf-8");
    sys.stdout = Log(sys.stdout, logf);
    sys.stderr = Log(sys.stderr, logf);

    print(f'VirtualBox configuration script');
    print(f'Running on {platform.system()} {platform.release()} ({platform.machine()})');
    print(f'Detected target: {g_sHostOS}');

    print();
    printTableHeader();

    for oLibCur in aoLibsToCheck:
        oLibCur.setArgs(args);
        oLibCur.performCheck();
        if oLibCur.fHave:
            oLibCur.compileAndExecute();
        printLibRow(oLibCur);

    print();

    for oToolCur in aoToolsToCheck:
        oToolCur.setArgs(args);
        if oToolCur.sName == "Java":
            if oToolCur.fDisabled:
                sStatus = "DISABLED";
            else:
                sStatus = check_java().split()[0]
            oToolCur.sCmdPath = shutil.which("java") if sStatus == "yes" else None;
        elif oToolCur.sName == "xcode":
            if oToolCur.fDisabled:
                sStatus = "DISABLED";
            else:
                sStatus = check_xcode().split()[0];
            oToolCur.sCmdPath = shutil.which("xcodebuild") if sStatus == "yes" else None;
        else:
            oToolCur.performCheck();
            sStatus = oToolCur.getStatusString().split()[0];
        printToolRow(oToolCur, sStatus);

    sSummaryLibs = [(lib.sName, lib.getStatusString()) for lib in aoLibsToCheck];
    sSummaryTools = [(tool.sName, tool.getStatusString()) for tool in aoToolsToCheck];
    printSummaryBlock("Summary (Libraries):", sSummaryLibs);
    printSummaryBlock("Summary (Tools):", sSummaryTools);

    asPathsInc = [(lib.sName, lib.sIncPath) for lib in aoLibsToCheck if lib.sIncPath];
    asPathsLibs = [(lib.sName, lib.sLibPath) for lib in aoLibsToCheck if lib.sLibPath];

    print();
    printPathsBlock("Include paths found:", asPathsInc);
    printPathsBlock("Library paths found:", asPathsLibs);
    print();

    print(printHeader("Build tools:"));
    aOsTools = {
        BuildTargets.LINUX:   ['gcc', 'make', 'pkg-config'],
        BuildTargets.DARWIN:  ['clang', 'make', 'brew'],
        BuildTargets.WINDOWS: ['cl', 'gcc', 'nmake', 'cmake', 'msbuild'],
        BuildTargets.SOLARIS: ['cc', 'gmake', 'pkg-config']
    };
    aToolsBin = aOsTools.get(g_enmBuildTarget, []);
    for sBinary in aToolsBin:
        sFound = shutil.which(sBinary);
        sStatus = f"{Ansi.GREEN}found{Ansi.RESET}" if sFound else f"{Ansi.RED}NOT found{Ansi.RESET}";
        print(f"{printName(sBinary):<30} {sStatus}");

    if g_cErrors == 0:
        write_autoconfig_kmk(g_aoLibs, g_aoTools);

    print('\nWork in progress! Do not use for production builds yet!\n');

    logf.close();
    return 0 if g_cErrors == 0 else 1;

if __name__ == "__main__":
    sys.exit(main());
