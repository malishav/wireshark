#
# win-setup - Prepare a Windows development environment for building Wireshark.
#
# Copyright 2015 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#requires -version 2

# Makefile.nmake + win-setup.sh does:
# - verify_tools: Checks required executables. CMake does this.
# - clean_setup: Removes current and past lib dirs.
# - process_libs: calls libverify or download for each lib.

# To do:
# - Make this the source of truth. Keep the list of libs here.
# - Download everything unconditionally, at least initially.
# - Download the Lua package for our compiler? It might make more
#   sense to switch to Nuget instead.

# Bugs:
# - Unzipping from the shell seems to be slower than Cygwin's unzip or 7zip.

<#
.SYNOPSIS
Prepare a Windows development environment for building Wireshark.

.DESCRIPTION
This script downloads and extracts third-party libraries required to compile
Wireshark.

.PARAMETER Destination
Specifies the destination directory for the text files. The path must
contain the pattern "wireshark-*-libs".

.PARAMETER Platform
Target platform. One of "win64" or "win32".

.PARAMETER VSVersion
Visual Studio version. Must be the numeric version (e.g. "12", "11"),
not the year.

.PARAMETER Force
Download each library even if exists on the local system.

.INPUTS
-Destination Destination directory.
-Platform Target platform.
-VSVersion Visual Studio version.
-Force Force fresh downloads.

.OUTPUTS
A set of libraries required to compile Wireshark on Windows, along with
their compressed archives.
A date stamp (current-tag.txt)

.EXAMPLE
C:\PS> .\tools\win-setup.ps1 -Destination C:\wireshark-master-64-libs -Platform win64
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({$_ -like "*\wireshark-*-libs"})]
    [String]
    $Destination,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateSet("win32", "win64")]
    [String]
    $Platform,

    [Parameter(Mandatory=$false, Position=2)]
    [ValidateSet("12", "11", "10")]
    [String]
    $VSVersion,

    [Parameter(Mandatory=$false)]
    [Switch]
    $Force
)

# Variables

# We create and delete files and directories. Bail out at the first sign of
# trouble instead of trying to catch exceptions everywhere.
$ErrorActionPreference = "Stop"

$Win64CurrentTag = "2015-04-06"
$Win32CurrentTag = "2015-04-06"

# Archive file / subdir.
$Win64Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
    "c-ares-1.9.1-1-win64ws.zip" = "";
    "GeoIP-1.5.1-2-win64ws.zip" = "GeoIP-1.5.1-2-win64ws";
    "gnutls-3.2.15-2.9-win64ws.zip" = "";
    "gtk+-bundle_2.24.23-3.39_win64ws.zip" = "gtk2";
    "kfw-3-2-2-x64-ws.zip" = "";
    "libsmi-svn-40773-win64ws.zip" = "";
    "nasm-2.09.08-win32.zip" = "";
    "portaudio_v19_2.zip" = "";
    "upx303w.zip" = "";
    "user-guide-g7ea0d6c.zip" = "user-guide";
    "WinSparkle-0.3-44-g2c8d9d3-win64ws.zip" = "";
    "WpdPack_4_1_2.zip" = "";
    "zlib128.zip" = "";
}

$Win32Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
    "c-ares-1.9.1-1-win32ws.zip" = "";
    "GeoIP-1.5.1-2-win32ws.zip" = "GeoIP-1.5.1-2-win32ws";
    "gnutls-3.2.15-2.7-win32ws.zip" = "";
    "gtk+-bundle_2.24.23-1.1_win32ws.zip" = "gtk2";
    "kfw-3-2-2-i386-ws-vc6.zip" = "";
    "libsmi-svn-40773-win32ws.zip" = "";
    "nasm-2.09.08-win32.zip" = "";
    "portaudio_v19_2.zip" = "";
    "upx303w.zip" = "";
    "user-guide-g7ea0d6c.zip" = "user-guide";
    "WinSparkle-0.3-44-g2c8d9d3-win32ws.zip" = "";
    "WpdPack_4_1_2.zip" = "";
    "zlib128.zip" = "";
}

# Lua

if ( @("12", "11", "10") -contains $VSVersion ) {
    $Win64Archives["lua-5.2.3_Win64_dll$($VSVersion)_lib.zip"] = "lua5.2.3"
    $Win32Archives["lua-5.2.3_Win32_dll$($VSVersion)_lib.zip"] = "lua5.2.3"
}


# Plain file downloads

$Win32Files = @(
    "WinPcap_4_1_3.exe";
)

$Win64Files = @(
    "WinPcap_4_1_3.exe";
)

$Archives = $Win64Archives;
$Files = $Win64Files;
$CurrentTag = $Win64CurrentTag;

if ($Platform -eq "win32") {
    $Archives = $Win32Archives;
    $Files = $Win32Files;
    $CurrentTag = $Win32CurrentTag;
}

$CleanupItems = @(
    "c-ares-1.9.1-1-win??ws"
    "gnutls-3.1.22-*-win??ws"
    "gnutls-3.2.15-*-win??ws"
    "gtk2"
    "gtk3"
    "kfw-3-2-2-final"
    "kfw-3-2-2-i386-ws-vc6"
    "kfw-3-2-2-x64-ws"
    "lua5.1.4"
    "lua5.2.?"
    "libsmi-0.4.8"
    "libsmi-svn-40773-win??ws"
    "nasm-2.09.08"
    "portaudio_v19"
    "portaudio_v19_2"
    "upx301w"
    "upx303w"
    "user-guide"
    "zlib-1.2.5"
    "zlib-1.2.8"
    "AirPcap_Devpack_4_1_0_1622"
    "GeoIP-1.5.1-*-win??ws"
    "WinSparkle-0.3-44-g2c8d9d3-win??ws"
    "WpdPack"
    "current-tag.txt"
)

[Uri] $DownloadPrefix = "https://anonsvn.wireshark.org/wireshark-$($Platform)-libs/tags/$($CurrentTag)/packages"

# Functions

function DownloadFile($fileName) {
    [Uri] $fileUrl = "$DownloadPrefix/$fileName"
    $destinationFile = "$fileName"
    if ((Test-Path $destinationFile -PathType 'Leaf') -and -not ($Force)) {
        Write-Output "$destinationFile already there; not retrieving."
        return
    }
    Write-Output "Downloading $fileUrl into $Destination"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($fileUrl, "$Destination\$destinationFile")
}

# https://msdn.microsoft.com/en-us/library/windows/desktop/bb787866.aspx
$CopyHereFlags = 4 + 16 + 512 + 1024

function DownloadArchive($fileName, $subDir) {
    DownloadFile $fileName
    $shell = New-Object -com shell.application
    $archiveFile = "$Destination\$fileName"
    $archiveDir = "$Destination\$subDir"
    if ($subDir -and -not (Test-Path $archiveDir -PathType 'Container')) {
        New-Item -ItemType Directory -Path $archiveDir > $null
    }
    $activity = "Extracting $archiveFile into $($archiveDir)"
    foreach ($item in $shell.NameSpace($archiveFile).items()) {
        Write-Progress -Activity "$activity" -Status "Working on $($item.Name)"
        # XXX Folder.CopyHere is really slow.
        $shell.NameSpace($archiveDir).CopyHere($item, $CopyHereFlags)
    }
    Write-Progress -Activity "$activity" -Status "Done" -Completed
}

# On with the show

# Make sure $Destination exists and do our work there.
if ( -not (Test-Path $Destination -PathType 'Container') ) {
    New-Item -ItemType 'Container' "$Destination" > $null
}

# CMake's file TO_NATIVE_PATH passive-aggressively omits the drive letter.
Set-Location "$Destination"
$Destination = $(Get-Item -Path ".\")
Write-Output "Working in $Destination"

# Check our last known state
$destinationTag = "INVALID"
$tagFile = "current_tag.txt"
if ((Test-Path $tagFile -PathType 'Leaf') -and -not ($Force)) {
    $destinationTag = Get-Content $tagFile
}

if ($destinationTag -ne $CurrentTag) {
    Write-Output "Tag $CurrentTag not found. Refreshing."
    $activity = "Removing directories"
    foreach ($oldItem in $CleanupItems) {
        if (Test-Path $oldItem) {
            Write-Progress -Activity "$activity" -Status "Removing $oldItem"
            Remove-Item -force -recurse $oldItem
        }
    }
    Write-Progress -Activity "$activity" -Status "Done" -Completed
} else {
    Write-Output "Tag $CurrentTag found. Skipping."
    exit 0
}

# Download files
foreach ($item in $Files) {
    DownloadFile $item
}

# Download and extract archives
foreach ($item in $Archives.GetEnumerator() | Sort-Object -property key) {
    DownloadArchive $item.Name $item.Value
}

# Save our last known state
Set-Content -Path $tagFile -Value "$CurrentTag"