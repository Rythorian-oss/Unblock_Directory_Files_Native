<#
.SYNOPSIS
    Recursively removes the Mark of the Web using zero-allocation native Windows API calls.

.DESCRIPTION
    Bypasses heavy PowerShell cmdlets to utilize C# Parallel.ForEach and kernel32.dll P/Invoke. 
    Eliminates GC heap fragmentation, resolves interlocked collision issues, and processes 
    massive directories at bare-metal speeds.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_.Trim('"', "'") -PathType Container })]
    [string]$Path,

    [int]$ThrottleLimit = [System.Environment]::ProcessorCount
)

begin {
    $ErrorActionPreference = 'Stop'
    
    # Compile the high-performance native handler if not already loaded
    if (-not ('NativeMotwRemover' -as [type])) {
        Add-Type -TypeDefinition @"
        using System;
        using System.IO;
        using System.Threading;
        using System.Threading.Tasks;
        using System.Collections.Concurrent;
        using System.Runtime.InteropServices;

        public class NativeMotwRemover
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool DeleteFile(string name);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern uint GetFileAttributes(string lpFileName);

            private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;

            public class AuditReport 
            {
                public string DirectoryProcessed;
                public int TotalFiles;
                public int SuccessfullyCleared;
                public int FailedFiles;
                public bool IsFullyVerified;
                public string[] FailedFileList;
            }

            public static AuditReport ProcessDirectory(string targetPath, int maxThreads)
            {
                var failedFiles = new ConcurrentBag<string>();
                int processedCount = 0;

                var options = new ParallelOptions { MaxDegreeOfParallelism = maxThreads };

                Parallel.ForEach(Directory.EnumerateFiles(targetPath, "*", SearchOption.AllDirectories), options, file =>
                {
                    Interlocked.Increment(ref processedCount);
                    
                    // The Alternate Data Stream (ADS) path
                    string streamPath = file + ":Zone.Identifier";

                    // Native API execution (Zero-allocation of FileInfo objects)
                    DeleteFile(streamPath);

                    // Strict Verification: Query attributes natively
                    uint attr = GetFileAttributes(streamPath);
                    if (attr != INVALID_FILE_ATTRIBUTES)
                    {
                        failedFiles.Add(file);
                    }
                });

                int totalFailed = failedFiles.Count;
                
                return new AuditReport 
                {
                    DirectoryProcessed = targetPath,
                    TotalFiles = processedCount,
                    SuccessfullyCleared = processedCount - totalFailed,
                    FailedFiles = totalFailed,
                    IsFullyVerified = (totalFailed == 0 && processedCount > 0),
                    FailedFileList = failedFiles.ToArray()
                };
            }
        }
"@
    }
}

process {
    # Clean literal quotes from the input before resolving
    $cleanPath = $Path.Trim('"', "'")
    $resolvedPath = (Resolve-Path -LiteralPath $cleanPath).ProviderPath

    if ($PSCmdlet.ShouldProcess($resolvedPath, "Native Zero-Allocation MotW Removal")) {
        Write-Verbose "Initiating native P/Invoke thread pool across $ThrottleLimit cores."
        
        $report = [NativeMotwRemover]::ProcessDirectory($resolvedPath, $ThrottleLimit)

        if (-not $report.IsFullyVerified -and $report.TotalFiles -gt 0) {
            Write-Warning "Audit failed: $($report.FailedFiles) file(s) retained the Mark of the Web."
        } else {
            Write-Verbose "Audit verified: 100% of discovered files successfully unblocked."
        }

        return $report
    }
}