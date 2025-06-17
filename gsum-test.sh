#!/bin/sh

# gsum-test.sh: Runs gsum CLI test cases, generating files, hashing with range/increment,
# validating output, and verifying hash files. POSIX-compliant with bash extensions for CI/CD.

# Set strict mode
set -eu

# Global counters for test cases
totalTestCases=0
passedTestCases=0
failedTestCases=0

# Detect Windows for .exe extension
exe=""
if [ "${OS:-}" = "Windows_NT" ] || uname -s 2>/dev/null | grep -E 'CYGWIN|MINGW' >/dev/null; then
    exe=".exe"
fi

# Generate unique testId (yyyy-mm-dd-hh-mm-ss + PID)
dateOutput=$(date -u +%Y-%m-%d-%H-%M-%S 2>/dev/null || date | tr -dc '0-9' | cut -c1-14)
testId="gsum-test-$dateOutput-$$"

# Detect terminal colors
detectTerminalColors() {
    colors=$(tput colors 2>/dev/null || echo 0)
    if [ "$colors" -gt 1 ]; then
        cyan="\033[36m"
        red="\033[31m"
        green="\033[32m"
        yellow="\033[33m"
        blue="\033[34m"
        magenta="\033[35m"
        reset="\033[0m"
    else
        cyan=""
        red=""
        green=""
        yellow=""
        blue=""
        magenta=""
        reset=""
    fi
}

# Log fatal error and exit
logFatal() {
    printf "${red}[FATAL] %b\n${reset}" "${1:?Missing message}" >&2
    return 1
}

# Log informational message
logInfo() {
    printf "${green}[ INFO] %b\n${reset}" "${1:?Missing message}" >&2
}

# Log debug message if DEBUG set
logDebug() {
    if [ -n "${DEBUG:-}" ]; then
        printf "${blue}[DEBUG] %b\n${reset}" "${1:?Missing message}" >&2
    fi
}

# Check environment tools (non-fatal)
checkEnvTools() {
    logDebug "Checking environment tools:"
    for tool in dd tr awk sed truncate printf hexdump; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$("$tool" --version 2>/dev/null | head -n1 || echo "unknown")
            logDebug "$tool version: $version"
        else
            logDebug "$tool not found in PATH, may cause issues"
        fi
    done
    return 0
}

# Get script directory
getScriptDir() {
    scriptDir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    logDebug "Script directory: $scriptDir"
    echo "$scriptDir"
}

# Get temp directory, cache in tempDir
getTempDir() {
    if [ -n "${tempDir:-}" ]; then
        echo "$tempDir"
        return 0
    fi
    if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && [ -w "$TMPDIR" ]; then
        tempDir="$TMPDIR"
    elif [ -n "${TMP:-}" ] && [ -d "$TMP" ] && [ -w "$TMP" ]; then
        tempDir="$TMP"
    elif [ -n "${Temp:-}" ] && [ -d "$Temp" ] && [ -w "$Temp" ]; then
        tempDir="$Temp"
    elif [ -d "/tmp" ] && [ -w "/tmp" ]; then
        tempDir="/tmp"
    else
        tempDir="$HOME/.tmp"
        mkdir "$tempDir" 2>/dev/null || (logFatal "Failed to create ${cyan}$tempDir${reset}"; return 1)
        [ -w "$tempDir" ] || (logFatal "No write permission for ${cyan}$tempDir${reset}"; return 1)
    fi
    logDebug "Selected temp directory: ${cyan}$tempDir${reset}"
    echo "$tempDir"
    return 0
}

# Get test directory, cache in testDirBase
getTestDir() {
    if [ -n "${testDirBase:-}" ]; then
        echo "$testDirBase"
        return 0
    fi
    tempBase=$(getTempDir) || (logFatal "Failed to get temp directory"; return 1)
    testDirBase="${tempBase}/${testId}"
    mkdir "$testDirBase" 2>/dev/null || (logFatal "Failed to create ${cyan}$testDirBase${reset}"; return 1)
    [ -w "$testDirBase" ] || (logFatal "No write permission for ${cyan}$testDirBase${reset}"; return 1)
    logDebug "Created test directory: ${cyan}$testDirBase${reset}"
    echo "$testDirBase"
    return 0
}

# Convert size (e.g., 1M, 6K) to bytes
convertFileSizeBytes() {
    size="${1:?Missing size}"
    case "$size" in
        *E) bytes=$((${size%E} * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)) ;;
        *P) bytes=$((${size%P} * 1024 * 1024 * 1024 * 1024 * 1024)) ;;
        *T) bytes=$((${size%T} * 1024 * 1024 * 1024 * 1024)) ;;
        *G) bytes=$((${size%G} * 1024 * 1024 * 1024)) ;;
        *M) bytes=$((${size%M} * 1024 * 1024)) ;;
        *K) bytes=$((${size%K} * 1024)) ;;
        *B) bytes=$((${size%B})) ;;
        *[0-9]) bytes="$size" ;;
        *) (logFatal "Invalid size format: $size"; return 1) ;;
    esac
    echo "$bytes"
}

# Calculate offset from percent or bytes
calculateOffset() {
    val="$1"
    fileSize="$2"
    if echo "$val" | grep -q '%$'; then
        percent=$(echo "$val" | sed 's/%$//')
        offset=$((fileSize * percent / 100))
        logDebug "Calculated offset: $percent% of $fileSize = $offset bytes"
        echo "$offset"
    else
        echo "$val"
    fi
}

# Parse range string (e.g., 5%-93% → 5 93)
parseRange() {
    range="${1:?Missing range}"
    fileSize="${2:?Missing fileSize}"
    startRaw=$(echo "$range" | cut -d'-' -f1)
    endRaw=$(echo "$range" | cut -d'-' -f2)
    start=$(calculateOffset "$startRaw" "$fileSize")
    end=$(calculateOffset "$endRaw" "$fileSize")
    echo "$start $end"
}

# Validate range bounds
validateRange() {
    start="${1:?Missing start}"
    end="${2:?Missing end}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    isPercent="${4:?Missing isPercent}"
    if [ "$isPercent" = "1" ]; then
        [ "$start" -lt 0 ] || [ "$end" -gt 100 ] || [ "$start" -ge "$end" ] && \
            (logFatal "Invalid percentage range: $start%-$end%"; return 1)
    else
        [ "$start" -lt 0 ] || [ "$end" -gt "$fileSizeBytes" ] || [ "$start" -ge "$end" ] && \
            (logFatal "Invalid absolute range: $start-$end"; return 1)
    fi
}

# Calculate range bytes
calculateRangeBytes() {
    start="${1:?Missing start}"
    end="${2:?Missing end}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    isPercent="${4:?Missing isPercent}"
    if [ "$isPercent" = "1" ]; then
        startBytes=$((fileSizeBytes * start / 100))
        endBytes=$((fileSizeBytes * end / 100))
    else
        startBytes="$start"
        endBytes="$end"
    fi
    logDebug "Range bytes: start=$startBytes, end=$endBytes"
    echo "$startBytes $endBytes"
}

# Convert range to bytes
convertFileRange() {
    range="${1:?Missing range}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    isPercent=0
    if echo "$range" | grep -E '^[0-9]+%-[0-9]+%$' >/dev/null; then
        isPercent=1
    fi
    startEnd=$(parseRange "$range" "$fileSizeBytes")
    start=$(echo "$startEnd" | cut -d' ' -f1)
    end=$(echo "$startEnd" | cut -d' ' -f2)
    validateRange "$start" "$end" "$fileSizeBytes" "$isPercent" || return 1
    startEndBytes=$(calculateRangeBytes "$start" "$end" "$fileSizeBytes" "$isPercent")
    logDebug "Converted range $range to $startEndBytes bytes"
    echo "$startEndBytes"
}

# Parse increment string (e.g., 5% → 5)
parseIncrement() {
    increment="${1:?Missing increment}"
    if echo "$increment" | grep -E '^[0-9]+%$' >/dev/null; then
        echo "$increment" | cut -d'%' -f1
    else
        (logFatal "Invalid increment format: $increment"; return 1)
    fi
}

# Validate increment percentage
validateIncrement() {
    percent="${1:?Missing percent}"
    [ "$percent" -le 0 ] || [ "$percent" -gt 100 ] && \
        (logFatal "Invalid increment percentage: $percent%"; return 1)
}

# Calculate increment bytes
calculateIncrementBytes() {
    percent="${1:?Missing percent}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    stepBytes=$((fileSizeBytes * percent / 100))
    logDebug "Increment bytes: $percent% of $fileSizeBytes = $stepBytes"
    echo "$stepBytes"
}

# Convert increment to bytes
convertIncrement() {
    increment="${1:?Missing increment}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    percent=$(parseIncrement "$increment") || return 1
    validateIncrement "$percent" || return 1
    stepBytes=$(calculateIncrementBytes "$percent" "$fileSizeBytes")
    logDebug "Converted increment $increment to $stepBytes bytes"
    echo "$stepBytes"
}

# Parse AlgoMatrix to space-separated list
parseAlgoMatrix() {
    algoMatrix="${1:?Missing algoMatrix}"
    [ -z "$algoMatrix" ] && (logFatal "Empty AlgoMatrix"; return 1)
    result=""
    IFS=','
    for entry in $algoMatrix; do
        trimmed=$(echo "$entry" | sed 's/^ *//;s/ *$//')
        [ -n "$trimmed" ] && result="${result:+$result,}$trimmed"
    done
    unset IFS
    echo "$result"
}

# Parse File directive
parseFiles() {
    testFile="${1:?Missing testFile}"
    fileLine=$(grep "^File" "$testFile" 2>/dev/null) || \
        (logFatal "No File directive in ${cyan}$testFile${reset}"; return 1)
    # shellcheck disable=SC2086
    set -- $fileLine
    shift
    if [ $# -lt 3 ]; then
        logFatal "Malformed File directive in $testFile: got '$fileLine'"
        return 1
    fi
    fileName="$1"
    fileSize="$2"
    fileType="$3"
    shift 3
    args="$*"
    echo "$fileName $fileSize $fileType $args"
}

# Create test files
createFiles() {
    fileName="${1:?Missing fileName}"
    fileSize="${2:?Missing fileSize}"
    fileType="${3:?Missing fileType}"
    args="${4:-}"
    fileSizeBytes=$(convertFileSizeBytes "$fileSize") || \
        (logFatal "Invalid file size $fileSize"; return 1)

    case "$fileType" in
        zero) fillFile "$fileName" "$fileSizeBytes" "00" 0 ;;
        fill) fillFile "$fileName" "$fileSizeBytes" "$args" 0 ;;
        tile)
            chunkSize=$(echo "$args" | cut -d' ' -f1)
            bytes=$(echo "$args" | cut -d' ' -f2)
            chunkSizeBytes=$(convertFileSizeBytes "$chunkSize") || \
                (logFatal "Invalid chunk size $chunkSize"; return 1)
            tileFile "$fileName" "$fileSizeBytes" "$chunkSizeBytes" "$bytes" || \
                (logFatal "Unable to generate Tile file $fileName"; return 1)
            fileName=$tileFileName
            ;;
        *) (logFatal "Unknown file type $fileType"; return 1) ;;
    esac
    logDebug "Generated file ${cyan}$fileName${reset} with size ${cyan}$fileSizeBytes${reset} bytes"
    echo "$fileName $fileSizeBytes"
}

# Parse AlgoMatrix, Range, Increment
parseAlgos() {
    testFile="${1:?Missing testFile}"
    logDebug "Parsing AlgoMatrix from ${cyan}$testFile${reset}"
    [ -f "$testFile" ] || (logFatal "Test file ${cyan}$testFile${reset} not found"; return 1)
    algoMatrix=$(grep "^AlgoMatrix" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2-) || \
        algoMatrix="default"
    logDebug "AlgoMatrix: $algoMatrix"
    rangeSpec=$(grep "^Range" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2- || true)
    incrementSpec=$(grep "^Increment" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2- || true)
    algoList=$(parseAlgoMatrix "$algoMatrix")
    echo "$algoList:$rangeSpec:$incrementSpec"
}

# Fill file with a byte
fillFile() {
    fileName="${1:?Missing fileName}"
    sizeBytes="${2:?Missing sizeBytes}"
    byteValue="${3:?Missing byteValue}"
    seekOffsetBytes="${4:?Missing seekOffsetBytes}"
    logDebug "Filling ${cyan}$fileName${reset} with ${cyan}$sizeBytes${reset} bytes of ${cyan}0x$byteValue${reset} at offset ${cyan}$seekOffsetBytes${reset}"

    # Strip 0x prefix if present
    cleanByteValue=$(echo "$byteValue" | sed 's/^0x//')

    # Convert byteValue to decimal
    decimalByte=$(printf "%d" "0x$cleanByteValue")

    # Truncate file to 0 if starting at offset 0
    if [ "$seekOffsetBytes" -eq 0 ]; then
        truncate -s 0 "$fileName" 2>/dev/null || touch "$fileName"
    fi

    # Use printf for small files (<= 4096 bytes) for precision
    if [ "$sizeBytes" -le 4096 ]; then
        if [ "$decimalByte" -eq 0 ]; then
            dd if=/dev/zero bs=1 count="$sizeBytes" of="$fileName" seek="$seekOffsetBytes" status=none 2>/dev/null || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        else
            octalByte=$(printf "%03o" "$decimalByte")
            dd if=/dev/zero bs=1 count="$sizeBytes" 2>/dev/null | tr '\0' "\\$octalByte" > "$fileName" || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        fi
    else
        # Use dd | tr for larger files
        LC_ALL=C
        blockSize=4096
        count=$(((sizeBytes + blockSize - 1) / blockSize))
        octalByte=$(printf "%03o" "$decimalByte")
        if [ "$decimalByte" -eq 0 ]; then
            dd if=/dev/zero bs="$blockSize" count="$count" 2>/dev/null | \
            dd of="$fileName" bs="$blockSize" seek=$((seekOffsetBytes / blockSize)) status=none 2>/dev/null || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        else
            dd if=/dev/zero bs="$blockSize" count="$count" 2>/dev/null | \
            tr '\0' "\\$octalByte" | \
            dd of="$fileName" bs="$blockSize" seek=$((seekOffsetBytes / blockSize)) status=none 2>/dev/null || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        fi
        truncate -s $((seekOffsetBytes + sizeBytes)) "$fileName" 2>/dev/null || {
            logFatal "Failed to truncate ${cyan}$fileName${reset} to $((seekOffsetBytes + sizeBytes)) bytes"; return 1
        }
    fi

    # Verify file contents at the correct offset
    if [ -f "$fileName" ] && [ "$sizeBytes" -gt 0 ]; then
        readSize=16
        if [ "$sizeBytes" -lt 16 ]; then
            readSize="$sizeBytes"
        fi
        headBytes=$(hexdump -C -n "$readSize" -s "$seekOffsetBytes" "$fileName" 2>/dev/null | head -n1 | cut -d'|' -f1 | tr -s ' ')
        logDebug "Bytes at offset $seekOffsetBytes in ${cyan}$fileName${reset}: $headBytes"
    fi
}

# Tile file with bytes
tileFile() {
    tileFileName="${1:?Missing tileFileName}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    chunkSizeBytes="${3:?Missing chunkSizeBytes}"
    bytes="${4:?Missing bytes}"
    logDebug "Creating tiled file ${cyan}$tileFileName${reset} with $fileSizeBytes bytes, chunk size $chunkSizeBytes, pattern $bytes"

    tmpFile="${tileFileName}.tile.$$"
    tileBytes=$(echo "$bytes" | tr ',' ' ')
    numPatterns=0
    for byte in $tileBytes; do
        numPatterns=$((numPatterns+1))
    done
    patternSizeBytes=$((numPatterns * chunkSizeBytes))
    totalCycles=$(( (fileSizeBytes + patternSizeBytes - 1) / patternSizeBytes ))

    # Initialize temp file
    truncate -s "$fileSizeBytes" "$tmpFile" 2>/dev/null || {
        logFatal "Failed to initialize ${cyan}$tmpFile${reset}"; return 1
    }

    byteOffset=0
    for _ in $(seq 1 $totalCycles); do
        for byte in $tileBytes; do
            if [ $((byteOffset + chunkSizeBytes)) -le "$fileSizeBytes" ]; then
                fillFile "$tmpFile" "$chunkSizeBytes" "$byte" "$byteOffset" || {
                    logFatal "Failed to create pattern chunk for byte $byte at offset $byteOffset"
                    rm -f "$tmpFile"; return 1
                }
            fi
            byteOffset=$((byteOffset + chunkSizeBytes))
            logDebug "Wrote chunk of $chunkSizeBytes bytes with 0x$byte at offset $byteOffset"
        done
    done

    logDebug "Writing tiled file ${cyan}$tileFileName${reset} with $fileSizeBytes bytes"
    mv "$tmpFile" "$tileFileName" || {
        logFatal "Failed to write tiled file ${cyan}$tileFileName${reset}"
        rm -f "$tmpFile"; return 1
    }
    logDebug "Tiled file ${cyan}$tileFileName${reset} completed"
    return 0
}

# Perform gsum command with proper algo handling
performGSum() {
    algoFull="${1:?Missing algoFull}"
    testDirBase="${2:?Missing testDirBase}"
    testFileName="${3:?Missing testFileName}"
    tempOutput="${4:?Missing tempOutput}"
    tempError="${5:?Missing tempError}"
    rangeSpec="${6:-}"
    incrementSpec="${7:-}"
    verifyFlag="${8:-}"

    # Extract algo and key
    if echo "$algoFull" | grep ' ' >/dev/null; then
        algo=$(echo "$algoFull" | cut -d' ' -f1)
        key=$(echo "$algoFull" | cut -d' ' -f2-)
    else
        algo="$algoFull"
        key=""
    fi

    # Build gsum command
    gsumCmd="$gsumAbsPath"
    if [ "$algo" != "default" ]; then
        gsumCmd="$gsumCmd -algo $algo"
    fi
    if [ -n "$key" ]; then
        gsumCmd="$gsumCmd -key \"$key\""
    fi
    if [ -n "$incrementSpec" ]; then
        gsumCmd="$gsumCmd -increment $incrementSpec"
    fi
    if [ -n "$verifyFlag" ]; then
        gsumCmd="$gsumCmd $verifyFlag"
    fi
    if [ -n "$rangeSpec" ]; then
        gsumCmd="$gsumCmd $testFileName#$rangeSpec"
    else
        gsumCmd="$gsumCmd $testFileName"
    fi

    logDebug "Executing ${cyan}$gsumCmd${reset}"

    if ! eval "$gsumCmd" > "$tempOutput" 2> "$tempError"; then
        errorMsg=$(cat "$tempError" 2>/dev/null || echo "no error output")
        logFatal "GSum execution for $algo failed: $errorMsg"
        return 1
    fi

    logDebug "Raw gsum output for $algo:\n$(cat "$tempOutput" 2>/dev/null)"
    logDebug "GSum completed successfully for $algo"
    return 0
}

# Test a single algorithm on a test file
testAlgo() {
    algo="${1:?Missing algo}"
    testFileName="${2:?Missing testFileName}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    testDirBase="${4:?Missing testDirBase}"
    expectedFile="${5:?Missing expectedFile}"
    rangeSpec="${6:-}"
    incrementSpec="${7:-}"

    tempOutput="${testDirBase}/tmp.$$.$algo"
    tempError="${testDirBase}/tmp.$$.$algo.err"
    logDebug "Testing algorithm: $algo"

    # Check that the test file exists
    [ -f "$testFileName" ] || {
        logFatal "Test file $testFileName does not exist"
        return 1
    }

    # Perform gsum
    performGSum "$algo" "$testDirBase" "$testFileName" "$tempOutput" "$tempError" "$rangeSpec" "$incrementSpec" || {
        rm -f "$tempOutput" "$tempError" 2>/dev/null
        return 1
    }

    # Check for empty output
    [ -s "$tempOutput" ] || {
        logInfo "Empty output for algorithm $algo"
        rm -f "$tempOutput" "$tempError" 2>/dev/null
        return 1
    }

    # Parse output with awk
    hashes=""
    IFS=$'\n'
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        # Extract hash (field 1) and fileNameAndRange (field 3 onwards)
        parsed=$(echo "$line" | awk '{print $1 " " substr($0, index($0,$3))}')
        hash=$(echo "$parsed" | awk '{print $1}')
        fileNameAndRange=$(echo "$parsed" | awk '{$1=""; sub(/^ /, ""); print}')

        logDebug "Parsed line: hash=$hash, fileNameAndRange=$fileNameAndRange"

        [ -z "$hash" ] && {
            logInfo "Invalid output line: $line"
            continue
        }

        # Extract range if present
        range=""
        if echo "$fileNameAndRange" | grep -q '#'; then
            range=$(echo "$fileNameAndRange" | sed 's/.*#//')
        fi

        # Store hash with range or algo key
        if [ -n "$range" ]; then
            if [ -n "$hashes" ]; then
                hashes="${hashes}|"
            fi
            hashes="${hashes}Hash-$algo-$range: $hash"
            logDebug "Collected hash: Hash-$algo-$range: $hash"
        else
            if [ -n "$hashes" ]; then
                hashes="${hashes}|"
            fi
            hashes="${hashes}Hash-$algo: $hash"
            logDebug "Collected hash: Hash-$algo: $hash"
        fi
    done < "$tempOutput"
    unset IFS

    rm -f "$tempOutput" "$tempError" 2>/dev/null
    logDebug "Completed testing algorithm $algo"
    printf '%s\n' "${hashes#\n}" 2>/dev/null || {
        logFatal "Failed to output hashes for algorithm $algo"
        return 1
    }
    return 0
}

# Run all algorithms for a test file
testAlgos() {
    algoList="${1:?Missing algoList}"
    testFileName="${2:?Missing testFileName}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    testDirBase="${4:?Missing testDirBase}"
    expectedFile="${5:?Missing expectedFile}"
    rangeSpec="${6:-}"
    incrementSpec="${7:-}"

    results=""
    IFS=','
    for algoEntry in $algoList; do
        algo=$(echo "$algoEntry" | sed 's/^ *//;s/ *$//')
        [ -z "$algo" ] && continue
        localRangeSpec=""
        if [ -n "$rangeSpec" ]; then
            localRangeSpec=$(echo "$rangeSpec" | sed 's/^ *//;s/ *$//')
        fi
        hashes=$(testAlgo "$algo" "$testFileName" "$fileSizeBytes" "$testDirBase" "$expectedFile" "$localRangeSpec" "$incrementSpec" | tr '\n' '|') || {
            logFatal "Algorithm $algo failed for file $testFileName"; return 1
        }
        logDebug "Gathered hashes for $algo: $hashes"
        if [ -n "$results" ]; then
            results="${results}|${hashes}"
        else
            results="${hashes}"
        fi
    done
    unset IFS
    logDebug "Gathered all hashes: ${results}"
    printf '%s\n' "${results#\n}"
    return 0
}

# Compare computed hashes to expected hashes
testHashes() {
    testFileName="${1:?Missing testFileName}"
    algoList="${2:?Missing algoList}"
    computedHashes="${3:?Missing computedHashes}"
    expectedFile="${4:?Missing expectedFile}"
    anyFailed=0
    IFS='|'
    for line in $computedHashes; do
        [ -z "$line" ] && continue
        key=$(echo "$line" | awk -F': ' '{print $1}')
        hash=$(echo "$line" | awk -F': ' '{for(i=2;i<=NF;i++) printf "%s%s", (i==2?"":": "), $i}')
        expected=""
        if [ -f "$expectedFile" ]; then
            logDebug "Key to look for: $key"
            expected=$(grep "^$key: " "$expectedFile" | head -n1 | awk -F': ' '{for(i=2;i<=NF;i++) printf "%s%s", (i==2?"":": "), $i}')
        fi
        if [ -z "$expected" ]; then
            logDebug "No expected hash for $key, skipping comparison"
            continue
        fi
        logDebug "Found expected hash for $key: $expected"
        if [ "$hash" = "$expected" ]; then
            logInfo "${green}PASSED${reset} $key for $testFileName"
        else
            logInfo "${red}FAILED${reset} $key for $testFileName: got $hash, expected $expected"
            anyFailed=1
        fi
    done
    unset IFS
    return $anyFailed
}

# Remove temporary files for a test case
cleanupTestCase() {
    testFileName="${1:?Missing testFileName}"
    algoList="${2:?Missing algoList}"
    if [ -n "${DEBUG:-}" ]; then
        logDebug "DEBUG set: retaining temporary files for $testFileName ($algoList)"
        return 0
    fi
    rm -f tmp.* 2>/dev/null
    for algo in $algoList; do
        rm -f "tmp.*.$algo" "tmp.*.$algo.err" 2>/dev/null
    done
}

# Run single test case
runTestCase() {
    testName="${1:?Missing testName}"
    testDirBase="${2:?Missing testDirBase}"

    cd "$testDirBase" || (logFatal "Failed to cd to test case directory $testDirBase"; return 1)

    logInfo "${cyan}=== Running test: $testName ===${reset}"
    logDebug "Starting test case ${cyan}$testName${reset}"

    testFile="${testDirBase}/${testName}.tst"
    expectedFile="${testDirBase}/${testName}.tst.expected"

    if [ ! -f "$expectedFile" ]; then
        logInfo "${red}FAILED${reset} Missing ${cyan}$expectedFile${reset}"
        return 1
    fi
    logDebug "Found expected file ${cyan}$expectedFile${reset}"

    descLine=$(grep '^Description:' "$testFile" 2>/dev/null || true)
    if [ -n "$descLine" ]; then
        logInfo "${descLine#Description: }"
    fi

    fileInfo=$(parseFiles "$testFile") || {
        logInfo "${red}FAILED${reset} Failed to parse ${cyan}$testFile${reset}"
        return 1
    }
    fileName=$(echo "$fileInfo" | cut -d' ' -f1)
    fileSize=$(echo "$fileInfo" | cut -d' ' -f2)
    fileType=$(echo "$fileInfo" | cut -d' ' -f3)
    args=$(echo "$fileInfo" | cut -d' ' -f4-)
    logDebug "Parsed File Information name: $fileName, size: $fileSize, type: $fileType, args: $args"

    fileInfo=$(createFiles "$fileName" "$fileSize" "$fileType" "$args") || {
        logInfo "${red}FAILED${reset} File creation for ${cyan}$fileName${reset}"
        return 1
    }
    testFileName=$(echo "$fileInfo" | cut -d' ' -f1)
    fileSizeBytes=$(echo "$fileInfo" | cut -d' ' -f2)
    logDebug "Using file ${cyan}$testFileName${reset} with size ${cyan}$fileSizeBytes${reset} bytes"

    algoInfo=$(parseAlgos "$testFile") || {
        logInfo "${red}FAILED${reset} Failed to parse algorithms from ${cyan}$testFile${reset}"
        return 1
    }
    algoList=$(echo "$algoInfo" | cut -d':' -f1)
    rangeSpec=$(echo "$algoInfo" | cut -d':' -f2)
    incrementSpec=$(echo "$algoInfo" | cut -d':' -f3)
    logInfo "  ${yellow}Algorithms: $algoList${reset}"
    logDebug "Parsed algo info: list=$algoList, range=$rangeSpec, increment=$incrementSpec"

    computedHashes=$(testAlgos "$algoList" "$testFileName" "$fileSizeBytes" "$testDirBase" "$expectedFile" "$rangeSpec" "$incrementSpec") || {
        logInfo "${red}FAILED${reset} Algorithm execution for ${cyan}$testName${reset}"
        cleanupTestCase "$testFileName" "$algoList"
        return 1
    }
    logDebug "Captured computed hashes for test: ${cyan}$testName${reset}"

    logDebug "About to compare computed hashes for test: ${cyan}$testName${reset}"
    if testHashes "$testFileName" "$algoList" "$computedHashes" "$expectedFile"; then
        logDebug "Hash comparison passed for test: ${cyan}$testName${reset}"
        logInfo "${green}PASSED${reset} test: $testName"
        cleanupTestCase "$testFileName" "$algoList"
        return 0
    else
        logInfo "${red}FAILED${reset} test: $testName"
        logDebug "Hash comparison failed for test: ${cyan}$testName${reset}"
        cleanupTestCase "$testFileName" "$algoList"
        return 1
    fi
}

# Prepare test environment
prepareTests() {
    cp "$binary" "$testDirBase/gsum${exe}" || (logFatal "Failed to copy binary to test directory"; return 1)
    chmod +x "$testDirBase/gsum${exe}" || (logFatal "Failed to chmod binary"; return 1)
    gsumAbsPath="$(cd "$testDirBase" && pwd)/gsum${exe}"
    logDebug "Absolute gsum binary path: $gsumAbsPath"
}

# Run all tests
runTests() {
    logInfo "Test Id: $testId"
    if [ "$testMode" = "file" ]; then
        testFiles="$testFilePath"
    else
        testFiles=$(find "$testDir" -type f -name "*.tst" 2>/dev/null | sort || true)
    fi
    logDebug "Found test files: ${cyan}$testFiles${reset}"
    if [ -z "$testFiles" ]; then
        logInfo "No test files found in ${cyan}$testDir${reset}"
        return
    fi

    for testFile in $testFiles; do
        testName=$(basename "$testFile" .tst)
        testCaseDir="$testDirBase/$testName"
        mkdir -p "$testCaseDir" || (logFatal "Failed to create test case directory $testCaseDir"; return 1)
        logDebug "Processing test file ${cyan}$testFile${reset} (name: $testName)"
        if ! cp "$testDir/$testName.tst" "$testCaseDir/$testName.tst" 2>/dev/null; then
            logFatal "Failed to copy ${cyan}$testDir/$testName.tst${reset} to ${cyan}$testCaseDir${reset}"
            failedTestCases=$((failedTestCases+1))
            totalTestCases=$((totalTestCases+1))
            continue
        fi
        logDebug "Copied ${cyan}$testDir/$testName.tst${reset} to ${cyan}$testCaseDir/$testName.tst${reset}"
        cp "$testDir/$testName.tst.expected" "$testCaseDir/$testName.tst.expected" 2>/dev/null || {
            logDebug "No expected file ${cyan}$testDir/$testName.tst.expected${reset}, proceeding"
        }

        logDebug "Starting test case $testName in $testCaseDir"
        if (
            cd "$testCaseDir" || (logFatal "Failed to cd to $testCaseDir"; return 1)
            runTestCase "$testName" "$testCaseDir"
        ); then
            passedTestCases=$((passedTestCases+1))
        else
            failedTestCases=$((failedTestCases+1))
        fi
        totalTestCases=$((totalTestCases+1))

        logDebug "Finished test case $testName"
        if [ "$testMode" = "file" ]; then
            break
        fi
    done
    logDebug "Completed all test cases"
}

# Print usage
printUsage() {
    logInfo "Usage: $0 [testcasesDir] [binary]"
    logInfo "  testcasesDir  Test cases dir (default: testcases)"
    logInfo "  binary        gsum binary (default: gsum${exe})"
    exit 0
}

# Parse args
parseArgs() {
    if [ "${1:-}" = "-h" ]; then
        printUsage
    fi
    scriptDir=$(getScriptDir)
    logDebug "Script directory: $scriptDir"
    testCaseOrDir="${1:-$scriptDir/testcases}"
    logDebug "Test case or dir: $testCaseOrDir"
    binary="${2:-$scriptDir/gsum${exe}}"
    [ "$#" -gt 2 ] && (logFatal "Too many arguments"; return 1)
    if [ -d "$testCaseOrDir" ]; then
        testMode="dir"
        testDir="$testCaseOrDir"
    elif [ -f "$testCaseOrDir" ]; then
        case "$testCaseOrDir" in
            *.tst)
                testMode="file"
                testFilePath="$testCaseOrDir"
                testDir="$(dirname "$testFilePath")"
                ;;
            *)
                (logFatal "Argument must be a directory or a .tst file: $testCaseOrDir"; return 1)
                ;;
        esac
    else
        (logFatal "Argument must be a directory or a .tst file: $testCaseOrDir"; return 1)
    fi
    [ -f "$binary" ] || (logFatal "Binary ${cyan}$binary${reset} not found"; return 1)
    logDebug "Using test directory: ${cyan}$testDir${reset}"
    logDebug "Using binary: ${cyan}$binary${reset}"
}

# Print test summary
printSummary() {
    logInfo "${cyan}=== Test Summary ===${reset}"
    logInfo "  ${magenta}TOTAL${reset} test cases: ${magenta}$totalTestCases${reset}"
    logInfo "  ${green}PASSED${reset} test cases: ${green}$passedTestCases${reset}"
    logInfo "  ${red}FAILED${reset} test cases: ${red}$failedTestCases${reset}"
}

# Cleanup after Test
cleanupAfterTest() {
    if [ -n "${DEBUG:-}" ]; then
        logDebug "Test directory $testDirBase retained for inspection."
    else
        rm -rf "$testDirBase" 2>/dev/null
        logInfo "Test directory $testDirBase removed"
    fi
}

# Main
main() {
    [ -n "${TRACE:-}" ] && set -x
    
    detectTerminalColors
    checkEnvTools
    parseArgs "$@"
    testDirBase=$(getTestDir) || (logFatal "Failed to get test directory"; return 1)
    prepareTests
    runTests
    printSummary    
    cleanupAfterTest

    [ "$failedTestCases" -eq 0 ] || (logFatal "Test cases failed: $failedTestCases failures"; return 1)
    logInfo "All Test cases passed."
    return 0
}

# Run main
main "$@"