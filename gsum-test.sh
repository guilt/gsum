#!/bin/sh

# .sh: Runs gsum CLI test cases, generating files, hashing with range/increment,
# validating output, and verifying hash files. POSIX-compliant for CI/CD.

# Set strict mode
set -eu

# Enable pipefail only if supported
# shellcheck disable=SC3040
# set -o pipefail 2>/dev/null

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
        printf "${blue}[DEBUG]${reset} %b\n" "${1:?Missing message}" >&2
    fi
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

# Parse range string (e.g., 5%-93% → 5 93)
# calculateOffset: converts a percent value (e.g., 5%) or byte value (e.g., 100) to a byte offset
# Usage: calculateOffset <value> <fileSize>
calculateOffset() {
    val="$1"
    fileSize="$2"
    if echo "$val" | grep -q '%$'; then
        percent=$(echo "$val" | sed 's/%$//')
        # Use bc for floating point math
        offset=$(echo "$fileSize * $percent / 100" | bc)
        echo "$offset"
    else
        echo "$val"
    fi
}

# parseRange: outputs start and end byte offsets for any range format
# Usage: parseRange <range> <fileSize>
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
        [ "$start" -lt 0 ] || [ "$end" -gt 100 ] || [ "$start" -ge "$end" ] && (logFatal "Invalid percentage range: $start%-$end%"; return 1)
    else
        [ "$start" -lt 0 ] || [ "$end" -gt "$fileSizeBytes" ] || [ "$start" -ge "$end" ] && (logFatal "Invalid absolute range: $start-$end"; return 1)
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
    startEnd=$(parseRange "$range")
    start=$(echo "$startEnd" | cut -d' ' -f1)
    end=$(echo "$startEnd" | cut -d' ' -f2)
    validateRange "$start" "$end" "$fileSizeBytes" "$isPercent"
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
    [ "$percent" -le 0 ] || [ "$percent" -gt 100 ] && (logFatal "Invalid increment percentage: $percent%"; return 1)
}

# Calculate increment bytes
calculateIncrementBytes() {
    percent="${1:?Missing percent}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    stepBytes=$((fileSizeBytes * percent / 100))
    echo "$stepBytes"
}

# Convert increment to bytes
convertIncrement() {
    increment="${1:?Missing increment}"
    fileSizeBytes="${2:?Missing fileSizeBytes}"
    percent=$(parseIncrement "$increment")
    validateIncrement "$percent"
    stepBytes=$(calculateIncrementBytes "$percent" "$fileSizeBytes")
    logDebug "Converted increment $increment to $stepBytes bytes"
    echo "$stepBytes"
}

# Parse AlgoMatrix to space-separated list
parseAlgoMatrix() {
    algoMatrix="${1:?Missing algoMatrix}"
    [ -z "$algoMatrix" ] && (logFatal "Empty AlgoMatrix"; return 1)
    # POSIX: Split on comma, trim whitespace, output comma-separated
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
    fileLine=$(grep "^File" "$testFile" 2>/dev/null) || (logFatal "No File directive in ${cyan}$testFile${reset}"; return 1)
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
    fileSizeBytes=$(convertFileSizeBytes "$fileSize") || (logFatal "Invalid file size $fileSize"; return 1)

    case "$fileType" in
        zero) fillFile "$fileName" "$fileSizeBytes" "00" 0 4096 ;;
        fill) fillFile "$fileName" "$fileSizeBytes" "$args" 0 4096 ;;
        tile)
            chunkSize=$(echo "$args" | cut -d' ' -f1)
            bytes=$(echo "$args" | cut -d' ' -f2)
            chunkSizeBytes=$(convertFileSizeBytes "$chunkSize") || (logFatal "Invalid chunk size $chunkSize"; return 1)
            tileFile "$fileName" "$fileSizeBytes" "$chunkSizeBytes" "$bytes" || (logFatal "Unable to generate Tile file $fileName"; return 1)
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
    algoMatrix=$(grep "^AlgoMatrix" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2-) || algoMatrix="default"
    logDebug "AlgoMatrix: $algoMatrix"
    rangeLine=$(grep "^Range" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2- || true)
    incrementLine=$(grep "^Increment" "$testFile" 2>/dev/null | cut -d':' -f2- | cut -c2- || true)
    algoList=$(parseAlgoMatrix "$algoMatrix")
    echo "$algoList:$rangeLine:$incrementLine"
}

# Fill file with a byte
fillFile() {
    fileName="${1:?Missing fileName}"
    sizeBytes="${2:?Missing sizeBytes}"
    byteValue="${3:?Missing byteValue}"
    seekOffsetChunk="${4:?Missing seekOffsetChunk}"
    blockSize="${5:-4096}"
    logDebug "Filling ${cyan}$fileName${reset} with $sizeBytes bytes of 0x$byteValue at offset $seekOffsetChunk with blockSize $blockSize"

    # Strip 0x prefix if present
    cleanByteValue=$(echo "$byteValue" | sed 's/^0x//')

    # Convert byteValue to decimal
    decimalByte=$(printf "%d" "0x$cleanByteValue")
    octalByte=$(printf "%o" "$decimalByte")

    # Use dd | tr | dd if available
    if [ -r "/dev/zero" ] && command -v tr >/dev/null 2>&1; then
        count=$(((sizeBytes + blockSize - 1) / blockSize))
        if [ "$decimalByte" -eq 0 ]; then
            # Special case: fill with binary zero
            dd if=/dev/zero bs="$blockSize" count="$count" 2>/dev/null | dd of="$fileName" bs="$blockSize" seek="$seekOffsetChunk" status=none 2>/dev/null || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        else
            # Fill with other values using tr
            dd if=/dev/zero bs="$blockSize" count="$count" 2>/dev/null | tr '\0' "\\$octalByte" | dd of="$fileName" bs="$blockSize" seek="$seekOffsetChunk" status=none 2>/dev/null || {
                logFatal "Failed to fill file ${cyan}$fileName${reset}"; return 1
            }
        fi
    else
        logFatal "dd and tr not available, cannot process file ${cyan}$fileName${reset}";
        return 1
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
    offset=0

    numPatterns=0
    for byte in $tileBytes; do
        numPatterns=$((numPatterns+1))
    done
    patternSizeBytes=$((numPatterns*chunkSizeBytes))
    totalCycles=$(( (fileSizeBytes + patternSizeBytes - 1) / patternSizeBytes ))

    offsetChunk=0
    for _ in $(seq 1 $totalCycles); do
        for byte in $tileBytes; do
            fillFile "$tmpFile" "$chunkSizeBytes" "$byte" "$offsetChunk" "$chunkSizeBytes" || {
                logFatal "Failed to create pattern chunk for byte $byte at offset $offsetChunk";
                rm -f "$tmpFile"; return 1;
            }
            offsetChunk=$((offsetChunk+1))
        done
    done

    logDebug "Writing tiled file ${cyan}$tileFileName${reset} with $fileSizeBytes bytes"
    dd if="$tmpFile" of="$tileFileName" bs="$fileSizeBytes" count="1" status=none 2>/dev/null || {
        logFatal "Failed to write tiled file ${cyan}$tileFileName${reset}";
        return 1
    }
    rm -f "$tmpFile"
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
    incrementLine="${7:-}"
    verifyFlag="${8:-}"

    # If space is in algoFull, use cut to extract algo and key
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
    if [ -n "$incrementLine" ]; then
        gsumCmd="$gsumCmd -increment $incrementLine"
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

    logDebug "GSum completed successfully for $algo"
    return 0
}


# Test a single algorithm on a test file
# Usage: testAlgo <algo> <testFileName> <fileSizeBytes> <rangeSpec> <incrementLine> <testDirBase> <expectedFile>
# shellcheck disable=SC2094
testAlgo() {
    algo="${1:?Missing algo}"
    testFileName="${2:?Missing testFileName}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    testDirBase="${4:?Missing testDirBase}"
    expectedFile="${5:?Missing expectedFile}"
    rangeSpec="${6:-}"
    incrementLine="${7:-}"

    tempOutput="${testDirBase}/tmp.$$.$algo"
    tempError="${testDirBase}/tmp.$$.$algo.err"
    logDebug "Testing algorithm: $algo"

    # Check that the test file exists and is not empty before hashing
    if [ ! -f "$testFileName" ]; then
        logFatal "Test file $testFileName does not exist"; return 1
    fi

    # Perform gsum and process output
    hashes=""
    if ! performGSum "$algo" "$testDirBase" "$testFileName" "$tempOutput" "$tempError" "$rangeSpec" "$incrementLine"; then
        rm -f "$tempOutput" "$tempError" 2>/dev/null
        return 1
    fi
    logDebug "Processing output for $algo"
    if [ ! -s "$tempOutput" ]; then
        logInfo "Empty output for algorithm $algo"
        rm -f "$tempOutput" "$tempError" 2>/dev/null
        return 1
    fi

    while IFS= read -r line || [ -n "$line" ]; do

        hash=$(echo "$line" | awk '{print $1}')
        fileNameAndRange=$(echo "$line" | awk '{print $3}')

        range=""
        if [ -n "$fileNameAndRange" ]; then
            # Extract after '#' if present, otherwise use as-is
            if echo "$fileNameAndRange" | grep -q '#'; then
                range=$(echo "$fileNameAndRange" | sed 's/.*#//')
            else
                range=""
            fi
        fi

        if [ -z "$hash" ]; then
            logInfo "Invalid output line: $line"
            rm -f "$tempOutput" "$tempError" 2>/dev/null
            return 1
        fi
        
        # If range is present, use range in key; otherwise, just Hash-$algo:
        if [ -n "$range" ]; then
            hashes="$hashes\nHash-$algo-$range: $hash"
            logDebug "Collected hash: Hash-$algo-$range: $hash"
        else
            hashes="$hashes\nHash-$algo: $hash"
            logDebug "Collected hash: Hash-$algo: $hash"
        fi
    done < "$tempOutput"
    rm -f "$tempOutput" "$tempError" 2>/dev/null
    logDebug "Completed testing algorithm $algo"
    printf '%s\n' "$hashes" 2>/dev/null || {
        logFatal "Failed to output hashes for algorithm $algo"
        return 1
    }
    return 0
}


# Run all algorithms for a test file
# Usage: testAlgos <algoList> <testFileName> <fileSizeBytes> <rangeLine> <incrementLine> <testDirBase> <expectedFile>
testAlgos() {
    algoList="${1:?Missing algoList}"
    testFileName="${2:?Missing testFileName}"
    fileSizeBytes="${3:?Missing fileSizeBytes}"
    testDirBase="${4:?Missing testDirBase}"
    expectedFile="${5:?Missing expectedFile}"
    rangeLine="${6:-}"
    incrementLine="${7:-}"

    results=""
    IFS=','
    for algoEntry in $algoList; do
        # Trim whitespace
        algo=$(echo "$algoEntry" | sed 's/^ *//;s/ *$//')
        [ -z "$algo" ] && continue
        # Determine rangeSpec for this test
        rangeSpec=""
        if [ -n "$rangeLine" ]; then
            rangeSpec=$(echo "$rangeLine" | sed 's/^ *//;s/ *$//')
        fi
        # Call testAlgo for each algorithm-key pair
        hashes=$(testAlgo "$algo" "$testFileName" "$fileSizeBytes" "$testDirBase" "$expectedFile" "$rangeSpec" "$incrementLine") || {
            logFatal "Algorithm $algo failed for file $testFileName"; return 1
        }
        # Append results
        results="$results\n$hashes"
    done
    unset IFS
    # Output all results (trim leading newline)
    printf '%s\n' "${results#\n}"
    return 0
}

# Compare computed hashes to expected hashes
# Usage: testHashes <testFileName> <algoList> <computedHashes> <expectedFile>
testHashes() {
    testFileName="${1:?Missing testFileName}"
    algoList="${2:?Missing algoList}"
    computedHashes="${3:?Missing computedHashes}"
    expectedFile="${4:?Missing expectedFile}"
    anyFailed=0
    IFS='
'
    for line in $computedHashes; do
        [ -z "$line" ] && continue
        key=$(echo "$line" | cut -d':' -f1)
        hash=$(echo "$line" | cut -d':' -f2- | xargs)
        expected=""
        if [ -f "$expectedFile" ]; then
            logDebug "Key to look for: $key"
            expected=$(grep "^$key:" "$expectedFile" | head -n1 | cut -d':' -f2- | xargs)
        fi
        if [ -z "$expected" ]; then
            # Do not log missing expected hashes and do not mark as failed
            logDebug "Missing expected hash for $key"
            continue
        else
            logDebug "Found expected hash for $key: $expected"
        fi
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
# Usage: cleanupTestCase <testFileName> <algoList>
cleanupTestCase() {
    testFileName="${1:?Missing testFileName}"
    algoList="${2:?Missing algoList}"
    if [ -n "${DEBUG:-}" ]; then
        logDebug "DEBUG set: retaining temporary files for $testFileName ($algoList) for inspection."
        return 0
    fi
    # Remove any tmp.* files related to this test
    rm -f tmp.* 2>/dev/null
    # Remove algorithm-specific temp files
    for algo in $algoList; do
        rm -f "tmp.*.$algo" "tmp.*.$algo.err" 2>/dev/null
    done
}

# Run single test case
# Usage: runTestCase <testName> <testDirBase>
runTestCase() {
    testName="${1:?Missing testName}"
    testDirBase="${2:?Missing testDirBase}"

    # Change to the test case directory for all operations
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

    # Print Description if present
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
    logDebug "Created file ${cyan}$testFileName${reset} with size $fileSizeBytes bytes"

    algoInfo=$(parseAlgos "$testFile") || {
        logInfo "${red}FAILED${reset} Failed to parse algorithms from ${cyan}$testFile${reset}"
        return 1
    }
    algoList=$(echo "$algoInfo" | cut -d':' -f1)
    rangeLine=$(echo "$algoInfo" | cut -d':' -f2)
    incrementLine=$(echo "$algoInfo" | cut -d':' -f3-)
    logInfo "  ${yellow}Algorithms: $algoList${reset}"
    logDebug "Parsed algo info: list=$algoList, range=$rangeLine, increment=$incrementLine"

    computedHashes=$(testAlgos "$algoList" "$testFileName" "$fileSizeBytes" "$testDirBase" "$expectedFile" "$rangeLine" "$incrementLine") || {
        logInfo "${red}FAILED${reset} Algorithm execution for ${cyan}$testName${reset}"
        cleanupTestCase "$testFileName" "$algoList"
        return 1
    }
    logDebug "Captured computed hashes for ${cyan}$testName${reset}"

    if testHashes "$testFileName" "$algoList" "$computedHashes" "$expectedFile"; then
        logDebug "Hash comparison or verification passed for ${cyan}$testName${reset}"
        logInfo "${green}PASSED${reset} test: $testName"
        cleanupTestCase "$testFileName" "$algoList"
        logDebug "Completed test case ${cyan}$testName${reset}"
        return 0
    else
        logInfo "${red}FAILED${reset} test: $testName"
        logDebug "Hash comparison or verification failed for ${cyan}$testName${reset}"
        cleanupTestCase "$testFileName" "$algoList"
        logDebug "Completed test case ${cyan}$testName${reset}"
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
# shellcheck disable=SC2164
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
            (logFatal "Failed to copy ${cyan}$testDir/$testName.tst${reset} to ${cyan}$testCaseDir${reset}"; return 1)
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
        # If only running a single file, break after first
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
    testCaseOrDir="${1:-testcases}"
    binary="${2:-gsum${exe}}"
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
        testMode="file"
        testFilePath="$testCaseOrDir"
        testDir="$(dirname "$testFilePath")"
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
    testDirBase=$(getTestDir) || (logFatal "Failed to get test directory"; return 1)
    parseArgs "$@"
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