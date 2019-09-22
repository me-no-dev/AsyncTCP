#!/bin/bash

CHUNK_INDEX=$1
CHUNKS_CNT=$2
if [ "$#" -lt 2 ]; then
	echo "Building all sketches"
	CHUNK_INDEX=0
	CHUNKS_CNT=1
fi
if [ "$CHUNKS_CNT" -le 0 ]; then
	echo "Chunks count must be positive number"
	exit 1
fi
if [ "$CHUNK_INDEX" -ge "$CHUNKS_CNT" ]; then
	echo "Chunk index must be less than chunks count"
	exit 1
fi

echo -e "travis_fold:start:prep_arduino_ide"
# Install Arduino IDE
wget -O arduino.tar.xz https://www.arduino.cc/download.php?f=/arduino-nightly-linux64.tar.xz
tar xf arduino.tar.xz
mv arduino-nightly $HOME/arduino_ide
mkdir -p $HOME/Arduino/libraries
mkdir -p $HOME/Arduino/hardware
echo -e "travis_fold:end:prep_arduino_ide"

echo -e "travis_fold:start:sketch_test_env_prepare"
cd $HOME/Arduino/libraries
cp -rf $TRAVIS_BUILD_DIR AsyncTCP
PLATFORM_EXAMPLES=$TRAVIS_BUILD_DIR/examples

git clone https://github.com/me-no-dev/ESPAsyncWebServer
git clone https://github.com/bblanchon/ArduinoJson
LIB_EXAMPLES=$HOME/Arduino/libraries/ESPAsyncWebServer/examples

cd $HOME/Arduino/hardware
pip install pyserial
mkdir espressif
cd espressif
git clone https://github.com/espressif/arduino-esp32.git esp32
cd esp32
git submodule update --init --recursive
cd tools
python get.py
PLATFORM_FQBN="espressif:esp32:esp32"
PLATFORM_SIZE_BIN=$HOME/Arduino/hardware/espressif/esp32/tools/xtensa-esp32-elf/bin/xtensa-esp32-elf-size
echo -e "travis_fold:end:sketch_test_env_prepare"

cd $TRAVIS_BUILD_DIR

ARDUINO_IDE_PATH=$HOME/arduino_ide
ARDUINO_USR_PATH=$HOME/Arduino
ARDUINO_BUILD_DIR=$HOME/build.tmp
ARDUINO_CACHE_DIR=$HOME/cache.tmp
ARDUINO_BUILD_CMD="$ARDUINO_IDE_PATH/arduino-builder -compile -logger=human -core-api-version=10810 -hardware \"$ARDUINO_IDE_PATH/hardware\" -hardware \"$ARDUINO_USR_PATH/hardware\" -tools \"$ARDUINO_IDE_PATH/tools-builder\" -built-in-libraries \"$ARDUINO_IDE_PATH/libraries\" -libraries \"$ARDUINO_USR_PATH/libraries\" -fqbn=$PLATFORM_FQBN -warnings=\"all\" -build-cache \"$ARDUINO_CACHE_DIR\" -build-path \"$ARDUINO_BUILD_DIR\" -verbose"

function print_size_info()
{
    elf_file=$1

    if [ -z "$elf_file" ]; then
    	printf "sketch                           iram0.text flash.text flash.rodata dram0.data dram0.bss    dram     flash\n"
        return 0
    fi

    elf_name=$(basename $elf_file)
    sketch_name="${elf_name%.*}"
    declare -A segments
    while read -a tokens; do
        seg=${tokens[0]}
        seg=${seg//./}
        size=${tokens[1]}
        addr=${tokens[2]}
        if [ "$addr" -eq "$addr" -a "$addr" -ne "0" ] 2>/dev/null; then
            segments[$seg]=$size
        fi
    done < <($PLATFORM_SIZE_BIN --format=sysv $elf_file)

    total_ram=$((${segments[dram0data]} + ${segments[dram0bss]}))
    total_flash=$((${segments[iram0text]} + ${segments[flashtext]} + ${segments[dram0data]} + ${segments[flashrodata]}))
    printf "%-32s %-8d   %-8d   %-8d     %-8d   %-8d     %-8d %-8d\n" $sketch_name ${segments[iram0text]} ${segments[flashtext]} ${segments[flashrodata]} ${segments[dram0data]} ${segments[dram0bss]} $total_ram $total_flash
    return 0
}

function build_sketch()
{
	local sketch=$1
    echo -e "\n------------ Building $sketch ------------\n";
    rm -rf $ARDUINO_BUILD_DIR/*
    time ($ARDUINO_BUILD_CMD $sketch >build.log)
    local result=$?
    if [ $result -ne 0 ]; then
        echo "Build failed ($1)"
        echo "Build log:"
        cat build.log
        return $result
    fi
    rm build.log
    return 0
}

function count_sketches()
{
    local path=$1
    if [ ! -d "$path" ]; then
        return 0
    fi
    local sketches=$(find $path -name *.ino)
    local sketchnum=0
    for sketch in $sketches; do
        local sketchdir=$(dirname $sketch)
        local sketchdirname=$(basename $sketchdir)
        local sketchname=$(basename $sketch)
        if [[ "${sketchdirname}.ino" != "$sketchname" ]]; then
            continue
        fi
        echo $sketch >> sketches.txt
        sketchnum=$(($sketchnum + 1))
    done
    return $sketchnum
}

function build_sketches()
{
    mkdir -p $ARDUINO_BUILD_DIR
    mkdir -p $ARDUINO_CACHE_DIR
    mkdir -p $ARDUINO_USR_PATH/libraries
    mkdir -p $ARDUINO_USR_PATH/hardware
    
    local chunk_idex=$1
    local chunks_num=$2
    rm -rf sketches.txt
    count_sketches $PLATFORM_EXAMPLES
    local sketchcount=$?
    count_sketches $LIB_EXAMPLES
    local libsketchcount=$?
    sketchcount=$(($sketchcount + $libsketchcount))
    local sketches=$(cat sketches.txt)

    local chunk_size=$(( $sketchcount / $chunks_num ))
    local all_chunks=$(( $chunks_num * $chunk_size ))
    if [ "$all_chunks" -lt "$sketchcount" ]; then
    	chunk_size=$(( $chunk_size + 1 ))
    fi

    local start_index=$(( $chunk_idex * $chunk_size ))
    if [ "$sketchcount" -le "$start_index" ]; then
    	echo "Skipping job"
    	return 0
    fi

    local end_index=$(( $(( $chunk_idex + 1 )) * $chunk_size ))
    if [ "$end_index" -gt "$sketchcount" ]; then
    	end_index=$sketchcount
    fi

    local start_num=$(( $start_index + 1 ))
    #echo -e "Sketches: \n$sketches\n"
    echo "Found $sketchcount Sketches";
    echo "Chunk Count : $chunks_num"
    echo "Chunk Size  : $chunk_size"
    echo "Start Sketch: $start_num"
    echo "End Sketch  : $end_index"

    local sketchnum=0
    print_size_info >size.log
    for sketch in $sketches; do
        local sketchdir=$(dirname $sketch)
        local sketchdirname=$(basename $sketchdir)
        local sketchname=$(basename $sketch)
        if [[ "${sketchdirname}.ino" != "$sketchname" ]]; then
            #echo "Skipping $sketch, beacause it is not the main sketch file";
            continue
        fi;
        if [[ -f "$sketchdir/.test.skip" ]]; then
            #echo "Skipping $sketch marked";
            continue
        fi
        sketchnum=$(($sketchnum + 1))
        if [ "$sketchnum" -le "$start_index" ]; then
        	#echo "Skipping $sketch index low"
        	continue
        fi
        if [ "$sketchnum" -gt "$end_index" ]; then
        	#echo "Skipping $sketch index high"
        	continue
        fi
        build_sketch $sketch
        local result=$?
        if [ $result -ne 0 ]; then
            return $result
        fi
        print_size_info $ARDUINO_BUILD_DIR/*.elf >>size.log
    done
    return 0
}

echo -e "travis_fold:start:test_arduino_ide"
# Build Examples
build_sketches $CHUNK_INDEX $CHUNKS_CNT
if [ $? -ne 0 ]; then exit 1; fi
echo -e "travis_fold:end:test_arduino_ide"

echo -e "travis_fold:start:size_report"
cat size.log
echo -e "travis_fold:end:size_report"
