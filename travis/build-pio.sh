#!/bin/bash

echo -e "travis_fold:start:install_pio"
pip install -U platformio
if [ $? -ne 0 ]; then exit 1; fi
echo -e "travis_fold:end:install_pio"

echo -e "travis_fold:start:install_lib"
python -m platformio lib --storage-dir $TRAVIS_BUILD_DIR install
if [ $? -ne 0 ]; then exit 1; fi
echo -e "travis_fold:end:install_lib"

echo -e "travis_fold:start:test_pio"
if [ -d "$TRAVIS_BUILD_DIR/examples" ]; then
	for EXAMPLE in $TRAVIS_BUILD_DIR/examples/*/*.ino; do
	    python -m platformio ci $EXAMPLE -l '.' -b esp32dev
		if [ $? -ne 0 ]; then exit 1; fi
	done
fi
echo -e "travis_fold:end:test_pio"

echo -e "travis_fold:start:install_json"
python -m platformio lib -g install https://github.com/bblanchon/ArduinoJson.git
if [ $? -ne 0 ]; then exit 1; fi
echo -e "travis_fold:end:install_json"

cd $HOME/
echo -e "travis_fold:start:install_web_server"
git clone https://github.com/me-no-dev/ESPAsyncWebServer
if [ $? -ne 0 ]; then exit 1; fi
python -m platformio lib --storage-dir $HOME/ESPAsyncWebServer install
if [ $? -ne 0 ]; then exit 1; fi
echo -e "travis_fold:end:install_web_server"

echo -e "travis_fold:start:test_web_server"
for EXAMPLE in $HOME/ESPAsyncWebServer/examples/*/*.ino; do
    python -m platformio ci $EXAMPLE -l $TRAVIS_BUILD_DIR -l $HOME/ESPAsyncWebServer -b esp32dev
	if [ $? -ne 0 ]; then exit 1; fi
done
echo -e "travis_fold:end:test_web_server"
