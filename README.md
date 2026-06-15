#Установка:

#Скачиваем и устанавливаем зависимости
sudo dnf update
sudo dnf groupinstall "Development Tools" "Development Libraries"
sudo dnf install -y git cmake gcc-c++ make openssl-devel mariadb-connector-c-devel
sudo dnf install zlib-devel

#УСТАНАВЛИВАЕМ MARIADB-CONNECTOR-CPP
sudo dnf install mariadb-connector-c-devel
git clone https://github.com/mariadb-corporation/mariadb-connector-cpp.git
cd mariadb-connector-cpp
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCONC_WITH_UNIT_TESTS=Off -DCMAKE_INSTALL_PREFIX=/usr -DWITH_SSL=OPENSSL
cmake --build . --config RelWithDebInfo -j $(nproc)
sudo make install

#УСТАНАВЛИВАЕМ uWebSockets
git clone --recurse-submodules https://github.com/uNetworking/uWebSockets.git
cd uWebSockets
WITH_OPENSSL=1 make
sudo make install

#УСТАНАВЛИВАЕМ usockets
sudo mkdir -p /usr/local/include/uSockets
sudo cp uSockets/src/*.h /usr/local/include/uSockets/
sudo cp uSockets/uSockets.a /usr/local/lib/
sudo ldconfig

#УСТАНАВЛИВАЕМ БИБЛИОТЕКУ NLOHMANN/JSON
git clone https://github.com/nlohmann/json.git
cd json
mkdir build && cd build
cmake ..


#КОМПИЛИРУЕМ ОСНОВНОЙ ПРОЕКТ
cd build
cmake ..
make
