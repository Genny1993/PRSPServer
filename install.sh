#!/bin/bash

# Путь к серверу
SERVER_PATH="/home/user/game/PRSPServer/build/prsp"
WORK_DIR="/home/user/game/PRSPServer/build"
SERVICE_NAME="prsp"
USER_NAME="user"

# Проверяем, что сервер существует
if [ ! -f "$SERVER_PATH" ]; then
    echo "Ошибка: $SERVER_PATH не найден!"
    exit 1
fi

# 1. Создаём systemd-сервис
echo "Создаю systemd-сервис..."

sudo bash -c "cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=PRSP Messenger Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${WORK_DIR}
ExecStart=${SERVER_PATH}
Restart=always
RestartSec=10
User=${USER_NAME}
Group=${USER_NAME}

[Install]
WantedBy=multi-user.target
EOF"

# 2. Перезагружаем systemd и запускаем сервис
echo "Активирую сервис..."
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl start ${SERVICE_NAME}

# 3. Добавляем в crontab для авто-перезапуска (на случай падения)
echo "Добавляю проверку в crontab..."

CRON_CMD="* * * * * pgrep -f '${SERVER_PATH}' || ${SERVER_PATH}"

(crontab -l 2>/dev/null | grep -v -F "$SERVER_PATH"; echo "$CRON_CMD") | crontab -

echo "Готово!"
