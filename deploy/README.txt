
if ! id -u fuco >/dev/null 2>&1; then
  sudo useradd --system --user-group --home-dir /opt/fuco --shell /usr/sbin/nologin fuco
fi
sudo install -d -o fuco -g fuco /opt/fuco/logs /opt/fuco/flask_session
sudo chown -R fuco:fuco /opt/fuco
sudo install -m 0644 deploy/systemd/fuco.service /etc/systemd/system/fuco.service
sudo systemctl daemon-reload
sudo systemctl enable --now fuco
sudo systemctl status fuco