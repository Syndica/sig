prefix := "/usr/local"
bin := "bin"
systemd := "lib/systemd"

build: 
	zig build -Doptimize=ReleaseSafe -Dno-run sig

install: create_user clone_repo
	install -Dm755 sig-update         "$(prefix)/$(bin)/sig-update"
	install -Dm644 sig.service        "$(prefix)/$(systemd)/system/sig.service"
	install -Dm644 sig-update.service "$(prefix)/$(systemd)/system/sig-update.service"
	install -Dm644 sig-update.timer   "$(prefix)/$(systemd)/system/sig-update.timer"
	systemctl daemon-reload

create_user:
	@if ! id sig >/dev/null 2>&1; then \
		echo "Creating user sig"; \
		useradd -m sig; \
	fi

clone_repo:
	@if ! [[ -d /home/sig/sig ]]; then \
		sudo -u sig git clone https://github.com/Syndica/sig.git /home/sig/sig; \
	fi

uninstall: stop
	rm "$(prefix)/$(bin)/sig-update"
	rm "$(prefix)/$(systemd)/user/sig.service"
	rm "$(prefix)/$(systemd)/user/sig-update.service"
	rm "$(prefix)/$(systemd)/user/sig-update.timer"
	systemctl daemon-reload
	userdel sig
	rm -rf /home/sig/sig

start:
	systemctl enable sig.service
	systemctl enable sig-update.timer
	systemctl start sig.service
	systemctl start sig-update.timer

stop:
	systemctl stop sig.service
	systemctl stop sig-update.timer
	systemctl disable sig.service
	systemctl disable sig-update.timer
