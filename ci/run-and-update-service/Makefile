prefix := /usr/local
bin := bin
systemd := lib/systemd
branch := main

install: create_user install_config
	install -Dm755 sig-update         "$(prefix)/$(bin)/sig-update"
	install -Dm644 sig.service        "$(prefix)/$(systemd)/system/sig.service"
	install -Dm644 sig-update.service "$(prefix)/$(systemd)/system/sig-update.service"
	install -Dm644 sig-update.timer   "$(prefix)/$(systemd)/system/sig-update.timer"
	sudo -u sig git clone https://github.com/Syndica/sig.git /home/sig/sig
	sudo -u sig mkdir /home/sig/sig/logs
	systemctl daemon-reload

create_user:
	@if ! id sig >/dev/null 2>&1; then \
		echo "Creating user sig"; \
		useradd -m sig; \
	fi

install_config:
	@if ! [ -f /etc/sig.conf ]; then \
		echo "Installing /etc/sig.conf"; \
		install -Dm644 sig.conf /etc/sig.conf; \
		sed -i 's#BRANCH=main#BRANCH=$(branch)#g' /etc/sig.conf; \
	fi

uninstall: stop
	-rm "$(prefix)/$(bin)/sig-update"
	-rm "$(prefix)/$(systemd)/system/sig.service"
	-rm "$(prefix)/$(systemd)/system/sig-update.service"
	-rm "$(prefix)/$(systemd)/system/sig-update.timer"
	-systemctl daemon-reload
	-userdel sig
	-rm -rf /home/sig/sig

start:
	systemctl enable sig.service
	systemctl enable sig-update.timer
	systemctl start sig-update.timer

stop:
	-systemctl stop sig.service
	-systemctl stop sig-update.timer
	-systemctl stop sig-update.service
	-systemctl disable sig.service
	-systemctl disable sig-update.timer
