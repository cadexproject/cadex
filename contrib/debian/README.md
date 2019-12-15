
Debian
====================
This directory contains files used to package cadexd/cadex-qt
for Debian-based Linux systems. If you compile cadexd/cadex-qt yourself, there are some useful files here.

## cadex: URI support ##


cadex-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install cadex-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your cadex-qt binary to `/usr/bin`
and the `../../share/pixmaps/cadex128.png` to `/usr/share/pixmaps`

cadex-qt.protocol (KDE)

