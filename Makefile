default:
	cargo build --release

x86_64-unknown-linux-gnu:
	cargo build --target $@ --release

aarch64-unknown-linux-gnu:
	cross build --target $@ --release

aarch64-linux-android:
	cross build --target $@ --release

armv7-linux-androideabi:
	cross build --target $@ --release

i686-linux-android:
	cross build --target $@ --release

x86_64-linux-android:
	cross build --target $@ --release
