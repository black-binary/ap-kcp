default:
	cargo build --release --bin ap-kcp-tun --features build_binary

x86_64-unknown-linux-musl:
	cargo build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip -j ./target/$@/release/ap-kcp-tun

aarch64-unknown-linux-musl:
	cross build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip -j ./target/$@/release/ap-kcp-tun

armv7-unknown-linux-musleabihf:
	cross build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip -j ./target/$@/release/ap-kcp-tun

armv5te-unknown-linux-musleabi:
	cross build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip -j ./target/$@/release/ap-kcp-tun

arm-unknown-linux-musleabihf:
	cross build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip -j ./target/$@/release/ap-kcp-tun

aarch64-linux-android:
	cross build --release --bin ap-kcp-tun --features build_binary --target $@
	zip $@.zip ./target/$@/release/ap-kcp-tun

all: x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf armv5te-unknown-linux-musleabi arm-unknown-linux-musleabihf aarch64-linux-android
