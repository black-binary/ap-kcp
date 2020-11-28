default:
	cargo build --release --bin ap-kcp-tun --features build_binary

x86_64-unknown-linux-musl:
	cargo build --release --bin ap-kcp-tun --features build_binary --target x86_64-unknown-linux-musl