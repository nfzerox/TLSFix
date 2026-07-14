#!/bin/zsh

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SDKROOT="${THEOS:-$HOME/theos}/sdks"
OSSL="$DIR/src/openssl"
SRCS=("$DIR/src/tlsfix_engine.c" "$DIR/src/tlsfix_hooks.c")
[ -f "$OSSL/lib/libssl.a" ] || { echo "missing $OSSL/lib/libssl.a (provide src/openssl: libcrypto.a/libssl.a + include/)"; exit 1; }

typeset -A SDKV MINV
SDKV=(armv6 "$SDKROOT/iPhoneOS5.1.sdk" armv7 "$SDKROOT/iPhoneOS5.1.sdk" arm64 "$SDKROOT/iPhoneOS7.0.sdk")
MINV=(armv6 2.0 armv7 3.0 arm64 7.0)
ARCHS=(${=TLSFIX_ARCHS:-armv6 armv7 arm64})

BUILD="$DIR/.build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
slices=()
for a in "${ARCHS[@]}"; do
  SDK="${SDKV[$a]}"; min="${MINV[$a]}"
  [ -d "$SDK" ] || { echo "missing SDK for $a: $SDK"; exit 1; }
  crt=(); case "$a" in armv6|armv7) crt=("$SDK/usr/lib/dylib1.o") ;; esac
  objs=()
  for src in "${SRCS[@]}"; do
    o="$BUILD/$(basename "${src%.c}")-$a.o"
    xcrun --sdk "$SDK" clang -arch "$a" -miphoneos-version-min="$min" -isysroot "$SDK" -fno-modules \
      -Wno-deprecated-declarations -I"$OSSL/include" -ffile-prefix-map="$DIR=." -c "$src" -o "$o" 2>&1 \
      | grep -ivE 'tbd file|is deprecated' || true
    [ -f "$o" ] || { echo "compile failed for $a ($src)"; exit 1; }
    objs+=("$o")
  done
  out="$BUILD/tlsfix-$a.dylib"
  xcrun --sdk "$SDK" ld -arch "$a" -ios_version_min "$min" -dylib -o "$out" \
    -install_name /Library/MobileSubstrate/DynamicLibraries/tlsfix.dylib \
    "${objs[@]}" "$OSSL/lib/libssl.a" "$OSSL/lib/libcrypto.a" \
    -syslibroot "$SDK" -L"$SDK/usr/lib" "${crt[@]}" \
    -F"${THEOS:-$HOME/theos}/vendor/lib" -framework CydiaSubstrate \
    -framework Security -framework CoreFoundation -lSystem
  [ -f "$out" ] || { echo "link failed for $a"; exit 1; }
  slices+=("$out"); echo "  $a (SDK $(basename "$SDK"), min $min) ok"
done

CTL="$DIR/control"
[ -f "$CTL" ] || { echo "missing control file: $CTL"; exit 1; }
ST="$BUILD/stage"
mkdir -p "$ST/DEBIAN" "$ST/Library/MobileSubstrate/DynamicLibraries"
lipo -create "${slices[@]}" -o "$ST/Library/MobileSubstrate/DynamicLibraries/tlsfix.dylib"
ldid -S "$ST/Library/MobileSubstrate/DynamicLibraries/tlsfix.dylib"
cp "$DIR/src/tlsfix.plist" "$ST/Library/MobileSubstrate/DynamicLibraries/tlsfix.plist"
cp "$CTL" "$ST/DEBIAN/control"
[ -n "$(tail -c1 "$ST/DEBIAN/control")" ] && echo >> "$ST/DEBIAN/control"
cat > "$ST/DEBIAN/postinst" <<'POST'
#!/bin/sh
for d in /Library/MobileSubstrate /Library/MobileSubstrate/DynamicLibraries; do
  [ -d "$d" ] && chmod 0755 "$d" 2>/dev/null || true
done
exit 0
POST
chmod 0755 "$ST/DEBIAN/postinst"
find "$ST" -type d -exec chmod 0755 {} +
find "$ST" -type f -exec chmod 0644 {} +
chmod 0755 "$ST/Library/MobileSubstrate/DynamicLibraries/tlsfix.dylib" "$ST/DEBIAN/postinst"

PKG=$(awk -F': *' '/^Package:/{print $2}' "$CTL")
VER=$(awk -F': *' '/^Version:/{print $2}' "$CTL")
mkdir -p "$DIR/Packages"
OUT="$DIR/Packages/${PKG}_${VER}_iphoneos-arm.deb"; rm -f "$OUT"
"${THEOS:-$HOME/theos}/bin/dm.pl" -b "$ST" "$OUT"
rm -rf "$BUILD"
echo "built: $OUT"
