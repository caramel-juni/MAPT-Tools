#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'HELP'
Usage:
  ./apk-clone.sh input.apk [--package com.example.app.clone] [--name 'App Clone']
                           [--output cloned.apk] [--install] [--serial emulator-5554]
                           [--provider-mode auto|preserve]

Options:
  --package ID      New unique Android application ID (default: original package + .clone)
  --name TEXT       Name shown under the launcher icon (default: original name + ' Clone')
  --output FILE     Output APK (default: ./<input-basename>-clone.apk)
  --provider-mode  auto (default) changes app-prefixed provider authorities;
                   preserve retains them (may prevent coexistence)
  App-defined custom permissions are renamed only when needed for coexistence.
  --install         Install the rebuilt APK using adb
  --serial SERIAL   adb target, e.g. emulator-5554 (implies --install)
  -h, --help        Show help

Requirements: apktool, python3, keytool, zipalign, apksigner; adb if installing.
A persistent TEST-ONLY key is created in ~/.local/share/apk-clone/test.keystore.
HELP
}

[[ $# -ge 1 ]] || { usage; exit 2; }
[[ $1 != -* ]] || { usage; exit 2; }
input=$1; shift
[[ -f $input ]] || { echo "Input not found: $input" >&2; exit 1; }
new_pkg=''; display_name=''; output=''; install=false; serial=''; provider_mode='auto'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package|--name|--output|--serial|--provider-mode)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      case "$1" in
        --package) new_pkg=$2;;
        --name) display_name=$2;;
        --output) output=$2;;
        --serial) serial=$2; install=true;;
        --provider-mode) provider_mode=$2;;
      esac
      shift 2;;
    --install) install=true; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

[[ $provider_mode == auto || $provider_mode == preserve ]] || { echo 'Invalid --provider-mode (auto or preserve)' >&2; exit 2; }
for cmd in apktool python3 keytool zipalign apksigner; do
  command -v "$cmd" >/dev/null || { echo "Missing prerequisite: $cmd" >&2; exit 1; }
done
if $install; then command -v adb >/dev/null || { echo 'Missing prerequisite: adb' >&2; exit 1; }; fi

input=$(realpath "$input")
base=$(basename "$input" .apk)
output=${output:-"./${base}-clone.apk"}
output=$(realpath -m "$output")
[[ "$input" != "$output" ]] || { echo 'Output cannot overwrite input APK' >&2; exit 1; }
mkdir -p "$(dirname "$output")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo '[1/6] Decoding APK (keeping original DEX bytecode)...'
apktool d -f -s "$input" -o "$work/decoded"
manifest="$work/decoded/AndroidManifest.xml"
[[ -s "$manifest" ]] || { echo 'No decoded AndroidManifest.xml' >&2; exit 1; }

original_pkg=$(python3 - "$manifest" <<'PY'
import sys, xml.etree.ElementTree as ET
print(ET.parse(sys.argv[1]).getroot().attrib.get('package', ''))
PY
)
[[ -n "$original_pkg" ]] || { echo 'Could not determine original package name' >&2; exit 1; }
new_pkg=${new_pkg:-"${original_pkg}.clone"}
display_name=${display_name:-"${base} Clone"}
if [[ ! $new_pkg =~ ^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$ ]]; then
  echo "Invalid Android package name: $new_pkg" >&2; exit 2
fi
[[ "$new_pkg" != "$original_pkg" ]] || { echo 'New package must differ from original' >&2; exit 2; }
echo "Original package: $original_pkg"
echo "Clone package:    $new_pkg"
echo "Launcher label:   $display_name"

echo '[2/6] Minimally patching package and launcher label...'
python3 - "$manifest" "$original_pkg" "$new_pkg" "$display_name" "$provider_mode" <<'PY'
import sys, xml.etree.ElementTree as ET
path, old, new, label, provider_mode = sys.argv[1:]
ANDROID = 'http://schemas.android.com/apk/res/android'
def a(n): return '{%s}%s' % (ANDROID, n)
with open(path, 'rb') as fp:
    for _, (prefix, uri) in ET.iterparse(fp, events=['start-ns']):
        try: ET.register_namespace(prefix or '', uri)
        except ValueError: pass
tree = ET.parse(path)
root = tree.getroot()
if root.get('package') != old:
    raise SystemExit('Unexpected original package')
app = root.find('application')
if app is None: raise SystemExit('No application in manifest')
# Only resolve relative component names. Implementation classes stay untouched.
component_tags = {'application','activity','activity-alias','service','receiver','provider','instrumentation'}
for el in root.iter():
    tag = el.tag.split('}')[-1]
    if tag in component_tags:
        name = el.get(a('name'))
        if name and name.startswith('.'): el.set(a('name'), old + name)
        elif name and '.' not in name: el.set(a('name'), old + '.' + name)
    if tag == 'activity-alias':
        target = el.get(a('targetActivity'))
        if target and target.startswith('.'): el.set(a('targetActivity'), old + target)
        elif target and '.' not in target: el.set(a('targetActivity'), old + '.' + target)
# Android will reject a second app defining the exact same custom permission.
# Rename ONLY app-owned custom permission declarations, plus the matching manifest
# references (uses-permission, component permission, read/writePermission, etc.).
# Do not change platform permissions such as android.permission.CAMERA.
custom_permissions = {}
for el in root:
    if el.tag.split('}')[-1] not in ('permission', 'permission-tree', 'permission-group'):
        continue
    name = el.get(a('name'))
    if name and (name == old or name.startswith(old + '.')):
        replacement = new + name[len(old):]
        custom_permissions[name] = replacement
        el.set(a('name'), replacement)
        print('Custom permission declaration adjusted:', name, '->', replacement)
for el in root.iter():
    for field in ('name', 'permission', 'readPermission', 'writePermission'):
        key = a(field)
        value = el.get(key)
        # Only exact custom permission references, not ordinary class names.
        if value in custom_permissions and (
            field != 'name' or el.tag.split('}')[-1] in
            ('uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m',
             'permission', 'permission-tree', 'permission-group')
        ):
            el.set(key, custom_permissions[value])
            print('Custom permission reference adjusted:', value, '->', custom_permissions[value])
# Authorities MUST be unique between applications; rewrite only original-app-prefixed
# values by default. Keep all Android/platform permissions unchanged.
for el in root.iter('provider'):
    authority = el.get(a('authorities'))
    if not authority: continue
    parts = authority.split(';')
    rewritten = [new + v[len(old):] if (v == old or v.startswith(old + '.')) else v for v in parts]
    if rewritten != parts:
        if provider_mode == 'auto':
            el.set(a('authorities'), ';'.join(rewritten))
            print('Provider authority adjusted:', authority, '->', ';'.join(rewritten))
            print('WARNING: Native code referencing the original authority may need a developer build.', file=sys.stderr)
        else:
            print('WARNING: Preserving provider authority; duplicate may prevent install:', authority, file=sys.stderr)
app.set(a('label'), label)
for el in app:
    if el.tag.split('}')[-1] not in ('activity','activity-alias'): continue
    for intent in el.findall('intent-filter'):
        actions={x.get(a('name')) for x in intent.findall('action')}
        categories={x.get(a('name')) for x in intent.findall('category')}
        if 'android.intent.action.MAIN' in actions and 'android.intent.category.LAUNCHER' in categories:
            el.set(a('label'),label)
            break
root.set('package', new)
tree.write(path, encoding='utf-8', xml_declaration=True)
if root.get(a('sharedUserId')):
    print('WARNING: sharedUserId may prevent installation after signing with a different key', file=sys.stderr)
PY

# Avoid an obsolete renameManifestPackage value overriding our new package.
python3 - "$work/decoded/apktool.yml" <<'PY'
import re,sys
from pathlib import Path
p=Path(sys.argv[1])
if p.exists():
    t=p.read_text()
    t=re.sub(r'(?m)^(\s*renameManifestPackage\s*:)\s*.*$', r'\1 null', t)
    p.write_text(t)
PY

echo '[3/6] Rebuilding with AAPT2 (required for modern Android resources)...'
if ! apktool b --use-aapt2 "$work/decoded" -o "$work/unsigned.apk"; then
  echo >&2 'APK rebuild failed. Check Apktool version (2.7.0 is outdated for SDK 36).'
  echo >&2 'Upgrade Apktool from https://apktool.org/docs/install/ then retry.'
  exit 1
fi
echo '[4/6] Aligning...'
zipalign -f -p 4 "$work/unsigned.apk" "$work/aligned.apk"

echo '[5/6] Signing with persistent test key...'
keydir="${XDG_DATA_HOME:-$HOME/.local/share}/apk-clone"
mkdir -p "$keydir"; chmod 700 "$keydir"
keystore="$keydir/test.keystore"
if [[ ! -f "$keystore" ]]; then
  keytool -genkeypair -noprompt -keystore "$keystore" -alias clone-test \
    -keyalg RSA -keysize 3072 -validity 3650 \
    -storepass android -keypass android \
    -dname 'CN=APK Clone Test, O=Local Security Testing, C=AU' >/dev/null
  chmod 600 "$keystore"
fi
apksigner sign --ks "$keystore" --ks-key-alias clone-test \
  --ks-pass pass:android --key-pass pass:android \
  --out "$output" "$work/aligned.apk"
apksigner verify "$output" || { echo 'APK signature verification failed' >&2; exit 1; }

if command -v aapt >/dev/null; then
  actual=$(aapt dump badging "$output" | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -n1)
  if [[ "$actual" != "$new_pkg" ]]; then
    echo "Package verification failed: expected $new_pkg, got ${actual:-unknown}" >&2
    exit 1
  fi
fi

echo '[6/6] Complete.'
echo "Output: $output"
if $install; then
  echo 'Installing clone...'
  if [[ -n "$serial" ]]; then adb -s "$serial" install -r "$output"
  else adb install -r "$output"; fi
fi
printf '\nOriginal package: %s\nClone package:    %s\n' "$original_pkg" "$new_pkg"
echo 'Note: DEX/native code and standard Android permissions remain untouched; app-defined custom permission names may change to avoid collisions.'
echo 'Hardcoded IDs, permission names, and signature checks may still fail at runtime.'
