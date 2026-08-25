#!/usr/bin/env bash
#
# Neural ICE CoreOS — le profil de secours en lien-local est-il RENDU, et juste ?
#
# Ce test EXÉCUTE neural-ice-hostname-init.sh sur un faux système de fichiers.
# Il ne lit pas le dépôt : un contrôle qui se contente de vérifier la présence
# d'une ligne dans un script mesure sa propre prose, pas un comportement.
#
# Écart couvert : ICE-Fabric #447 — sans DHCP, l'appliance n'obtenait AUCUNE
# adresse IPv4 et n'était joignable par aucun chemin.
set -euo pipefail

SCRIPT=image/mdns/neural-ice-hostname-init.sh
n=0
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok()   { n=$((n+1)); printf '  ok  %s\n' "$*"; }
egal() { [ "$2" = "$3" ] || fail "$1 : attendu '$3', obtenu '$2'"; ok "$1"; }

[ -f "$SCRIPT" ] || fail "script introuvable : $SCRIPT (lancer depuis la racine du dépôt)"

# ---------------------------------------------------------------- bac à sable
bac="$(mktemp -d)"; trap 'rm -rf "$bac"' EXIT
IFACE=enP7s7
MAC=30:c5:99:3f:93:b9

monter_bac() { # $1 = mac de l interface de gestion
  rm -rf "$bac"; mkdir -p "$bac"
  mkdir -p "$bac/nm" "$bac/sys/$IFACE" "$bac/run" "$bac/etc"
  printf '%s\n' "$1" > "$bac/sys/$IFACE/address"
  cat > "$bac/nm/mgmt-${IFACE}.nmconnection" <<EOF
[connection]
id=mgmt-${IFACE}
type=ethernet
interface-name=${IFACE}
autoconnect=true
autoconnect-priority=100

[ipv4]
method=auto

[ipv6]
method=auto
EOF
  printf '[server]\nhost-name=x\n' > "$bac/etc/avahi.conf"
  printf 'inconnu\n'               > "$bac/etc/hostname"
  printf '127.0.0.1\tlocalhost\n'  > "$bac/etc/hosts"
  printf 'inconnu'                 > "$bac/etc/proc-hostname"
}

jouer() { # exécute le script entier dans le bac
  env NEURAL_ICE_NM_CONN_DIR="$bac/nm" \
      NEURAL_ICE_SYS_NET="$bac/sys" \
      NEURAL_ICE_RUN_DIR="$bac/run" \
      NEURAL_ICE_AVAHI_CONF="$bac/etc/avahi.conf" \
      NEURAL_ICE_ETC_HOSTNAME="$bac/etc/hostname" \
      NEURAL_ICE_ETC_HOSTS="$bac/etc/hosts" \
      NEURAL_ICE_PROC_HOSTNAME="$bac/etc/proc-hostname" \
      bash "$SCRIPT"
}

# ============================================================ 1. la dérivation
# Sourcer expose les fonctions sans lancer main() — la garde BASH_SOURCE.
monter_bac "$MAC"
derive() {
  env NEURAL_ICE_NM_CONN_DIR="$bac/nm" NEURAL_ICE_SYS_NET="$bac/sys" \
      NEURAL_ICE_RUN_DIR="$bac/run" NEURAL_ICE_AVAHI_CONF="$bac/etc/avahi.conf" \
      bash -c "source '$SCRIPT'; linklocal_address '$1'"
}
echo "== 1. l'adresse dérive des deux mêmes octets que le nom d'hôte =="
egal "93b9 (l'appliance de démonstration)" "$(derive 93b9)" "169.254.147.185"
egal "0a0b"                                "$(derive 0a0b)" "169.254.10.11"
egal "00ff — RFC 3927 interdit 169.254.0.x" "$(derive 00ff)" "169.254.1.255"
egal "ffab — RFC 3927 interdit 169.254.255.x" "$(derive ffab)" "169.254.254.171"
if derive abc >/dev/null 2>&1; then fail "un suffixe de 3 caractères doit être refusé"; fi
ok "un suffixe mal formé est refusé"

# ================================================ 2. le profil est bien rendu
echo "== 2. le profil est rendu par une exécution COMPLÈTE du script =="
monter_bac "$MAC"
mgmt_avant="$(sha256sum "$bac/nm/mgmt-${IFACE}.nmconnection" | cut -d' ' -f1)"
jouer >"$bac/log1" 2>&1 || fail "le script a échoué : $(tail -3 "$bac/log1")"
profil="$bac/nm/fallback-${IFACE}.nmconnection"
[ -f "$profil" ] || fail "profil de secours non rendu (main ne l'appelle pas ?) — $(tail -3 "$bac/log1")"
ok "le profil existe après un run complet — l'appel depuis main est donc atteint"
egal "nom d'hôte dérivé"    "$(cat "$bac/etc/hostname")" "ni-coreos-93b9"
egal "droits du profil"     "$(stat -c %a "$profil")"    "600"
for ligne in \
  "id=fallback-${IFACE}" \
  "interface-name=${IFACE}" \
  "autoconnect=true" \
  "autoconnect-priority=10" \
  "method=manual" \
  "address1=169.254.147.185/16" \
  "method=link-local"; do
  grep -qxF "$ligne" "$profil" || fail "ligne absente du profil : $ligne"
done
ok "toutes les clés attendues sont présentes"
egal "priorité, une seule occurrence" "$(grep -c '^autoconnect-priority=' "$profil")" "1"
egal "le profil de gestion est intact" "$(sha256sum "$bac/nm/mgmt-${IFACE}.nmconnection" | cut -d' ' -f1)" "$mgmt_avant"
egal "aucun fichier temporaire laissé" "$(find "$bac/nm" -name '*.tmp.*' | wc -l)" "0"

# ============================================================ 3. idempotence
echo "== 3. rejouer ne change rien =="
empreinte1="$(sha256sum "$profil" | cut -d' ' -f1)"
jouer >"$bac/log2" 2>&1 || fail "second run en échec"
egal "contenu inchangé" "$(sha256sum "$profil" | cut -d' ' -f1)" "$empreinte1"
grep -q "already current" "$bac/log2" || fail "le second run doit reconnaître le profil comme à jour"
ok "le second run le dit explicitement"

# ==================================================== 4. la dérive est reprise
echo "== 4. un profil altéré est remis en état (sabotage) =="
sed -i 's/^autoconnect-priority=10$/autoconnect-priority=100/' "$profil"
grep -qxF "autoconnect-priority=100" "$profil" || fail "le sabotage n'a pas pris"
jouer >"$bac/log3" 2>&1 || fail "run après sabotage en échec"
egal "priorité restaurée" "$(sed -n 's/^autoconnect-priority=//p' "$profil")" "10"
egal "retour à l'empreinte d'origine" "$(sha256sum "$profil" | cut -d' ' -f1)" "$empreinte1"

# ============================== 5. une autre machine obtient une AUTRE adresse
echo "== 5. deux appliances n'ont pas la même adresse de secours =="
monter_bac "30:c5:99:3f:0a:0b"
jouer >/dev/null 2>&1 || fail "run sur la seconde MAC en échec"
egal "adresse dérivée de la seconde MAC" \
  "$(sed -n 's|^address1=||p' "$bac/nm/fallback-${IFACE}.nmconnection")" "169.254.10.11/16"
egal "nom d'hôte de la seconde MAC" "$(cat "$bac/etc/hostname")" "ni-coreos-0a0b"

printf '\nPASS — %d contrôles\n' "$n"
