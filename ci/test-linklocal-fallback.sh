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

# Bouchons de commandes EXTERNES (frontière du script, pas son intérieur) : ils
# consignent leurs appels pour qu'on puisse exiger que NetworkManager soit
# rechargé quand le profil change, et seulement là.
poser_bouchons() { # $1 = etat rendu par `systemctl is-active` (0 = actif)
  mkdir -p "$bac/bin"
  cat > "$bac/bin/nmcli" <<EOF
#!/bin/sh
echo "nmcli \$*" >> "$bac/appels"
case "\$*" in
  *"connection show --active"*) [ -f "$bac/actives" ] && cat "$bac/actives" ; exit 0 ;;
  *"connection up"*) [ -f "$bac/dhcp-absent" ] && exit 4 ; exit 0 ;;
esac
exit 0
EOF
  cat > "$bac/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$bac/appels"
exit $1
EOF
  chmod +x "$bac/bin/nmcli" "$bac/bin/systemctl"
  : > "$bac/appels"
}

jouer() { # exécute le script entier dans le bac
  env NEURAL_ICE_NM_CONN_DIR="$bac/nm" \
      NEURAL_ICE_SYS_NET="$bac/sys" \
      NEURAL_ICE_RUN_DIR="$bac/run" \
      NEURAL_ICE_AVAHI_CONF="$bac/etc/avahi.conf" \
      NEURAL_ICE_ETC_HOSTNAME="$bac/etc/hostname" \
      NEURAL_ICE_ETC_HOSTS="$bac/etc/hosts" \
      NEURAL_ICE_PROC_HOSTNAME="$bac/etc/proc-hostname" \
      PATH="$bac/bin:$PATH" \
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
if derive abc  >/dev/null 2>&1; then fail "un suffixe de 3 caractères doit être refusé"; fi
if derive zzzz >/dev/null 2>&1; then fail "un suffixe non hexadécimal doit être refusé"; fi
ok "un suffixe mal formé est refusé"

# Le repliement RFC 3927 est INÉVITABLE : 65536 suffixes pour 254*256 = 65024
# adresses utilisables. On l'épingle pour qu'il reste un choix documenté et non
# une surprise — et pour qu'un changement d'algorithme se voie ici.
egal "00ff et 01ff partagent leur adresse (replié)" "$(derive 00ff)" "$(derive 01ff)"
egal "ffab et feab partagent leur adresse (replié)" "$(derive ffab)" "$(derive feab)"
collisions=0
for x in 0a0b 93b9 7f10 c0de; do
  for y in 0a0c 93ba 7f11 c0df; do
    [ "$x" = "$y" ] && continue
    [ "$(derive "$x")" = "$(derive "$y")" ] && collisions=$((collisions+1))
  done
done
egal "hors bande repliée, aucune collision" "$collisions" "0"

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

# ======================================== 6. NetworkManager est bien prévenu
# Mesuré sur ni-coreos-93b9 le 25.08 : un keyfile fraîchement écrit reste
# INVISIBLE pour un NetworkManager déjà lancé — `nmcli con show` répond
# « no such connection profile » — jusqu'à un rechargement.
echo "== 6. NetworkManager est rechargé quand, et seulement quand, le profil change =="
monter_bac "$MAC"; poser_bouchons 0
jouer >/dev/null 2>&1 || fail "run avec bouchons en échec"
egal "rechargement demandé au premier rendu" "$(grep -c '^nmcli connection reload$' "$bac/appels")" "1"

: > "$bac/appels"
jouer >/dev/null 2>&1 || fail "second run avec bouchons en échec"
egal "aucun rechargement quand rien ne change" "$(grep -c '^nmcli connection reload$' "$bac/appels")" "0"

monter_bac "$MAC"; poser_bouchons 3   # NetworkManager déclaré inactif
jouer >/dev/null 2>&1 || fail "run NM inactif en échec"
egal "aucun rechargement si NetworkManager ne tourne pas" "$(grep -c '^nmcli connection reload$' "$bac/appels")" "0"
[ -f "$bac/nm/fallback-${IFACE}.nmconnection" ] || fail "le profil doit être rendu même sans NetworkManager"
ok "le profil est rendu quand même — il sera lu au prochain démarrage"

# ============ 6bis. un profil au bon contenu mais au mauvais mode est réparé
# NetworkManager IGNORE un keyfile lisible par un non-root : sans réparation, le
# script dirait « already current » à chaque démarrage pendant que le secours
# n'existe pas.
echo "== 6bis. contenu identique, mode dérivé : le fichier est réparé =="
monter_bac "$MAC"; poser_bouchons 0
jouer >/dev/null 2>&1 || fail "premier rendu en échec"
profil="$bac/nm/fallback-${IFACE}.nmconnection"
empreinte="$(sha256sum "$profil" | cut -d' ' -f1)"
chmod 0644 "$profil"
: > "$bac/appels"
jouer >"$bac/log6b" 2>&1 || fail "run après dérive de mode en échec"
egal "mode réparé"                 "$(stat -c %a "$profil")" "600"
egal "contenu inchangé"            "$(sha256sum "$profil" | cut -d' ' -f1)" "$empreinte"
egal "NetworkManager re-prévenu"   "$(grep -c '^nmcli connection reload$' "$bac/appels")" "1"
grep -q "repaired link-local profile mode" "$bac/log6b" || fail "la réparation doit être journalisée"
ok "la réparation est dite explicitement"

# ==================== 7. une écriture qui échoue n'installe RIEN de tronqué
# Cette fonction est appelée à gauche d'un `||`, ce qui DÉSACTIVE errexit dans
# tout son corps : sans vérification explicite à chaque pas, un `cat` en échec
# tomberait jusqu'au `mv` et installerait un profil vide, journalisé comme rendu.
echo "== 7. un échec d'écriture ne laisse ni profil tronqué ni temporaire =="

compter_profils() { local f n=0; for f in "$bac"/nm/fallback-*; do [ -e "$f" ] && n=$((n+1)); done; printf '%d' "$n"; }


monter_bac "$MAC"
chmod 500 "$bac/nm"                       # plus de création possible dans le répertoire
jouer >"$bac/log7a" 2>&1 || fail "le script doit CONTINUER malgré l'échec du profil"
chmod 700 "$bac/nm"
egal "aucun profil installé"        "$(compter_profils)" "0"
egal "aucun temporaire laissé"      "$(find "$bac/nm" -name '*.tmp.*' | wc -l)" "0"
egal "le nom d'hôte est fait quand même" "$(cat "$bac/etc/hostname")" "ni-coreos-93b9"
grep -q "WARN" "$bac/log7a" || fail "l'échec doit être journalisé"
ok "l'échec est bruyant et non fatal"

echouer_sur() { # $1 = commande a faire echouer, $2 = condition sur \$1
  mkdir -p "$bac/bin"
  cat > "$bac/bin/$1" <<EOF
#!/bin/sh
case "\$1" in $2) exit 1 ;; esac
exec /usr/bin/$1 "\$@"
EOF
  chmod +x "$bac/bin/$1"
}

monter_bac "$MAC"; poser_bouchons 3; echouer_sur chmod '0600'
jouer >"$bac/log7b" 2>&1 || fail "le script doit continuer si chmod échoue"
egal "chmod en échec : aucun profil"   "$(compter_profils)" "0"
egal "chmod en échec : aucun temporaire" "$(find "$bac/nm" -name '*.tmp.*' | wc -l)" "0"

# Le vrai chemin appelle la dérivation sous `||`, donc SANS errexit : une erreur
# arithmétique n'arrête alors plus rien. C'est la garde explicite qui refuse, et
# c'est ici — pas en appelant la fonction directement — qu'on peut le voir.
monter_bac "zz:zz:zz:zz:zz:zz"; poser_bouchons 3
jouer >"$bac/log7d" 2>&1 || fail "un suffixe non hexadécimal ne doit pas faire échouer le script"
egal "suffixe non hexadécimal : aucun profil" "$(compter_profils)" "0"
egal "suffixe non hexadécimal : aucun temporaire" "$(find "$bac/nm" -name '*.tmp.*' | wc -l)" "0"
grep -q "WARN" "$bac/log7d" || fail "le refus doit être journalisé"
ok "le refus passe par la garde, pas par un hasard arithmétique"

monter_bac "$MAC"; poser_bouchons 3; echouer_sur mv '*'
jouer >"$bac/log7c" 2>&1 || fail "le script doit continuer si mv échoue"
egal "mv en échec : aucun profil"      "$(compter_profils)" "0"
egal "mv en échec : aucun temporaire"  "$(find "$bac/nm" -name '*.tmp.*' | wc -l)" "0"

# ================= 8. le retour au DHCP quand le secours tient l interface
# NetworkManager ne préempte JAMAIS une connexion active : `autoconnect` ne
# choisit qu'à périphérique libre, et `autoconnect-priority` ne fait qu'ordonner
# les candidats à cet instant. Sans mécanisme explicite, une appliance démarrée
# sans DHCP garde son adresse lien-local même quand un serveur apparaît.
RETRY=image/mdns/neural-ice-dhcp-retry.sh
[ -f "$RETRY" ] || fail "script de retour au DHCP introuvable : $RETRY"
echo "== 8. retour au DHCP =="

# Le one-shot reste disponible pour une action explicite, mais il ne doit pas
# être planifié : chaque tentative DHCP fait tomber le fallback pendant le
# timeout. Une appliance hors ligne garde donc son adresse sans interruption.
[ ! -e image/bootc-overlay/etc/systemd/system/neural-ice-dhcp-retry.timer ] || \
  fail "un timer DHCP disruptif ne doit pas être livré"
if sed -n '/systemctl enable/,/systemctl set-default/p' image/Containerfile.bootc \
  | grep -Fq 'neural-ice-dhcp-retry.timer'; then
  fail "le retry DHCP disruptif ne doit pas être activé dans l'image"
fi
ok "aucun retry DHCP périodique n'est livré ni activé"

rejouer_retry() {
  env NEURAL_ICE_NM_CONN_DIR="$bac/nm" NEURAL_ICE_SYS_NET="$bac/sys" \
      NEURAL_ICE_RUN_DIR="$bac/run" NEURAL_ICE_AVAHI_CONF="$bac/etc/avahi.conf" \
      NEURAL_ICE_HOSTNAME_INIT="$SCRIPT" PATH="$bac/bin:$PATH" \
      bash "$RETRY"
}

monter_bac "$MAC"; poser_bouchons 0
printf 'fallback-%s:%s\n' "$IFACE" "$IFACE" > "$bac/actives"
: > "$bac/appels"
rejouer_retry >"$bac/log8a" 2>&1 || fail "le retour au DHCP ne doit pas échouer"
egal "reconnexion demandée quand le secours tient" \
  "$(grep -c "^nmcli connection up mgmt-${IFACE}$" "$bac/appels")" "1"

printf 'mgmt-%s:%s\n' "$IFACE" "$IFACE" > "$bac/actives"
: > "$bac/appels"
rejouer_retry >"$bac/log8b" 2>&1 || fail "run avec DHCP actif en échec"
egal "aucune reconnexion quand le DHCP tient déjà" \
  "$(grep -c '^nmcli connection up' "$bac/appels")" "0"

# Le nom du profil se lit DANS le fichier, il n est pas supposé « mgmt-<iface> ».
sed -i "s/^id=mgmt-${IFACE}$/id=administration/" "$bac/nm/mgmt-${IFACE}.nmconnection"
printf 'fallback-%s:%s\n' "$IFACE" "$IFACE" > "$bac/actives"
: > "$bac/appels"
rejouer_retry >"$bac/log8c" 2>&1 || fail "run avec un id renommé en échec"
egal "le profil est nommé d après son fichier" \
  "$(grep -c '^nmcli connection up administration$' "$bac/appels")" "1"
sed -i "s/^id=administration$/id=mgmt-${IFACE}/" "$bac/nm/mgmt-${IFACE}.nmconnection"

# NetworkManager arrêté : rien du tout.
poser_bouchons 3
printf 'fallback-%s:%s\n' "$IFACE" "$IFACE" > "$bac/actives"
: > "$bac/appels"
rejouer_retry >"$bac/log8d" 2>&1 || fail "run NM arrêté en échec"
egal "aucune reconnexion si NetworkManager est arrêté" \
  "$(grep -c '^nmcli connection up' "$bac/appels")" "0"

# Le DHCP est toujours absent : l échec doit être dit, pas masqué.
poser_bouchons 0; touch "$bac/dhcp-absent"
printf 'fallback-%s:%s\n' "$IFACE" "$IFACE" > "$bac/actives"
rejouer_retry >"$bac/log8e" 2>&1 || fail "un échec de reconnexion ne doit pas faire échouer l unité"
grep -q "still no DHCP" "$bac/log8e" || fail "l échec de reconnexion doit être journalisé"
ok "un DHCP toujours absent est dit, et l unité sort proprement"
rm -f "$bac/dhcp-absent"

printf '\nPASS — %d contrôles\n' "$n"
