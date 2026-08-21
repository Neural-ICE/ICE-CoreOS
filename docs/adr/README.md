# ADR — où lire les décisions de la constellation

> **Le corpus canonique des ADR est le vault Obsidian**, pas ce répertoire.

```
/data/github/@Neural-ICE_Dev/ICE-Obsidian/Neural-ICE_Dev/wiki/decisions/
```

Inventaire complet, statuts, état runtime et amendements : **`index-adr.md`** dans ce répertoire.

## ⚠️ Les ADR de ce dépôt vivent à DEUX endroits

C'est un rangement historique incohérent, pas une distinction de sens :

| Emplacement | Contenu |
|---|---|
| **`docs/ADR-*.md`** (répertoire parent) | **11 ADR** — `ADR-0002` … `ADR-0013`. Secure Boot, LUKS/TPM, canaux, kernel 4k, licence FSL, multi-arch, enveloppe GB10, identité bootc, état OTA atomique, racine TPM |
| **`docs/adr/ADR-*.md`** (ici) | **3 ADR** — `ADR-0041` (firmware GSP), `ADR-0042` (pilote R580), `ADR-0043` (console KMS/vconsole) |

Les deux jeux sont indexés sous le préfixe `OS-` dans le vault.

## La convention de préfixe — et une collision à connaître

Trois dépôts numérotent leurs ADR **indépendamment à partir de 0001**. Un « ADR-0004 » nu est
ambigu : *chiffrement disque TPM+LUKS* ici, *packaging de l'IP runtime* dans ICE-Fabric.

| Préfixe | Dépôt | Fichier du vault |
|---|---|---|
| `OS-00XX` | **ICE-CoreOS** (ce dépôt) | `adr-os-00XX-<slug>.md` |
| `FAB-00XX` | ICE-Fabric | `adr-fab-00XX-<slug>.md` |
| `ADM-000X` | ICE-Admin | `adr-adm-000X-<slug>.md` |

**Écrivez `OS-0004`, jamais `ADR-0004`.** Quand vous citez un ADR d'un autre dépôt, **nommez le
dépôt** — la forme qu'emploient déjà `docs/ADR-0012` et `docs/ADR-0013` :
`- Related: ADR-0004, ADR-0012; ICE-Fabric ADR-0039`.

> 🔴 **`OS-0043` est actuellement attribué DEUX FOIS.** `ADR-0043-gb10-console-kms-vconsole.md`
> (ici, décidé le 2026-07-29, fusionné le 2026-08-20) et une page **native du vault** du 2026-08-04
> sur le média d'installation scindé. Le vault les distingue par leur *slug*
> (`adr-os-0043-console-kms-vconsole` vs `adr-os-0043-media-installation-scinde`) en attendant un
> arbitrage Owner. **Ne réutilisez pas `0043`.**

## ⚠️ Pourquoi les fichiers `ADR-*.md` sont TOUJOURS ici

Deux raisons, et la seconde est propre à ce dépôt.

**1 — La copie vers le vault est incomplète.** Mesuré le 2026-08-21 : `ADR-0012-atomic-ota-state-v1.md`
fait 267 lignes, sa page de vault 86, avec `couverture-lecture: "40/267"`. Décision Owner du
2026-08-04 : *« la suppression suit la preuve de lecture, elle ne la précède pas »*.

**2 — 🔴 ICE-CoreOS est le SEUL dépôt public de Neural ICE** (open-core, `FAB-0032` ; amendement de
visibilité Owner du 2026-07-31). **Ses ADR font partie de l'artefact ouvert.** Les déplacer dans un
vault privé retirerait la justification de conception d'un dépôt public — *« une décision de
positionnement, pas de rangement »*, et **elle n'est pas tranchée.**

> **Donc : ces fichiers restent le texte intégral de la décision, et rien ne dit qu'ils doivent
> partir.** Le vault en porte la version alignée, avec l'état runtime et les liens transverses.

## Écrire un nouvel ADR

Les décisions **transverses** vont dans `ICE-Fabric/docs/adr/`. Ne créez un ADR ici que pour une
décision **propre à l'OS** (boot, kernel, chiffrement, bootc, initramfs, firmware).

⚠️ **Vérifiez le numéro contre les DEUX** : le plus haut sur `origin/main` **et** les numéros
**réservés** par un brouillon ou une PR non fusionnée. `origin/main` seul ne suffit pas — c'est
exactement comme ça que `OS-0043` s'est retrouvé attribué deux fois. Le prochain libre est `0044`,
sous réserve du brouillon `ADR-DRAFT-os-0044-*` déposé dans `raw_mission_report_to_ingest/`.

Déposez ensuite un rapport dans `raw_mission_report_to_ingest/` pour que le vault l'intègre — une
session **dépose**, elle n'écrit jamais dans le vault.
