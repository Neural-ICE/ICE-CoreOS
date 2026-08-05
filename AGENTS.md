# AGENTS.md — ICE-CoreOS

> 🔴 **Ce fichier ne contient QUE du routage.** Architecture, décisions, missions, écarts, état —
> tout vit dans le vault Obsidian. **Ne rien recopier ici : cela se périmerait en silence, et une
> session ferait confiance à la copie.**

## Avant d'écrire une ligne de code

Racine du vault : `/data/github/@Neural-ICE_Dev/ICE-Obsidian/Neural-ICE_Dev/`

| Lire | Chemin, relatif à cette racine |
|---|---|
| **Le point d'entrée agent** — catalogue de tout | `index.md` |
| Le schéma qui gouverne l'ensemble | `AGENTS.md` |
| **Ce repo** — état vérifié, pièges, contrats | `wiki/composants/ice-coreos.md` |
| **Les écarts ouverts** sur ce périmètre | `wiki/ecarts/` — filtrer sur `repos: [ICE-CoreOS]` |
| **Les décisions qui contraignent** | `wiki/decisions/index-adr.md` |
| **Ce qui tourne ailleurs en ce moment** | `wiki/missions/chantiers-en-cours.md` |

> **C'est ce qui manquait** : une session ouverte ici n'avait aucun accès aux missions, à
> l'architecture ni aux décisions — d'où l'incohérence entre sessions.

## Les deux règles dures

**1 · 🔒 Avant de coder — prendre sa zone.**
Lire `/data/github/@Neural-ICE_Dev/raw_mission_report_to_ingest/`.
Si un `ZONE-*.claim.md` couvre tes fichiers, **s'arrêter** — la collision se juge **au fichier**, pas
au repo. Sinon, y **poser le tien** (`ZONE-<goal>-<session>.claim.md`), et le **supprimer à la fin**.

**2 · 🔴 Ne JAMAIS écrire dans le vault Obsidian.**
À la fin, déposer un rapport dans `/data/github/@Neural-ICE_Dev/raw_mission_report_to_ingest/` :
ce qui est **livré** (commit, branche, PR) · les **preuves** (commande exacte + sortie) · **ce qui
n'est PAS fait et pourquoi** · les **écarts** rencontrés · les **décisions prises faute d'arbitrage**.
**Nom de fichier et gabarit exact : le `README.md` de ce répertoire** — ne pas les deviner, ils
portent une contrainte d'unicité par session.

> **Un rapport propose la clôture, il ne la prononce pas.** Le vault est intégré par une seule
> instance, **après vérification du code**. Le niveau V1/V2 **se prouve, il ne se déclare pas**.

Format et gabarits : `raw_mission_report_to_ingest/README.md`.
Doctrine : `wiki/how-to/how-to-agents-md-minimal-et-rapports-de-mission.md`.
