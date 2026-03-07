# Change Log

## [1.1] - 2026-03-06
### Ajoutés
- Export des résultats en CSV
- Barre de progression pendant le scan de dossiers
- Détection explicite du quota API (erreur 403)
- Try/Catch robuste dans la boucle de scan

### Corrigés
- Espaces supprimés dans `$script:BaseUrl` (erreur 400)
- Trim() sur les URLs utilisateur
- Nettoyage contenu markdownlint.json du script

## [1.0] - 2026-03-05
- Version initiale avec scanner fichiers/dossiers/URLs/hash
