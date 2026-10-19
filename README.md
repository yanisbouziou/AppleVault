# AppleVault

AppleVault est une application macOS pour organiser une collection d’appareils Apple : fiches détaillées, réparations, statistiques, profils locaux, inventaire guidé, affichage plein écran et sauvegardes.

## Ouvrir le projet

Cette version contient le **projet source Xcode** ; ce n’est pas encore une application `.app` prête à télécharger.

1. Télécharge le dépôt ou clone-le avec Git.
2. Ouvre `AppleVault.xcodeproj` dans Xcode.
3. Choisis le schéma **AppleVault** et lance l’application avec le bouton ▶︎.

Le projet cible macOS 15.8 ou ultérieur et nécessite Xcode.

## Données et réseau

Les profils et les collections sont enregistrés localement dans le dossier Application Support d’AppleVault. Les mots de passe des profils sont protégés par le trousseau macOS. Aucune synchronisation de compte n’est configurée.

La météo utilise Open-Meteo et le service de géocodage Open-Meteo. Les images distantes ne sont chargées que si une fiche contient une adresse d’image. Le serveur de mises à jour n’est pas configuré par défaut.

## État du projet

AppleVault est un projet en développement. Les versions publiées ici sont des sources à ouvrir dans Xcode ; aucune version signée, notarizée ou distribuée par l’App Store n’est fournie pour le moment.

Le mode développeur sert au développement local et n’est activé que dans une compilation Debug.

## Licence

Le dépôt est public pour consulter le code. Aucune licence de réutilisation n’est définie pour le moment.
