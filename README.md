# AppleVault

AppleVault est une application macOS pour organiser une collection d’appareils Apple : fiches détaillées, réparations, statistiques, profils locaux, affichage plein écran et sauvegardes.

## Télécharger l’application

La version de test la plus récente est publiée sur [GitHub Releases](https://github.com/yanisbouziou/AppleVault/releases/latest). Elle s’installe sans Xcode.

1. Télécharge le fichier ZIP de la version voulue et décompresse-le.
2. Glisse `AppleVault.app` dans le dossier **Applications** et remplace l’ancienne version si macOS le propose.
3. Si macOS bloque l’ouverture, fais un Ctrl-clic sur AppleVault.app, choisis **Ouvrir**, puis confirme.

Les versions publiques actuelles ne possèdent pas de certificat Apple Developer ID et ne sont pas notarisées. macOS peut afficher un avertissement au premier lancement.

## Sauvegarder la collection avant une mise à jour

Les profils et les collections sont enregistrés localement dans le dossier Application Support d’AppleVault. Remplacer l’application dans **Applications** ne supprime pas ces données. Pour garder une copie séparée avant une mise à jour :

1. Ouvre AppleVault et sélectionne le profil à sauvegarder.
2. Dans la barre d’outils, ouvre le menu **Sauvegarde** puis choisis **Créer une sauvegarde JSON…**.
3. Choisis un emplacement sûr, par exemple une clé USB ou un dossier iCloud Drive, et enregistre le fichier.

Répète l’opération pour chaque profil à conserver. Le JSON contient les fiches de la collection. Les photos et documents associés sont conservés séparément dans les données locales d’AppleVault ; ne supprime pas ces données lors d’une mise à jour.

## Restaurer une sauvegarde après la mise à jour

En général, la collection réapparaît automatiquement après remplacement de l’application. Si elle n’apparaît pas :

1. Dans AppleVault, sélectionne le **même profil** que celui qui a été sauvegardé.
2. Dans la barre d’outils, ouvre **Sauvegarde** puis choisis **Restaurer depuis un fichier JSON…**.
3. Sélectionne le fichier JSON sauvegardé avant la mise à jour.

L’import ajoute les appareils absents et remplace les fiches qui ont le même identifiant. Vérifie que le bon profil est sélectionné avant l’import. Les photos et documents sont des fichiers séparés ; ils restent disponibles si les données locales d’AppleVault n’ont pas été supprimées.

## Menu développeur

Le code développeur `3343` fonctionne uniquement dans une compilation **Debug** lancée depuis Xcode. Il n’est pas inclus dans la version publique téléchargée depuis GitHub.

1. Ouvre `AppleVault.xcodeproj` dans Xcode, sélectionne le schéma **AppleVault** et lance l’application avec **▶︎** ou `⌘R` (la configuration Run par défaut est Debug).
2. Dans AppleVault, ouvre le menu **Sauvegarde** dans la barre d’outils et choisis **Verrouiller AppleVault**.
3. Sur l’écran de verrouillage, saisis `3343` dans le champ du mot de passe puis clique **Déverrouiller**.
4. Pour quitter, utilise **Quitter et reverrouiller** dans le menu développeur.

Le menu développeur affiche des diagnostics et outils de maintenance. Le code ne remplace pas le mot de passe du profil pour déverrouiller la collection.

## Données et réseau

Les profils et les collections restent sur ce Mac. Les mots de passe de profils et les notes privées utilisent le trousseau macOS. Aucune synchronisation de compte n’est configurée. La météo utilise Open-Meteo. Le vérificateur de versions consulte les releases publiques de ce dépôt GitHub ; il fournit un lien de téléchargement, mais ne télécharge ni n’installe les mises à jour automatiquement.

## Projet Xcode

Le code source est aussi disponible dans ce dépôt. Pour le modifier, ouvre `AppleVault.xcodeproj` dans Xcode. Le projet cible macOS 15.8 ou ultérieur.

## Licence

Le dépôt est public pour consulter le code. Aucune licence de réutilisation n’est définie pour le moment.
