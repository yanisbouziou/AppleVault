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

1. Ouvre AppleVault, puis **Réglages > Données**.
2. Vérifie que **Enregistrer la collection sur ce Mac** et **Créer des sauvegardes automatiques** sont activés.
3. Sélectionne le profil à sauvegarder, puis clique **Afficher le dossier des sauvegardes…**.
4. Copie le fichier `.json` le plus récent commençant par `AppleVault-` vers un endroit sûr, par exemple une clé USB ou un dossier iCloud Drive.

Chaque profil a son propre dossier de sauvegardes. Le JSON contient les fiches de la collection. Les photos et documents associés sont conservés séparément dans les données locales d’AppleVault ; ne supprime pas ces données lors d’une mise à jour.

## Restaurer une sauvegarde après la mise à jour

En général, la collection réapparaît automatiquement après remplacement de l’application. Si elle n’apparaît pas :

1. Dans AppleVault, sélectionne le **même profil** que celui qui a été sauvegardé.
2. Ouvre **Réglages > Données**.
3. Si la sauvegarde n’est pas déjà dans la liste **Restaurer une ancienne sauvegarde**, clique **Afficher le dossier des sauvegardes…** et copie le fichier `.json` sauvegardé dans ce dossier.
4. Ferme puis rouvre Réglages. Sous **Restaurer une ancienne sauvegarde**, choisis le bon fichier et clique **Restaurer**.
5. Confirme l’action. La collection actuelle du profil sélectionné sera remplacée par le contenu de cette sauvegarde.

## Données et réseau

Les profils et les collections restent sur ce Mac. Les mots de passe de profils et les notes privées utilisent le trousseau macOS. Aucune synchronisation de compte n’est configurée. La météo utilise Open-Meteo. Le vérificateur de versions consulte les releases publiques de ce dépôt GitHub ; il fournit un lien de téléchargement, mais ne télécharge ni n’installe les mises à jour automatiquement.

## Projet Xcode

Le code source est aussi disponible dans ce dépôt. Pour le modifier, ouvre `AppleVault.xcodeproj` dans Xcode. Le projet cible macOS 15.8 ou ultérieur.

## Licence

Le dépôt est public pour consulter le code. Aucune licence de réutilisation n’est définie pour le moment.
