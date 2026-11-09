# Sous-domaine du formulaire et retrait du module

Le module utilise un seul lien commun à tous les RS. L'administration reste sur
le staging ; le sous-domaine expose uniquement le formulaire et ses deux actions
(recherche de sections et création). Les comptes sont créés dans la base du staging.

## Mise en service

1. Dans le DNS de `abservesmart.com`, créer `creation` comme CNAME vers
   `staging.abservesmart.com` (ou un A vers l'adresse actuelle du VPS).
2. Sur le VPS, créer un site HTTPS pour `creation.abservesmart.com` avec un
   certificat couvrant ce nom. Utiliser le gestionnaire web/certificats déjà en
   place. Il ne faut pas rediriger ce site vers l'accueil du staging.
3. Acheminer les chemins du formulaire vers le même processus Django que le
   staging, en conservant le Host `creation.abservesmart.com`. Si le serveur
   utilise Nginx, le fichier `nginx.locations.conf.example` fournit les règles à
   placer dans ce nouveau site HTTPS. Adapter l'upstream à celui du staging :
   son port ou socket n'est pas connu depuis ce dépôt. Ne pas remplacer la
   configuration du site staging. Vérifier la configuration avant rechargement.
4. Dans la configuration privée du processus Django (pas dans Git), ajouter :

   ```dotenv
   CLIENT_ACCOUNTS_ENABLED=1
   CLIENT_ACCOUNTS_PUBLIC_HOST=creation.abservesmart.com
   ```

   Ajouter aussi `creation.abservesmart.com` à `DJANGO_ALLOWED_HOSTS` en conservant
   les noms déjà autorisés. Le paramètre PUBLIC_HOST contient seulement le nom
   d'hôte, sans `https://`, chemin ni port. Ne le définir qu'une fois DNS et HTTPS
   prêts : les anciens liens sur le domaine staging seront alors refusés.

5. Récupérer la version du dépôt staging, exécuter `python manage.py migrate`
   dans l'environnement Python du site, puis redémarrer le processus Django.
   Conserver les réglages existants de reconnaissance HTTPS derrière le proxy.
6. Dans l'administration du staging, activer le module si nécessaire et copier
   le lien affiché. Il doit commencer par `https://creation.abservesmart.com/`.

La migration vers le lien commun désactive les anciens modules par société sans
supprimer les comptes créés. Le nouveau module démarre désactivé.

## Vérification après déploiement

- En navigation privée, le lien valide affiche le formulaire sans connexion ni menu.
- La recherche retrouve les vraies sections ; après création, seul le username
  apparaît dans la confirmation.
- Sur `creation.abservesmart.com`, `/`, `/login/`, `/admin/`, `/administration/`,
  `/profile/` et `/creation-comptes-clients/` retournent 404, même avec une session
  admin préexistante. Aucun droit de connexion n'est donné au visiteur.
- Les URLs `/creer-compte/...` sur le domaine staging retournent 404 une fois
  PUBLIC_HOST configuré. La gestion du module reste accessible aux admins sur staging.
- Désactiver le module bloque le lien, y compris les recherches et envois depuis
  un formulaire déjà ouvert. Une réactivation génère un nouveau lien.

## Si le responsable refuse

Cette procédure est préparée ; elle n'est pas exécutée tant que le retrait n'est
pas demandé.

1. Désactiver le module dans l'administration : son lien est révoqué immédiatement.
2. Mettre `CLIENT_ACCOUNTS_ENABLED=0` dans la configuration privée et redémarrer
   Django. Toutes les entrées du module retournent alors 404 ; ses entrées dans
   le menu et l'accueil disparaissent. Le reste du logiciel continue à fonctionner.
3. Retirer uniquement le site web `creation.abservesmart.com`, son enregistrement
   DNS et, s'il est dédié à ce nom seul, son certificat et sa tâche de renouvellement.
   Ne pas retirer un certificat partagé avec staging ni l'upstream de staging.
4. Pour supprimer définitivement le code, préparer un commit ciblé retirant
   `client_accounts/`, le template `templates/essai-comptes-clients.html`, les
   intégrations correspondantes dans `settings.py`, `urls.py`, le menu et l'accueil.
   Ne pas revenir à un ancien état complet du dépôt : cela pourrait rétablir des
   corrections de sécurité annulées ou écraser des changements sans rapport.
5. Les comptes créés sont des utilisateurs ordinaires et doivent être conservés.
   Les tables propres au module gardent toutefois leurs matricules et l'historique
   des créations. Avant de supprimer ces tables, choisir explicitement si ces
   informations doivent être archivées ou transférées. Un archivage contenant des
   données clients reste privé et hors du dépôt. Une suppression des tables se fait
   ensuite, avant de retirer l'app de Django, avec une migration de retrait validée.

Le réglage ENABLED=0 est un arrêt réversible ; il ne prétend pas supprimer les
fichiers ou les données. Le retrait définitif est distinct et ne supprime pas les
comptes, sociétés ou sections existants.

Référence du proxy : [documentation officielle Nginx](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass).
