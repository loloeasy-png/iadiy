# IADIY – vraie solution accès 24h

## Ce que fait ce projet
- crée une vraie commande Revolut côté serveur
- redirige vers le checkout Revolut
- reçoit le webhook Revolut
- vérifie la signature du webhook
- crée un accès valable 24h
- affiche le chatbot uniquement si l’accès est valide

## Fichiers
- `server.js` : backend Express
- `public/index.html` : page vente
- `public/acces-iadi.html` : page accès privée
- `.env.example` : variables à remplir

## Installation
```bash
npm install
cp .env.example .env
npm start
```

## Variables à remplir
Dans `.env` :
- `APP_BASE_URL=https://tondomaine.com`
- `REVOLUT_SECRET_API_KEY=...`
- `REVOLUT_WEBHOOK_SIGNING_SECRET=...`
- `BOTPRESS_BOT_ID=...`
- `BOTPRESS_CLIENT_ID=...`

## Mise en ligne
- héberge ce projet sur un Node.js server
- configure OVH pour pointer vers ton hébergement
- dans Revolut, crée le webhook vers :
  `https://tondomaine.com/api/revolut-webhook`

## Ce que tu dois faire dans Botpress
Dans `public/acces-iadi.html`, remplace :
- `REPLACE_BOT_ID`
- `REPLACE_CLIENT_ID`

## Ce que tu dois faire dans Revolut
Ton backend crée une commande et met un `redirect_url`. Revolut recommande un backend qui crée l’ordre, récupère `checkout_url`, puis suit le statut via webhook. La redirection seule ne suffit pas pour la logique métier ; il faut aussi vérifier le statut côté serveur et utiliser les webhooks. citeturn442053view2turn643844search2turn962771view0

## Sécurité webhook
La signature du webhook doit être vérifiée avec HMAC SHA-256 à partir de :
`v1.{Revolut-Request-Timestamp}.{raw-payload}`
et il faut aussi contrôler une tolérance d’environ 5 minutes sur l’horodatage. citeturn962771view0

## Botpress
La page d’accès privée affiche le chatbot dans un élément HTML dédié. Botpress documente ce mode `Embedded` avec un `Element ID` spécifique. citeturn804763view3

## Important
Ce projet met la vraie logique 24h.
Ce qui reste à faire :
- déployer
- remplir les clés
- enregistrer le webhook Revolut
