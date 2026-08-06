import express from 'express'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import dotenv from 'dotenv'
import nodemailer from 'nodemailer'

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3000
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`
const REVOLUT_API_BASE = process.env.REVOLUT_API_BASE || 'https://merchant.revolut.com'
const REVOLUT_API_VERSION = process.env.REVOLUT_API_VERSION || '2025-12-04'
const PRICE_EUR_CENTS = Number(process.env.PRICE_EUR_CENTS || 500)

const DATA_DIR = path.join(__dirname, 'data')
const DB_FILE = path.join(DATA_DIR, 'db.json')
fs.mkdirSync(DATA_DIR, { recursive: true })

// ─── DB ──────────────────────────────────────────────────────────────────────

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { orders: [], accesses: [] }
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2))
    return initial
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))
}

function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2))
}

// ─── UTILS ───────────────────────────────────────────────────────────────────

function uid(size = 24) {
  return crypto.randomBytes(size).toString('hex')
}

function hmacSha256(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex')
}

function safeCompare(a, b) {
  try {
    const aBuf = Buffer.from(a)
    const bBuf = Buffer.from(b)
    if (aBuf.length !== bBuf.length) return false
    return crypto.timingSafeEqual(aBuf, bBuf)
  } catch {
    return false
  }
}

function verifyRevolutWebhook(rawBody, timestamp, signatureHeader, signingSecret) {
  if (!timestamp || !signatureHeader || !signingSecret) return false

  const ts = Number(timestamp)
  if (!Number.isFinite(ts)) return false

  // Rejette les webhooks de plus de 5 minutes
  if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) return false

  const payloadToSign = `v1.${timestamp}.${rawBody}`
  const expected = `v1=${hmacSha256(signingSecret, payloadToSign)}`

  return String(signatureHeader)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .some(sig => safeCompare(sig, expected))
}

function createAccess(db, internalRef) {
  // Si un accès actif existe déjà pour cette commande, on le retourne
  const existing = db.accesses.find(
    a => a.orderId === internalRef && a.status === 'active' && new Date(a.expiresAt) > new Date()
  )
  if (existing) return existing

  const access = {
    id: uid(12),
    orderId: internalRef,
    token: uid(24),
    status: 'active',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString()
  }

  db.accesses.push(access)
  saveDb(db)
  return access
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://iadiy.fr')
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

app.use('/public', express.static(path.join(__dirname, 'public')))
app.use(express.urlencoded({ extended: false }))

// Le webhook Revolut nécessite le raw body pour vérifier la signature
// → on le monte AVANT express.json()
app.post('/api/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  const signingSecret = process.env.REVOLUT_WEBHOOK_SECRET
  const timestamp = req.headers['revolut-request-timestamp']
  const signature = req.headers['revolut-signature']
  const rawBody = req.body.toString('utf8')

  console.log('WEBHOOK reçu :', rawBody)

  // Vérification de signature (désactivable en dev avec SKIP_WEBHOOK_VERIFY=true)
  if (process.env.SKIP_WEBHOOK_VERIFY !== 'true') {
    if (!verifyRevolutWebhook(rawBody, timestamp, signature, signingSecret)) {
      console.warn('Webhook : signature invalide')
      return res.status(401).json({ error: 'Signature invalide' })
    }
  }

  let event
  try {
    event = JSON.parse(rawBody)
  } catch {
    return res.status(400).json({ error: 'JSON invalide' })
  }

  // On ne traite que ORDER_COMPLETED
  if (event.event !== 'ORDER_COMPLETED') {
    return res.json({ ok: true, ignored: true })
  }

  const revolutOrderId = event.order_id
  const db = loadDb()
  const order = db.orders.find(o => o.revolutOrderId === revolutOrderId)

  if (!order) {
    console.warn('Webhook : commande introuvable pour', revolutOrderId)
    // On répond 200 pour que Revolut ne retente pas
    return res.json({ ok: true, warning: 'commande introuvable' })
  }

  if (order.status === 'completed') {
    return res.json({ ok: true, already: true })
  }

  // Marquer la commande comme complétée
  order.status = 'completed'
  order.completedAt = new Date().toISOString()

  // Créer l'accès 24h
  const access = createAccess(db, order.internalRef)
  console.log('Accès créé :', access.token, 'expire :', access.expiresAt)

  return res.json({ ok: true })
})

// express.json() pour toutes les autres routes
app.use(express.json())
// ─── IDENTIFICATION (email + code à usage unique) ─────────────────────────────

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
})

function ensureAuthTables(db) {
  if (!db.utilisateurs) db.utilisateurs = []
  if (!db.codesVerification) db.codesVerification = []
  if (!db.sessions) db.sessions = []
  return db
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000))
}

app.post('/api/request-code', async (req, res) => {
  const contact = String(req.body?.contact || '').trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact)) {
    return res.status(400).json({ error: 'Adresse email invalide' })
  }

  const db = ensureAuthTables(loadDb())

  const recent = db.codesVerification
    .filter(c => c.contact === contact)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0]
  if (recent && (Date.now() - new Date(recent.createdAt).getTime()) < 60 * 1000) {
    return res.status(429).json({ error: 'Merci de patienter avant de redemander un code' })
  }

  const code = generateCode()
  db.codesVerification.push({
    contact, code, utilise: false, tentatives: 0,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
  })
  saveDb(db)

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'IADIY <no-reply@iadiy.fr>',
      to: contact,
      subject: `Votre code de connexion IADIY : ${code}`,
      text: `Votre code est ${code}. Il expire dans 10 minutes.`
    })
  } catch (err) {
    console.error('Erreur envoi email :', err)
    return res.status(500).json({ error: "Impossible d'envoyer l'email" })
  }

  return res.json({ ok: true })
})

app.post('/api/verify-code', (req, res) => {
  const contact = String(req.body?.contact || '').trim().toLowerCase()
  const code = String(req.body?.code || '').trim()
  if (!contact || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Requête invalide' })
  }

  const db = ensureAuthTables(loadDb())
  const entry = db.codesVerification
    .filter(c => c.contact === contact && !c.utilise)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0]

  if (!entry) return res.status(400).json({ error: 'Aucun code en attente' })
  if (new Date(entry.expiresAt) < new Date()) return res.status(400).json({ error: 'Code expiré' })
  if (entry.tentatives >= 5) return res.status(429).json({ error: 'Trop de tentatives' })

  if (entry.code !== code) {
    entry.tentatives += 1
    saveDb(db)
    return res.status(400).json({ error: 'Code incorrect' })
  }

  entry.utilise = true

  let user = db.utilisateurs.find(u => u.contact === contact)
  if (!user) {
    user = { id: uid(8), contact, createdAt: new Date().toISOString() }
    db.utilisateurs.push(user)
  }

  const session = {
    token: uid(24), userId: user.id,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  }
  db.sessions.push(session)
  saveDb(db)

  return res.json({ ok: true, token: session.token, user: { id: user.id, contact: user.contact } })
})

// ─── ROUTES ───────────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

app.get('/acces-iadi', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'acces-iadi.html'))
})

// Crée une commande Revolut et retourne l'URL de paiement
app.post('/api/create-order', async (req, res) => {
  try {
    const secret = process.env.REVOLUT_SECRET_API_KEY
    if (!secret) {
      return res.status(500).json({ error: 'REVOLUT_SECRET_API_KEY manquante' })
    }

    const internalRef = uid(10)
    const successUrl = `${APP_BASE_URL}/acces-iadi?order_ref=${internalRef}`

    const payload = {
      amount: PRICE_EUR_CENTS,
      currency: 'EUR',
      description: 'Accès IADIY 24h',
      redirect_url: successUrl,
      merchant_order_ext_ref: internalRef,
      metadata: {
        reference: internalRef,
        product: 'iadiy-24h'
      }
    }

    console.log('CREATE ORDER → successUrl:', successUrl)

    const response = await fetch(`${REVOLUT_API_BASE}/api/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${secret}`,
        'Revolut-Api-Version': REVOLUT_API_VERSION
      },
      body: JSON.stringify(payload)
    })

    // FIX : on parse toujours en JSON (plus de .text() qui bloque)
    const data = await response.json().catch(() => ({}))
    console.log('REVOLUT STATUS =', response.status, '| RESPONSE =', data)

    if (!response.ok) {
      return res.status(500).json({ error: 'Échec création commande Revolut', details: data })
    }

    const db = loadDb()
    db.orders.push({
      internalRef,
      revolutOrderId: data.id,
      publicId: data.public_id || null,
      checkoutUrl: data.checkout_url || null,
      status: data.state || 'pending',
      createdAt: new Date().toISOString()
    })
    saveDb(db)

    return res.json({
      ok: true,
      checkout_url: data.checkout_url,
      order_id: data.id,
      internal_ref: internalRef
    })
  } catch (error) {
    console.error('create-order crash:', error)
    return res.status(500).json({ error: 'Erreur serveur create-order' })
  }
})

// Appelé par /acces-iadi après redirection Revolut
// Revolut redirige vers /acces-iadi?order_ref=xxx
// Cette route vérifie le statut et retourne le token si c'est payé
app.get('/api/resolve-order', (req, res) => {
  const { order_ref } = req.query
  if (!order_ref) return res.status(400).json({ error: 'order_ref manquant' })

  const db = loadDb()
  const order = db.orders.find(o => o.internalRef === order_ref)

  if (!order) return res.status(404).json({ error: 'Commande introuvable' })

  if (order.status !== 'completed') {
    // Le webhook n'est peut-être pas encore arrivé → on interroge Revolut directement
    // pour éviter une mauvaise expérience utilisateur
    return res.status(202).json({ status: 'pending', message: 'Paiement en cours de confirmation' })
  }

  const access = db.accesses.find(
    a => a.orderId === order_ref && a.status === 'active' && new Date(a.expiresAt) > new Date()
  )

  if (!access) return res.status(403).json({ error: 'Aucun accès actif trouvé' })

  return res.json({
    ok: true,
    token: access.token,
    expiresAt: access.expiresAt
  })
})

// Vérifie un token d'accès (appelé par Botpress ou acces-iadi.html)
app.get('/api/verify-access', (req, res) => {
  const { token } = req.query
  if (!token) return res.status(400).json({ error: 'Token manquant' })

  const db = loadDb()
  const access = db.accesses.find(a => a.token === token)

  if (!access) return res.status(403).json({ error: 'Accès refusé' })
  if (access.status !== 'active') return res.status(403).json({ error: 'Accès expiré' })

  if (new Date(access.expiresAt).getTime() < Date.now()) {
    access.status = 'expired'
    saveDb(db)
    return res.status(403).json({ error: 'Accès expiré' })
  }

  return res.json({ ok: true, expiresAt: access.expiresAt })
})

// ─── DEV ONLY ─────────────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== 'production') {
  app.get('/dev-access', (req, res) => {
    const db = loadDb()
    const internalRef = 'dev-' + uid(5)
    const access = createAccess(db, internalRef)
    res.send(`
      <p>Token de test créé (24h) :</p>
      <a href="/acces-iadi?token=${access.token}">
        ${APP_BASE_URL}/acces-iadi?token=${access.token}
      </a>
    `)
  })

  // Simule un webhook ORDER_COMPLETED pour tester sans vrai paiement
  app.post('/dev-webhook', (req, res) => {
    const { order_ref } = req.body
    const db = loadDb()
    const order = db.orders.find(o => o.internalRef === order_ref)
    if (!order) return res.status(404).json({ error: 'Order not found' })
    order.status = 'completed'
    order.completedAt = new Date().toISOString()
    const access = createAccess(db, order.internalRef)
    res.json({ ok: true, token: access.token, expiresAt: access.expiresAt })
  })
}

// ─── START ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✅ IADIY server running on ${APP_BASE_URL}`)
})
