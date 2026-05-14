import express from 'express'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import dotenv from 'dotenv'

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

function uid(size = 24) {
  return crypto.randomBytes(size).toString('hex')
}

function hmacSha256(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex')
}

function safeCompare(a, b) {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

function verifyRevolutWebhook(rawBody, timestamp, signatureHeader, signingSecret) {
  if (!timestamp || !signatureHeader || !signingSecret) return false

  const now = Date.now()
  const ts = Number(timestamp)
  if (!Number.isFinite(ts)) return false

  const age = Math.abs(now - ts)
  if (age > 5 * 60 * 1000) return false

  const signatures = String(signatureHeader)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)

  const payloadToSign = `v1.${timestamp}.${rawBody}`
  const expected = `v1=${hmacSha256(signingSecret, payloadToSign)}`

  return signatures.some(sig => safeCompare(sig, expected))
}

function findOrderByInternalRef(db, internalRef) {
  return db.orders.find(o => o.internalRef === internalRef)
}

function findOrderByRevolutId(db, revolutOrderId) {
  return db.orders.find(o => o.revolutOrderId === revolutOrderId)
}

function createAccess(db, order) {
  const existing = db.accesses.find(a => a.orderId === order.internalRef && a.status === 'active')
  if (existing) return existing

  const token = uid(24)
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()

  const access = {
    id: uid(12),
    orderId: order.internalRef,
    token,
    status: 'active',
    createdAt: new Date().toISOString(),
    expiresAt
  }

  db.accesses.push(access)
  saveDb(db)
  return access
}

app.use('/public', express.static(path.join(__dirname, 'public')))
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

app.get('/acces-iadi', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'acces-iadi.html'))
})

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
      description: 'Accès IADI 24h',
      redirect_url: successUrl,
      merchant_order_ext_ref: internalRef,
      metadata: {
        reference: internalRef,
        product: 'iadi-24h'
      }
    }
console.log('SECRET OK =', !!secret)
console.log('SUCCESS URL =', successUrl)
console.log('APP_BASE_URL =', APP_BASE_URL)
console.log('PAYLOAD =', payload)
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
    const text = await response.text()
console.log('REVOLUT STATUS =', response.status)
console.log('REVOLUT RAW =', text)

    if (!response.ok) {
      console.error('Revolut create-order error:', data)
      return res.status(500).json({
        error: 'Erreur création paiement Revolut',
        details: data
      })
    }

    const db = loadDb()
    db.orders.push({
      internalRef,
      revolutOrderId: data.id,
      publicId: data.public_id || null,
      checkoutUrl: data.checkout_url || null,
      status: data.state || 'created',
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
    console.error(error)
    return res.status(500).json({ error: 'Erreur serveur create-order' })
  }
})

app.get('/api/verify-access', (req, res) => {
  const { token } = req.query
  const db = loadDb()

  const access = db.accesses.find(a => a.token === token)

  // ❌ pas trouvé
  if (!access) {
    return res.status(403).json({ error: "Accès refusé" })
  }

  // ❌ pas actif
  if (access.status !== 'active') {
    return res.status(403).json({ error: "Accès expiré" })
  }

  // ❌ expiré dans le temps
  if (new Date(access.expiresAt).getTime() < Date.now()) {
    access.status = 'expired'
    saveDb(db)
    return res.status(403).json({ error: "Accès expiré" })
  }

  // ✅ OK
  return res.json({
    success: true,
    expiresAt: access.expiresAt
  })
})

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
      description: 'Accès IADI 24h',
      redirect_url: successUrl,
      merchant_order_ext_ref: internalRef,
      metadata: {
        reference: internalRef,
        product: 'iadi-24h'
      }
    }

    console.log('SUCCESS URL =', successUrl)
    console.log('PAYLOAD REVOLUT =', payload)

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

    const data = await response.json().catch(() => ({}))

    console.log('REVOLUT RESPONSE =', data)

    if (!response.ok) {
      return res.status(500).json({
        error: 'Échec de création commande Revolut',
        details: data
      })
    }

    const db = loadDb()
    db.orders.push({
      internalRef,
      revolutOrderId: data.id,
      publicId: data.public_id || null,
      checkoutUrl: data.checkout_url || null,
      status: data.state || 'created',
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
    console.error(error)
    return res.status(500).json({ error: 'Erreur serveur create-order' })
  }
})

app.get('/success', async (req, res) => {
  const orderRef = req.query.order_ref
  if (!orderRef) {
    return res.redirect('/')
  }
  res.redirect(`/acces-iadi?order_ref=${encodeURIComponent(orderRef)}`)
})
app.get('/dev-access', (req, res) => {
  const db = loadDb()

  const token = 'test123'

  db.accesses.push({
    token: token,
    status: 'active',
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
  })

  saveDb(db)

  res.send(`Accès créé : <a href="${APP_BASE_URL}/acces-iadi?token=${access.token}">${APP_BASE_URL}/acces-iadi?token=${access.token}</a>`)
})

app.listen(PORT, () => {
  console.log(`IADIY server running on ${APP_BASE_URL}`)
})
