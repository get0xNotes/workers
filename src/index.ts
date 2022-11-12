import { Context, Hono } from 'hono'
import { PostgrestClient } from '@supabase/postgrest-js'
import { Environment } from 'hono/dist/hono'
import { Schema } from 'hono/dist/validator/schema'
import * as jose from 'jose'

const app = new Hono()

app.get('/api', (c) => c.text('Hello from 0xNotes API!'))

async function unameAvailable(ctx: Context<any, Environment, Schema>, uname: string) {
  // Local validation
  uname = uname.toLowerCase()
  const unameSanitized = uname.replace(/[^0-9a-zA-Z_\-.]/g, '').toLowerCase()
  if (uname != unameSanitized) {
    return {available: false, reason: 'Username contains invalid characters.'}
  } else if (uname.length < 5) {
    return {available: false, reason: 'Username is too short (min 5 chars).'}
  } else if (uname.length > 20) {
    return {available: false, reason: 'Username is too long (max 20 chars).'}
  }

  // Remote validation
  const postgrest = new PostgrestClient(ctx.env.POSTGREST_ENDPOINT, {headers: {apikey: ctx.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('users').select('username').eq('username', uname)
  if (res.data) {
    const taken = res.data.length == 0 ? false : true
    return {available: !taken, reason: taken ? `Username ${uname} is taken.` : `Username ${uname} is available.`}
  } else {
    return {available: false, reason: 'Error retrieving data from database.'}
  }
}

async function createSession(ctx: Context<any, Environment, Schema>, uname: string, exp: string = "1d") {
  return await new jose.SignJWT({claim: true})
    .setProtectedHeader({alg: 'EdDSA'})
    .setIssuedAt()
    .setIssuer('0xNotes')
    .setAudience(uname)
    .setExpirationTime(exp)
    .sign(await jose.importJWK(JSON.parse(ctx.env.SERVER_JWK)))
}

async function validateSession(ctx: Context<any, Environment, Schema>, token: string) {
  let JWK = JSON.parse(ctx.env.SERVER_JWK)
  delete JWK.d
  try {
    const { payload, protectedHeader } = await jose.jwtVerify(token, await jose.importJWK(JWK), {issuer: '0xNotes'})
    return {valid: true, uname: payload.aud}
  } catch (e) {
    return {valid: false, uname: null}
  }
}

type NewNote = {
  keys: {[x: string]: string},
  title: string,
  content: string,
}

app.post('/api/note/create', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  const {valid, uname} = await validateSession(c, token)
  const body = await c.req.json<NewNote>()
  if (!valid) {
    return c.json({success: false, reason: "Authorization required."}, 401)
  }
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  // col: id, author, contributors, keys, title, content, modified
  const res = await postgrest.from('notes').insert({author: uname, contributors: [uname], keys: body.keys, title: body.title, content: body.content, modified: new Date().toISOString(), modifiedBy: uname}).select("id")
  if (res.data) {
    return c.json({success: true, id: res.data[0].id})
  } else {
    return c.json({success: false, reason: "Error inserting note into database."})
  }
})

// List all notes (title and metadata only)
app.get('/api/notes', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  const {valid, uname} = await validateSession(c, token)
  if (!valid) {
    return c.json({success: false, reason: "Authorization required."}, 401)
  }
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('notes').select('id, title, author, keys, modified, modifiedBy').contains('contributors', [uname])
  
  if (res.data && uname) {
    // Strip keys belonging to other users
    for (let i = 0; i < res.data.length; i++) {
      for (let key in res.data[i].keys) {
        if (key != uname) {
          delete res.data[i].keys[key]
        }
      }
    }
    return c.json({success: true, notes: res.data})
  } else {
    return c.json({success: false, reason: "Error retrieving notes from database."})
  }
})

app.get('/api/note/:id', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  const {valid, uname} = await validateSession(c, token)
  if (!valid) {
    return c.json({success: false, reason: "Authorization required."}, 401)
  }
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('notes').select('id, title, author, contributors, keys, content, modified, modifiedBy').eq('id', c.req.param('id'))
  if (res.data && uname) {
    // Check if user has access to the note
    if (!res.data[0].contributors.includes(uname)) {
      return c.json({success: false, reason: "You do not have access to this note."}, 403)
    }

    // Strip keys belonging to other users
    for (let key in res.data[0].keys) {
      if (key != uname) {
        delete res.data[0].keys[key]
      }
    }
    return c.json({success: true, note: res.data[0]})
  } else {
    return c.json({success: false, reason: "Error retrieving note from database."})
  }
})

// Update collaborators
app.post('/api/note/:id/contributors', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  const {valid, uname} = await validateSession(c, token)
  if (!valid) {
    return c.json({success: false, reason: "Authorization required."}, 401)
  }

  // Check if user is the author of the note
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('notes').select('author').eq('id', c.req.param('id'))
  if (res.data && uname) {
    if (res.data[0].author != uname) {
      return c.json({success: false, reason: "You are not the author of this note."}, 403)
    }
  } else {
    return c.json({success: false, reason: "Error retrieving note from database."})
  }

  let contribs = await (await c.req.json<{contributors: string[]}>()).contributors

  if (!contribs) {
    return c.json({success: false, reason: "No contributors provided."}, 400)
  }

  contribs.push(String(uname))
  contribs = [...new Set(contribs)]

  let removed = []

  // Check if contributor exists
  for (let i = 0; i < contribs.length; i++) {
    const res = await postgrest.from('users').select('username').eq('username', contribs[i])
    if (res.data?.length == 0) {
      removed.push(contribs[i])
      // Remove contributor from list
      contribs.splice(i, 1)
      i--
    }
  }

  // Update contributors
  const res2 = await postgrest.from('notes').update({contributors: contribs, modified: new Date().toISOString(), modifiedBy: uname}).eq('id', c.req.param('id'))
  return c.json({success: true, invalid: removed})
})



// Get the pubKey of a user
app.get('/api/user/:uname/publickey', async (c) => {
  const uname = c.req.param('uname')
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('users').select('pk').eq('username', uname)
  if (res.data) {
    return c.json({success: true, pk: res.data[0].pk}, 200, {'Cache-Control': 'max-age=3600'})
  } else {
    return c.json({success: false, reason: 'Error retrieving data from database.'})
  }
})

// Check if the username is available
app.get('/api/user/:uname/available', async (c) => {
  const uname = c.req.param('uname')
  var res = await unameAvailable(c, uname)
  return c.json({success: true, available: res.available, reason: res.reason})
})

type Creds = {
  username: string,
  auth: string,
  pk?: string,
  sk?: string,
  totp?: string
}

// Create a new user
app.post('/api/signup', async (c) => {
  const body = await c.req.json<Creds>()
  if (!body.username || !body.auth || !body.pk || !body.sk) {
    return c.json({success: false, reason: 'Missing required fields.'})
  }
  const uname = body.username.toString().toLowerCase()
  const authKey = body.auth.toString()
  const pubKey = body.pk.toString()
  const privKey = body.sk.toString() // Note: Private key has been encrypted client-side

  // Validate username
  const availRes = await unameAvailable(c, uname)
  if (!availRes.available) {
    return c.json({success: false, reason: availRes.reason})
  }

  // Validate authKey (must be 256-bit hex string)
  if (authKey.length != 64 || !/^[0-9a-fA-F]+$/.test(authKey)) {
    return c.json({success: false, reason: 'Invalid authKey.'})
  }

  // Validate pubKey (must be 256-bit hex string)
  if (pubKey.length != 64 || !/^[0-9a-fA-F]+$/.test(pubKey)) {
    return c.json({success: false, reason: 'Invalid pubKey.'})
  }

  // Validate encrypted privKey (must be 512-bit hex string)
  if (privKey.length != 128 || !/^[0-9a-fA-F]+$/.test(privKey)) {
    return c.json({success: false, reason: 'Invalid privKey.'})
  }

  // Create record in DB
  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const res = await postgrest.from('users').insert([{username: uname, auth: authKey, pk: pubKey, sk: privKey}])
  if (res.error) {
    return c.json({success: false, reason: 'Error creating user.'})
  } else {
    const session = await createSession(c, uname)
    return c.json({success: true, session: session, reason: 'User created.'})
  }
})

app.post('/api/login', async (c) => {
  const body = await c.req.json<Creds>()
  if (!body.username || !body.auth) {
    return c.json({success: false, reason: 'Missing required fields.'})
  }

  const postgrest = new PostgrestClient(c.env.POSTGREST_ENDPOINT, {headers: {apikey: c.env.POSTGREST_APIKEY}})
  const uname = body.username.toString().toLowerCase()
  const authKey = body.auth.toString()
  const res = await postgrest.from('users').select('auth, totp, sk').eq('username', uname)
  
  if (res.data) {
    if (res.data[0].auth == authKey) {
      const session = await createSession(c, uname)
      return c.json({success: true, username: body.username, session: session, sk: res.data[0].sk})
      // TODO: TOTP
    } else {
      return c.json({success: false, reason: 'Invalid credentials.'})
    }
  }
})

export default app