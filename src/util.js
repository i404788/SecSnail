'use strict'

const crypto = require('crypto')
const EC = require('eliptic').ec
const ec = new EC('curve25519')

const encrypt = ({ iv, key, plaintext }) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  return Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final()
  ])
}

const decrypt = ({ ciphertext, iv, key }) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ])
}

const genKeyPair = () => {
  const kp = ec.genKeyPair();
  const pubKey = ec.getPublic().encode('hex')
  const privKey = ec.getPrivate()
  return { pubKey, privKey }
}

const hmac = ({ data, key }) => {
  const hmac = crypto.createHmac('sha512', key)
  hmac.update(data)
  return hmac.digest()
}

// TODO: add tests from https://tools.ietf.org/html/rfc5869
const hkdf = ({ ikm, info, length, salt }) => {
  salt = salt || Buffer.alloc(32)
  info = info || Buffer.alloc(0)
  const key = hmac({ data: ikm, key: salt })

  let t = Buffer.alloc(0)
  let okm = Buffer.alloc(0)

  for (let i = 0; i < Math.ceil(length / 32); i++) {
    const data = Buffer.concat([t, info, Buffer.from([1 + i])])
    t = hmac({ data, key })
    okm = Buffer.concat([okm, t])
  }

  return okm.slice(0, length)
}

const dh = (a, bp) => {
  if (bp instanceof Buffer)
    bp = bp.toString('hex')
  if (typeof bp === 'string')
    bp = ec.keyFromPublic(bp, 'hex')

  return a.derive(bp).toBuffer()
}

const x3dh = ({Ia, Ha, Ibp, Hbp, recv}) => {
  if (recv) {
    const seed = Buffer.concat([dh(Ia, Hbp), dh(Ha, Ibp), dh(Ha, Hbp)])
    return hkdf({ikm: seed, salt: Buffer.alloc(seed.byteLength), length: 32, info: Buffer.from('x3dh')}) 
  } else {
    const seed = Buffer.concat([dh(Ha, Ibp), dh(Ia, Hbp), dh(Ha, Hbp)])
    return hkdf({ikm: seed, salt: Buffer.alloc(seed.byteLength), length: 32, info: Buffer.from('x3dh')}) 
  }
}

const isArray = x => Array.isArray(x)
const isBuffer = x => Buffer.isBuffer(x)
const isInteger = x => Number.isInteger(x)
const isIntegerInRange = (a, b) => x => isInteger(x) && x >= a && x <= b
const isString = x => typeof x === 'string'
const isNonEmptyString = x => x && isString(x)
const isArrayPublicKeys = x => isArray(x) && x.every(isPublicKey)
const isBufferOrString = x => isBuffer(x) || isString(x)

const isPublicKey = x => {
  if (typeof x !== 'string)
    return false

  return x.length === 64
}


const validators = {
  'an array': isArray,
  'a buffer': isBuffer,
  'a buffer or string': isBufferOrString,
  'an integer': isInteger,
  'a string': isString,
  'a non-empty string': isNonEmptyString,
  'a public key': isPublicKey,
  'an array of public keys': isArrayPublicKeys,
  'a valid port number': isIntegerInRange(1, 65535)
}

const validate = (...args) => {
  for (const [key, type, value] of args) {
    if (!validators[type](value)) {
      throw new Error(`Expected ${key} to be ${type}`)
    }
  }
}

module.exports = {
  decrypt,
  encrypt,
  genKeyPair,
  hkdf,
  x3dh,
  hmac,
  validate
}
