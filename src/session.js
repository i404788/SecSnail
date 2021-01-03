'use strict'

const crypto = require('crypto')
const util = require('./util')

const SALTS = {'RK': Buffer.alloc(32).fill(1), 'NHK': {}, 'HK': Buffer.alloc(32).fill(4)}

/**
 * This class represents a Double Ratchet session between two peers.
 */
class Session {
  constructor (state = {}) {
    this.ad = state.ad || null
    this.info = state.info || null

    this.pubKey = state.pubKey || null
    this.privKey = state.privKey || null
    this.peerKey = state.peerKey || null

    this.rootKey = state.rootKey || null
    this.recvChainKey = state.recvChainKey || null
    this.sendChainKey = state.sendChainKey || null

    this.sendMsgNum = state.sendMsgNum || 0
    this.recvMsgNum = state.recvMsgNum || 0
    this.prevChainLen = state.prevChainLen || 0
    this.skippedMsgs = state.skippedMsgs || []

    this.sendHeaderKey = state.sendHeaderKey || null
    this.sendNextHeaderKey = state.sendNextHeaderKey || null
    this.recvHeaderKey = state.recvHeaderKey || null
    this.recvNextHeaderKey = state.recvNextHeaderKey || null
  }

  static get MAX_SKIP () {
    return 10
  }

  static get PUBKEY_LEN () {
    return 64
  }

  static fromX3DH(recv = false, IKeys = null, HKeys = null){
    let R = null
    if (!recv)
	    R = util.genKeyPair()
    const { pubKey: IKpub, privKey: IKpriv } = IKeys || util.genKeyPair()
    const { pubKey: HKpub, privKey: HKpriv } = HKeys || util.genKeyPair()

    const resolve = ({IKr, HKr, Rr = null}) => {
      // console.log({Ia: IKpriv.toBuffer().toString('hex'), Ha: HKpriv.toBuffer().toString('hex'), Ibp: IKr, Hbp: HKr, recv, length: 96})
      let mkey = util.x3dh({Ia: IKpriv, Ha: HKpriv, Ibp: IKr, Hbp: HKr, recv, length: 96})
      // console.log(mkey)
      const secKeys = []

      for (let i = 0; i < 3; i++) {
        secKeys.push(mkey.slice(0, 32))
        mkey = mkey.slice(32)
      }
      
      let ad = null
      if (recv)
        ad = Buffer.concat([Buffer.from(IKpub, 'hex'), Buffer.from(IKr, 'hex')])
      else
        ad = Buffer.concat([Buffer.from(IKr, 'hex'), Buffer.from(IKpub, 'hex')])

      const sess = new Session()
      sess.init({ad, info: 'secsnail', keyPair: R, peerKey: Rr, secKeys});
      return sess 
    }

    if (!recv)
     return [{IKr: IKpub, HKr: HKpub, Rr: R.pubKey}, resolve]
    else
      return [{IKr: IKpub, HKr: HKpub}, resolve]
  }

  /**
   * Initialize session with keys, secrets, and additional info.
   *
   * @param  {Object}   args
   * @param  {Buffer}   args.ad
   * @param  {Buffer}   args.info
   * @param  {Object}   args.keyPair
   * @param  {Buffer}   args.peerKey
   * @param  {Buffer[]} args.secKeys
   *
   * @return {Buffer}
   */
  init ({ ad, info, keyPair, peerKey, secKeys }) {
    if (keyPair) {
      this.pubKey = keyPair.pubKey
      this.privKey = keyPair.privKey
    } else {
      this.genKeyPair()
    }

    this.ad = ad
    this.info = info
    this.rootKey = Buffer.from(secKeys[0])

    if (peerKey) {
      this.peerKey = peerKey
      const { chainKey, nextHeaderKey } = this.kdfRoot()

      this.sendChainKey = chainKey
      this.sendNextHeaderKey = nextHeaderKey
      this.sendHeaderKey = Buffer.from(secKeys[1])
      this.recvNextHeaderKey = Buffer.from(secKeys[2])
    } else {
      this.recvNextHeaderKey = Buffer.from(secKeys[1])
      this.sendNextHeaderKey = Buffer.from(secKeys[2])
    }

    return Buffer.from(this.pubKey)
  }

  /**
   * Encrypt a plaintext into a message header and payload.
   *
   * @param  {(Buffer|String)} plaintext
   *
   * @return {Object}
   */
  encrypt (plaintext) {
    const msgKey = this.kdfSendChain()
    const header = this.encryptHeader()
    const nonce = Buffer.concat([this.ad, header])
    const payload = Session.authEncrypt({ ikm: msgKey, info: this.info, nonce, plaintext })

    ++this.sendMsgNum

    return { header, payload }
  }

  /**
   * Decrypt a message header and payload into plaintext.
   *
   * @param  {Object} args
   * @param  {Buffer} args.header
   * @param  {Buffer} args.payload
   *
   * @return {Buffer}
   */
  decrypt ({ header, payload }) {
    let headerKey, msgKey, msgNum, obj

    for (let i = 0; i < this.skippedMsgs.length; i++) {
      ({ headerKey, msgKey, msgNum } = this.skippedMsgs[i])
      obj = null

      try {
        obj = this.decryptHeader({ header, headerKey })
      } catch {}

      if (obj && obj.msgNum === msgNum) {
        this.skippedMsgs.splice(i, 1)
        break
      }

      msgKey = null
    }

    if (!msgKey) {
      obj = null

      try {
        obj = this.decryptHeader({ header, headerKey: this.recvHeaderKey })
      } catch {}

      if (!obj) {
        try {
          obj = this.decryptHeader({ header, headerKey: this.recvNextHeaderKey })
        } catch {}

        if (!obj) {
          throw new Error('Failed to decrypt header')
        }

        this.skipMsgs(obj.prevChainLen)

        this.prevChainLen = this.sendMsgNum
        this.sendMsgNum = 0
        this.recvMsgNum = 0
        this.peerKey = obj.pubKey

        this.sendHeaderKey = this.sendNextHeaderKey
        this.recvHeaderKey = this.recvNextHeaderKey

        {
          const { chainKey, nextHeaderKey } = this.kdfRoot()
          this.recvChainKey = chainKey
          this.recvNextHeaderKey = nextHeaderKey
        }

        this.genKeyPair()
        {
          const { chainKey, nextHeaderKey } = this.kdfRoot()
          this.sendChainKey = chainKey
          this.sendNextHeaderKey = nextHeaderKey
        }
      }

      this.skipMsgs(obj.msgNum)
      msgKey = this.kdfRecvChain()

      ++this.recvMsgNum
    }

    const nonce = Buffer.concat([this.ad, header])

    return Session.authDecrypt({ ikm: msgKey, info: this.info, nonce, payload })
  }

  genKeyPair () {
    const { pubKey, privKey } = util.genKeyPair()
    this.pubKey = pubKey
    this.privKey = privKey
  }

  static kdfChain (chainKey) {
    const msgKey = util.hmac({ key: chainKey, data: Buffer.from([1]) })
    chainKey = util.hmac({ key: chainKey, data: Buffer.from([2]) })

    return { msgKey, chainKey }
  }

  kdfRoot () {
    const dh = util.dh(this.privKey, this.peerKey)
    const okm = util.hkdf({
      ikm: dh, 
      info: this.info,
      length: 96,
      salt: this.rootKey
    })

    this.rootKey = okm.slice(0, 32)

    const chainKey = okm.slice(32)
    const nextHeaderKey = okm.slice(64)

    return { chainKey, nextHeaderKey }
  }

  kdfSendChain () {
    const { msgKey, chainKey } = Session.kdfChain(this.sendChainKey)
    this.sendChainKey = chainKey

    return msgKey
  }

  kdfRecvChain () {
    const { msgKey, chainKey } = Session.kdfChain(this.recvChainKey)
    this.recvChainKey = chainKey

    return msgKey
  }

  static authEncrypt ({ ikm, info, nonce, plaintext }) {
    const okm = util.hkdf({ ikm, info, length: 80 })
    const encKey = okm.slice(0, 32)
    const authKey = okm.slice(32, 64)
    const iv = okm.slice(64)
    const ciphertext = util.encrypt({ plaintext, iv, key: encKey })
    const hmac = util.hmac({ data: nonce, key: authKey })

    return Buffer.concat([ciphertext, hmac])
  }

  static authDecrypt ({ ikm, info, nonce, payload }) {
    const okm = util.hkdf({ ikm, info, length: 80 })
    const encKey = okm.slice(0, 32)
    const authKey = okm.slice(32, 64)
    const iv = okm.slice(64)

    const hmac = payload.slice(-32)
    const valid = util.hmac({ data: nonce, key: authKey }).equals(hmac)

    if (!valid) {
      throw new Error('Invalid HMAC')
    }

    const ciphertext = payload.slice(0, -32)
    return util.decrypt({ ciphertext, iv, key: encKey })
  }

  encryptHeader () {
    const prevChainLen = Buffer.alloc(4)
    prevChainLen.writeUInt32BE(this.prevChainLen)

    const msgNum = Buffer.alloc(4)
    msgNum.writeUInt32BE(this.sendMsgNum)

    const header = Buffer.concat([
      Buffer.from(this.pubKey),
      prevChainLen,
      msgNum
    ])

    const nonce = crypto.randomBytes(16)
    const payload = Session.authEncrypt({ ikm: this.sendHeaderKey, info: this.info, nonce, plaintext: header })

    return Buffer.concat([payload, nonce])
  }

  decryptHeader ({ header, headerKey }) {
    const nonce = header.slice(-16)
    header = header.slice(0, -16)
    header = Session.authDecrypt({ ikm: headerKey, info: this.info, nonce, payload: header })

    const pubKey = header.slice(0, Session.PUBKEY_LEN)

    let prevChainLen = header.slice(Session.PUBKEY_LEN, Session.PUBKEY_LEN + 4)
    prevChainLen = prevChainLen.readUInt32BE()

    let msgNum = header.slice(Session.PUBKEY_LEN + 4, Session.PUBKEY_LEN + 8)
    msgNum = msgNum.readUInt32BE()

    return { pubKey, prevChainLen, msgNum }
  }

  skipMsgs (until) {
    if (this.recvMsgNum + Session.MAX_SKIP < until) {
      throw new Error('Cannot skip that many messages')
    }

    if (!this.recvChainKey) return

    for (; this.recvMsgNum < until; this.recvMsgNum++) {
      const msgKey = this.kdfRecvChain()
      this.skippedMsgs.push({ headerKey: this.recvHeaderKey, msgKey, msgNum: this.recvMsgNum })
    }
  }
}

module.exports = Session
