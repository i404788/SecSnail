const session = require('../src/session')
const util = require('../src/util')

function throwIfError(v){ if (v instanceof Error) throw v }
function assert(v, e) { throwIfError(v || new Error(e)) }

function testx3dh()
{
  const {pubKey: aipub, privKey: aipriv} = util.genKeyPair()
  const {pubKey: ahpub, privKey: ahpriv} = util.genKeyPair()
  const {pubKey: bipub, privKey: bipriv} = util.genKeyPair()
  const {pubKey: bhpub, privKey: bhpriv} = util.genKeyPair()

  const amkey = util.x3dh({Ia: aipriv, Ha: ahpriv, Ibp: bipub, Hbp: bhpub, recv: true, length: 32})
  const bmkey = util.x3dh({Ia: bipriv, Ha: bhpriv, Ibp: aipub, Hbp: ahpub, recv: false, length: 32})

  assert(amkey.equals(bmkey), `X3DH doesn't resolve to the same value ${amkey.toString('hex')} != ${bmkey.toString('hex')}`)
}

function testsession()
{
  const [akeys, aresolve] = session.fromX3DH(false)
  const [bkeys, bresolve] = session.fromX3DH(true)

  console.log(akeys, bkeys)
  const bsession = bresolve(akeys)
  const asession = aresolve(bkeys)

  const ct = bsession.encrypt("Testing")
  const pt = asession.decrypt(ct)
  console.log(`${ct} ${pt}`)
}

const totest = {testx3dh, testsession}
for (const f in totest) {
  try {
    totest[f]()
  } catch (e) {
    console.error(`Failed test ${f}`)
    console.error(e)
  }
}