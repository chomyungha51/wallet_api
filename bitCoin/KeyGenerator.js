import Web3 from 'web3'
import BIP39 from 'bip39'
import pkg from 'ethereumjs-wallet'
import bs58 from 'bs58'
import EC from 'elliptic'
import sha256 from 'js-sha256'
import ripemd160 from 'ripemd160'
import bitcore from 'bitcore-lib'

const {hdkey} = pkg
const {ec} = EC
const web3 = new Web3()

export const generateMnemonic = () => {
    return BIP39.generateMnemonic()
}

export const generateSeed = (mnemonic) => {
    return BIP39.mnemonicToSeedSync(mnemonic)
}

export const generatePrivateKey = (mnemonic) => {
    const seed = generateSeed(mnemonic).toString()

    const rootKey = hdkey.fromMasterSeed(seed)
    const hardenedKey = rootKey.derivePath("m/44'/60'/0'/0'")
    const childKey = hardenedKey.deriveChild(0)
    const wallet = childKey.getWallet()
    const privateKey = wallet.getPrivateKey()
    return privateKey
}

export const generatePublicKey = (privateKey) => {
    const ecdsa = new ex('secp256k1')
    const keys = ecdsa.keyFromPrivate(privateKey)
    const publicKey = keys.getPublic('hex').substring(2, 66)
    return "03"+publicKey
}

export const generateAddress = (publicKey) => {
    const hash = sha256(Buffer.from(publicKey, 'hex'))
    const publicKeyHash = new ripemd160().update(Buffer.from(hash, 'hex')).digest()
    const prefixPublicKey = Buffer.from("6F" + publicKeyHash.toString('hex'), 'hex')
    const onceHash = sha256(prefixPublicKey)
    const doubleHash = sha256(Buffer.from(onceHash, 'hex'))
    const checksum = doubleHash.substring(0, 8)
    const prefixPublicKeyChecksum = prefixPublicKey.toString('hex') + checksum
    const address = bs58.encode(Buffer.from(prefixPublicKeyChecksum, 'hex'))
    return address
}