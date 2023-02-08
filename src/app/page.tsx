'use client';
import base64url from 'base64url';
import * as bitcoin from 'bitcoinjs-lib';
import { derToJose } from 'ecdsa-sig-formatter';
import { sha256, toUtf8Bytes } from 'ethers';
import { useState } from 'react';
import * as u8a from 'uint8arrays';

export default function Home() {
  const [address, setAddress] = useState('');
  const [signature, setSignature] = useState('');

  return (
    <main className="flex flex-col h-full items-center gap-y-16 px-4 py-16 justify-between">
      <p>{address ? `Address: ${address}` : ''}</p>
      <p className="break-all">{signature ? `Signature: ${signature}` : ''}</p>
      <div className="flex flex-col gap-y-8">
        <button
          className="bg-green-600 rounded-full text-green-50 px-6 py-2"
          onClick={async () => {
            try {
              const req: any = {
                publicKey: {
                  allowCredentials: [
                    { id: fromHexString('02'), transports: ['nfc'], type: 'public-key' },
                  ],
                  challenge: new Uint8Array([
                    113, 241, 176, 49, 249, 113, 39, 237, 135, 170, 177, 61, 15, 14, 105, 236, 120,
                    140, 4, 41, 65, 225, 107, 63, 214, 129, 133, 223, 169, 200, 21, 88,
                  ]),
                  timeout: 60000,
                  userVerification: 'discouraged',
                },
              };

              const xdd: any = await navigator.credentials.get(req);
              const sig = xdd.response.signature;

              if (typeof sig !== 'undefined') {
                const sss = buf2hex(sig);
                const _keys = parseKeys(sss);

                if (_keys) {
                  console.log(_keys);
                  setAddress(_keys);
                }
              }
            } catch (err) {
              console.log('Error with scan', err);
            }
          }}
        >
          Scan for Address
        </button>
        <button
          className="bg-green-600 rounded-full text-green-50 px-6 py-2"
          onClick={async () => {
            try {
              const sigCmd = generateCmd(1, 1, 'some message');
              const hexSigCmd = fromHexString(sigCmd);
              console.log({ hexSigCmd, sigCmd });

              const req: any = {
                publicKey: {
                  allowCredentials: [{ id: hexSigCmd, transports: ['nfc'], type: 'public-key' }],
                  challenge: new Uint8Array([
                    113, 241, 176, 49, 249, 113, 39, 237, 135, 170, 177, 61, 15, 14, 105, 236, 120,
                    140, 4, 41, 65, 225, 107, 63, 214, 129, 133, 223, 169, 200, 21, 88,
                  ]),
                  timeout: 60000,
                  userVerification: 'discouraged',
                },
              };

              const xdd: any = await navigator.credentials.get(req);

              const sig = xdd.response.signature;
              const ES256 = base64url.toBase64(derToJose(Buffer.from(sig), 'ES256'));
              setSignature(ES256);
              console.log({ ES256 });

              // the code below actually gets us the same signature as the three lines above
              const unpackedSig = unpackDERSignature(new Uint8Array(sig));
              const { r, s } = unpackedSig;
              console.log({ base64RS: u8a.toString(new Uint8Array([...r, ...s]), 'base64') });
            } catch (err) {
              console.log('Error with scan', err);
            }
          }}
        >
          Sign &ldquo;some message&rdquo;
        </button>
      </div>
    </main>
  );
}

function buf2hex(buffer: Buffer | Uint8Array) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function generateCmd(cmd: number, keyslot: number, message: string) {
  // what's the point of hashing this with sha256?
  let messageBytes = sha256(toUtf8Bytes(message));
  console.log({ message, messageBytes });

  // Remove prepended 0x.
  messageBytes = messageBytes.slice(2);

  let cmdBytes: string | Uint8Array = new Uint8Array(2);
  cmdBytes[0] = cmd;
  cmdBytes[1] = keyslot;
  cmdBytes = buf2hex(cmdBytes);

  const inputBytes = cmdBytes + messageBytes;
  return inputBytes;
}

function parseKeys(payload: string) {
  try {
    const primaryPublicKeyLength = parseInt('0x' + payload.slice(0, 2)) * 2;
    const primaryPublicKeyRaw = payload.slice(2, primaryPublicKeyLength + 2);
    const { address } = bitcoin.payments.p2pkh({ pubkey: Buffer.from(primaryPublicKeyRaw, 'hex') });
    return address;
  } catch (err) {
    console.error(err);
    return false;
  }
}

const toHex = (b: Uint8Array) => '0x' + u8a.toString(b, 'base16');
function unpackDERSignature(sig: Uint8Array) {
  const bytes = sig.values();

  if (bytes.next().value !== 0x30) {
    throw Error('Invalid header, ' + toHex(sig));
  }
  bytes.next(); // ignore second byte of header

  if (bytes.next().value !== 0x02) {
    throw Error('Invalid header (2).');
  }

  let length_r = bytes.next().value;
  if (length_r == 33) {
    bytes.next(); // ignore prepended padding
    length_r -= 1;
  }
  const r = new Uint8Array(length_r);
  for (let i = 0; i < length_r; ++i) {
    r[i] = bytes.next().value;
  }

  if (bytes.next().value !== 0x02) {
    throw Error('Invalid header (2).');
  }

  let length_s = bytes.next().value;
  if (length_s == 33) {
    bytes.next(); // ignore prepended padding
    length_s -= 1;
  }
  const s = new Uint8Array(length_r);
  for (let i = 0; i < length_s; ++i) {
    s[i] = bytes.next().value;
  }

  return { r, s };
}

function fromHexString(hexString: string) {
  // @ts-expect-error
  return new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}
