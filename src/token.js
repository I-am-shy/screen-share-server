import crypto from 'crypto';

const ErrorCode = {
  success: 0,
  appIDInvalid: 1,
  userIDInvalid: 3,
  secretInvalid: 5,
  effectiveTimeInSecondsInvalid: 6,
};

function makeNonce() {
  const min = -Math.pow(2, 31);
  const max = Math.pow(2, 31) - 1;
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function aesGcmEncrypt(plainText, key) {
  if (![16, 24, 32].includes(key.length)) {
    throw createError(ErrorCode.secretInvalid, '密钥长度无效。密钥必须为16、24或32字节。');
  }
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAutoPadding(true);
  const encrypted = cipher.update(plainText, 'utf8');
  const encryptBuf = Buffer.concat([encrypted, cipher.final(), cipher.getAuthTag()]);

  return { encryptBuf, nonce };
}

function createError(errorCode, errorMessage) {
  return { errorCode, errorMessage };
}

export function generateToken04(appId, userId, secret, effectiveTimeInSeconds, payload = '') {
  if (!appId || typeof appId !== 'number') {
    throw createError(ErrorCode.appIDInvalid, 'appID 无效');
  }

  if (!userId || typeof userId !== 'string' || userId.length > 64) {
    throw createError(ErrorCode.userIDInvalid, 'userId 无效');
  }

  if (!secret || typeof secret !== 'string' || secret.length !== 32) {
    throw createError(ErrorCode.secretInvalid, 'secret 必须为32字节字符串');
  }

  if (!(effectiveTimeInSeconds > 0)) {
    throw createError(ErrorCode.effectiveTimeInSecondsInvalid, 'effectiveTimeInSeconds invalid');
  }

  const VERSION_FLAG = '04';

  const createTime = Math.floor(new Date().getTime() / 1000);
  const tokenInfo = {
    app_id: appId,
    user_id: userId,
    nonce: makeNonce(),
    ctime: createTime,
    expire: createTime + effectiveTimeInSeconds,
    payload: payload || '',
  };

  const plaintText = JSON.stringify(tokenInfo);

  const { encryptBuf, nonce } = aesGcmEncrypt(plaintText, secret);

  const [b1, b2, b3, b4] = [
    new Uint8Array(8),
    new Uint8Array(2),
    new Uint8Array(2),
    new Uint8Array(1),
  ];
  new DataView(b1.buffer).setBigInt64(0, BigInt(tokenInfo.expire), false);
  new DataView(b2.buffer).setUint16(0, nonce.byteLength, false);
  new DataView(b3.buffer).setUint16(0, encryptBuf.byteLength, false);
  new DataView(b4.buffer).setUint8(0, 1);

  const buf = Buffer.concat([
    Buffer.from(b1),
    Buffer.from(b2),
    Buffer.from(nonce),
    Buffer.from(b3),
    Buffer.from(encryptBuf),
    Buffer.from(b4),
  ]);
  const dv = new DataView(Uint8Array.from(buf).buffer);
  return VERSION_FLAG + Buffer.from(dv.buffer).toString('base64');
}
