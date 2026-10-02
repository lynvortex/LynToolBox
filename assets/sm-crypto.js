/**
 * 绘萤工具箱 - 国密 SM2/SM3/SM4 纯 JS 实现（零依赖）
 * SM3: GB/T 32905-2016  SM4: GB/T 32907-2016  SM2: GB/T 32918
 */
(function () {
    'use strict';

    /* ================= 工具函数 ================= */
    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

    function hexToBytes(hex) {
        hex = hex.replace(/\s+/g, '');
        if (hex.length % 2) hex = '0' + hex;
        var out = new Uint8Array(hex.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }
    function bytesToHex(bytes) {
        var s = '';
        for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
        return s;
    }
    function utf8ToBytes(str) { return new TextEncoder().encode(str); }
    function bytesToUtf8(bytes) { return new TextDecoder().decode(bytes); }
    function hexToBigInt(hex) { return BigInt('0x' + (hex || '0')); }
    function bigIntToHex(n, len) {
        var s = n.toString(16);
        if (len) s = s.padStart(len, '0');
        return s;
    }

    /* ================= SM3 ================= */
    var SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];

    function sm3Pad(msg) {
        var len = msg.length;
        var bitLen = len * 8;
        var padLen = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
        var padded = new Uint8Array(len + padLen + 8);
        padded.set(msg);
        padded[len] = 0x80;
        var hi = Math.floor(bitLen / 4294967296), lo = bitLen >>> 0;
        padded[padded.length - 8] = (hi >>> 24) & 0xff;
        padded[padded.length - 7] = (hi >>> 16) & 0xff;
        padded[padded.length - 6] = (hi >>> 8) & 0xff;
        padded[padded.length - 5] = hi & 0xff;
        padded[padded.length - 4] = (lo >>> 24) & 0xff;
        padded[padded.length - 3] = (lo >>> 16) & 0xff;
        padded[padded.length - 2] = (lo >>> 8) & 0xff;
        padded[padded.length - 1] = lo & 0xff;
        return padded;
    }

    function sm3Compress(v, block) {
        var W = new Array(68), W1 = new Array(64);
        for (var j = 0; j < 16; j++) {
            W[j] = ((block[j * 4] << 24) | (block[j * 4 + 1] << 16) | (block[j * 4 + 2] << 8) | block[j * 4 + 3]) >>> 0;
        }
        for (j = 16; j < 68; j++) {
            var p1 = W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15);
            p1 = (p1 ^ rotl(p1, 15) ^ rotl(p1, 23)) >>> 0;
            W[j] = (p1 ^ rotl(W[j - 13], 7) ^ W[j - 6]) >>> 0;
        }
        for (j = 0; j < 64; j++) W1[j] = (W[j] ^ W[j + 4]) >>> 0;

        var A = v[0], B = v[1], C = v[2], D = v[3], E = v[4], F = v[5], G = v[6], H = v[7];
        for (j = 0; j < 64; j++) {
            var T = j < 16 ? 0x79cc4519 : 0x7a879d8a;
            var SS1 = rotl(((rotl(A, 12) + E + rotl(T, j % 32)) & 0xffffffff) >>> 0, 7);
            var SS2 = (SS1 ^ rotl(A, 12)) >>> 0;
            var FF = j < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C));
            var GG = j < 16 ? (E ^ F ^ G) : ((E & F) | ((~E) & G));
            var TT1 = ((FF + D + SS2 + W1[j]) & 0xffffffff) >>> 0;
            var TT2 = ((GG + H + SS1 + W[j]) & 0xffffffff) >>> 0;
            D = C; C = rotl(B, 9); B = A; A = TT1;
            H = G; G = rotl(F, 19); F = E;
            E = (TT2 ^ rotl(TT2, 9) ^ rotl(TT2, 17)) >>> 0;
        }
        return [
            (A ^ v[0]) >>> 0, (B ^ v[1]) >>> 0, (C ^ v[2]) >>> 0, (D ^ v[3]) >>> 0,
            (E ^ v[4]) >>> 0, (F ^ v[5]) >>> 0, (G ^ v[6]) >>> 0, (H ^ v[7]) >>> 0
        ];
    }

    function sm3Digest(msgBytes) {
        var padded = sm3Pad(msgBytes);
        var v = SM3_IV.slice();
        for (var i = 0; i < padded.length; i += 64) {
            v = sm3Compress(v, padded.subarray(i, i + 64));
        }
        var out = new Uint8Array(32);
        for (i = 0; i < 8; i++) {
            out[i * 4] = (v[i] >>> 24) & 0xff;
            out[i * 4 + 1] = (v[i] >>> 16) & 0xff;
            out[i * 4 + 2] = (v[i] >>> 8) & 0xff;
            out[i * 4 + 3] = v[i] & 0xff;
        }
        return out;
    }

    function sm3Hex(input, isHex) {
        var bytes = isHex ? hexToBytes(input) : utf8ToBytes(input);
        return bytesToHex(sm3Digest(bytes));
    }

    /* ================= SM4 ================= */
    var SM4_SBOX = [
        0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
        0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
        0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
        0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
        0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
        0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
        0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
        0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
        0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
        0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
        0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
        0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
        0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
        0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
        0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
        0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
    ];
    var SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
    var SM4_CK = (function () {
        var ck = [];
        for (var i = 0; i < 32; i++) {
            ck.push((((4 * i) * 7 % 256) << 24) | (((4 * i + 1) * 7 % 256) << 16) | (((4 * i + 2) * 7 % 256) << 8) | ((4 * i + 3) * 7 % 256));
        }
        return ck;
    })();

    function sm4Tau(A) {
        return ((SM4_SBOX[(A >>> 24) & 0xff] << 24) | (SM4_SBOX[(A >>> 16) & 0xff] << 16) | (SM4_SBOX[(A >>> 8) & 0xff] << 8) | SM4_SBOX[A & 0xff]) >>> 0;
    }
    function sm4L(B) { return (B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24)) >>> 0; }
    function sm4L1(B) { return (B ^ rotl(B, 13) ^ rotl(B, 23)) >>> 0; }

    function sm4ExpandKey(keyBytes) {
        var MK = [];
        for (var i = 0; i < 4; i++) {
            MK.push(((keyBytes[i * 4] << 24) | (keyBytes[i * 4 + 1] << 16) | (keyBytes[i * 4 + 2] << 8) | keyBytes[i * 4 + 3]) >>> 0);
        }
        var Kall = [MK[0] ^ SM4_FK[0], MK[1] ^ SM4_FK[1], MK[2] ^ SM4_FK[2], MK[3] ^ SM4_FK[3]];
        var rk = [];
        for (i = 0; i < 32; i++) {
            var x = (Kall[i + 1] ^ Kall[i + 2] ^ Kall[i + 3] ^ SM4_CK[i]) >>> 0;
            var next = (Kall[i] ^ sm4L1(sm4Tau(x))) >>> 0;
            Kall.push(next);
            rk.push(next);
        }
        return rk;
    }

    function sm4CryptBlock(block, rk) {
        var X = [];
        for (var i = 0; i < 4; i++) {
            X.push(((block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]) >>> 0);
        }
        for (i = 0; i < 32; i++) {
            var x = (X[1] ^ X[2] ^ X[3] ^ rk[i]) >>> 0;
            var nx = (X[0] ^ sm4L(sm4Tau(x))) >>> 0;
            X = [X[1], X[2], X[3], nx];
        }
        var out = new Uint8Array(16);
        for (i = 0; i < 4; i++) {
            var w = X[3 - i];
            out[i * 4] = (w >>> 24) & 0xff;
            out[i * 4 + 1] = (w >>> 16) & 0xff;
            out[i * 4 + 2] = (w >>> 8) & 0xff;
            out[i * 4 + 3] = w & 0xff;
        }
        return out;
    }

    function pkcs7Pad(bytes) {
        var pad = 16 - (bytes.length % 16);
        var out = new Uint8Array(bytes.length + pad);
        out.set(bytes);
        for (var i = bytes.length; i < out.length; i++) out[i] = pad;
        return out;
    }
    function pkcs7Unpad(bytes) {
        var pad = bytes[bytes.length - 1];
        if (pad < 1 || pad > 16) throw new Error('PKCS#7 填充无效');
        return bytes.slice(0, bytes.length - pad);
    }

    function sm4Encrypt(dataBytes, keyHex, mode, ivHex) {
        var rk = sm4ExpandKey(hexToBytes(keyHex));
        var padded = pkcs7Pad(dataBytes);
        var out = new Uint8Array(padded.length);
        var prev = ivHex ? hexToBytes(ivHex) : null;
        for (var i = 0; i < padded.length; i += 16) {
            var block = padded.subarray(i, i + 16);
            if (mode === 'cbc' && prev) {
                var xored = new Uint8Array(16);
                for (var j = 0; j < 16; j++) xored[j] = block[j] ^ prev[j];
                block = xored;
            }
            var enc = sm4CryptBlock(block, rk);
            out.set(enc, i);
            if (mode === 'cbc') prev = enc;
        }
        return out;
    }

    function sm4Decrypt(dataBytes, keyHex, mode, ivHex) {
        var rk = sm4ExpandKey(hexToBytes(keyHex)).reverse();
        var out = new Uint8Array(dataBytes.length);
        var prev = ivHex ? hexToBytes(ivHex) : null;
        for (var i = 0; i < dataBytes.length; i += 16) {
            var block = dataBytes.subarray(i, i + 16);
            var dec = sm4CryptBlock(block, rk);
            if (mode === 'cbc' && prev) {
                for (var j = 0; j < 16; j++) dec[j] ^= prev[j];
                prev = block;
            }
            out.set(dec, i);
        }
        return pkcs7Unpad(out);
    }

    function randomHex(len) {
        var b = new Uint8Array(len);
        crypto.getRandomValues(b);
        return bytesToHex(b);
    }

    /* ================= SM2 ================= */
    var SM2_P = hexToBigInt('fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff');
    var SM2_A = hexToBigInt('fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc');
    var SM2_B = hexToBigInt('28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93');
    var SM2_N = hexToBigInt('fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123');
    var SM2_GX = hexToBigInt('32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7');
    var SM2_GY = hexToBigInt('bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0');
    var SM2_DEFAULT_ID = '1234567890123456';

    function mod(a, m) { var r = a % m; return r < 0n ? r + m : r; }
    function powMod(base, exp, m) {
        var result = 1n;
        base = mod(base, m);
        while (exp > 0n) {
            if (exp & 1n) result = mod(result * base, m);
            base = mod(base * base, m);
            exp >>= 1n;
        }
        return result;
    }
    function invMod(a, m) { return powMod(mod(a, m), m - 2n, m); }

    function pointAdd(p1, p2) {
        if (!p1) return p2;
        if (!p2) return p1;
        var x1 = p1[0], y1 = p1[1], x2 = p2[0], y2 = p2[1];
        if (x1 === x2) {
            if (mod(y1 + y2, SM2_P) === 0n) return null;
            return pointDouble(p1);
        }
        var k = mod((y2 - y1) * invMod(x2 - x1, SM2_P), SM2_P);
        var x3 = mod(k * k - x1 - x2, SM2_P);
        var y3 = mod(k * (x1 - x3) - y1, SM2_P);
        return [x3, y3];
    }
    function pointDouble(p) {
        if (!p || p[1] === 0n) return null;
        var x = p[0], y = p[1];
        var k = mod((3n * x * x + SM2_A) * invMod(2n * y, SM2_P), SM2_P);
        var x3 = mod(k * k - 2n * x, SM2_P);
        var y3 = mod(k * (x - x3) - y, SM2_P);
        return [x3, y3];
    }
    function pointMul(k, p) {
        var result = null, addend = p;
        while (k > 0n) {
            if (k & 1n) result = pointAdd(result, addend);
            addend = pointDouble(addend);
            k >>= 1n;
        }
        return result;
    }
    function onCurve(p) {
        if (!p) return false;
        var x = p[0], y = p[1];
        return mod(y * y - (x * x * x + SM2_A * x + SM2_B), SM2_P) === 0n;
    }

    function randomModN() {
        var buf = new Uint8Array(32);
        var k;
        do {
            crypto.getRandomValues(buf);
            k = hexToBigInt(bytesToHex(buf));
        } while (k <= 1n || k >= SM2_N - 1n);
        return k;
    }

    function getZ(pubPoint, id) {
        id = id || SM2_DEFAULT_ID;
        var idBytes = utf8ToBytes(id);
        var entl = idBytes.length * 8;
        var parts = new Uint8Array(2 + idBytes.length + 32 * 6);
        parts[0] = (entl >> 8) & 0xff;
        parts[1] = entl & 0xff;
        parts.set(idBytes, 2);
        var offset = 2 + idBytes.length;
        var fields = [SM2_A, SM2_B, SM2_GX, SM2_GY, pubPoint[0], pubPoint[1]];
        for (var i = 0; i < 6; i++) {
            parts.set(hexToBytes(bigIntToHex(fields[i], 64)), offset);
            offset += 32;
        }
        return sm3Digest(parts);
    }

    function kdf(z, klen) {
        var out = new Uint8Array(klen);
        var ct = 1, offset = 0;
        var rounds = Math.ceil(klen / 32);
        for (var i = 0; i < rounds; i++) {
            var input = new Uint8Array(z.length + 4);
            input.set(z);
            input[z.length] = (ct >>> 24) & 0xff;
            input[z.length + 1] = (ct >>> 16) & 0xff;
            input[z.length + 2] = (ct >>> 8) & 0xff;
            input[z.length + 3] = ct & 0xff;
            var h = sm3Digest(input);
            var take = Math.min(32, klen - offset);
            out.set(h.subarray(0, take), offset);
            offset += take;
            ct++;
        }
        return out;
    }

    function parsePubKey(pubHex) {
        pubHex = pubHex.replace(/\s+/g, '');
        if (pubHex.length === 130 && pubHex.slice(0, 2) === '04') pubHex = pubHex.slice(2);
        if (pubHex.length !== 128) throw new Error('公钥格式错误（需 64 字节，可带 04 前缀）');
        return [hexToBigInt(pubHex.slice(0, 64)), hexToBigInt(pubHex.slice(64))];
    }

    var sm2 = {
        generateKeyPair: function () {
            var d = randomModN();
            var P = pointMul(d, [SM2_GX, SM2_GY]);
            return {
                privateKey: bigIntToHex(d, 64),
                publicKey: '04' + bigIntToHex(P[0], 64) + bigIntToHex(P[1], 64)
            };
        },
        sign: function (msg, privHex, id) {
            var d = hexToBigInt(privHex);
            var P = pointMul(d, [SM2_GX, SM2_GY]);
            var z = getZ(P, id);
            var m = new Uint8Array(z.length + msg.length);
            m.set(z); m.set(msg, z.length);
            var e = hexToBigInt(bytesToHex(sm3Digest(m)));
            var r, s, k;
            do {
                do {
                    k = randomModN();
                    var kg = pointMul(k, [SM2_GX, SM2_GY]);
                    r = mod(e + kg[0], SM2_N);
                } while (r === 0n || r + k === SM2_N);
                s = mod(invMod(1n + d, SM2_N) * (k - r * d), SM2_N);
            } while (s === 0n);
            return bigIntToHex(r, 64) + bigIntToHex(s, 64);
        },
        verify: function (msg, sigHex, pubHex, id) {
            var r = hexToBigInt(sigHex.slice(0, 64));
            var s = hexToBigInt(sigHex.slice(64, 128));
            if (r < 1n || r >= SM2_N || s < 1n || s >= SM2_N) return false;
            var P = parsePubKey(pubHex);
            if (!onCurve(P)) return false;
            var z = getZ(P, id);
            var m = new Uint8Array(z.length + msg.length);
            m.set(z); m.set(msg, z.length);
            var e = hexToBigInt(bytesToHex(sm3Digest(m)));
            var t = mod(r + s, SM2_N);
            if (t === 0n) return false;
            var point = pointAdd(pointMul(s, [SM2_GX, SM2_GY]), pointMul(t, P));
            if (!point) return false;
            return mod(e + point[0], SM2_N) === r;
        },
        encrypt: function (msgBytes, pubHex) {
            var P = parsePubKey(pubHex);
            if (!onCurve(P)) throw new Error('公钥不在曲线上');
            var c1, x2y2, t, k;
            do {
                k = randomModN();
                var kG = pointMul(k, [SM2_GX, SM2_GY]);
                c1 = hexToBytes('04' + bigIntToHex(kG[0], 64) + bigIntToHex(kG[1], 64));
                var kP = pointMul(k, P);
                x2y2 = hexToBytes(bigIntToHex(kP[0], 64) + bigIntToHex(kP[1], 64));
                t = kdf(x2y2, msgBytes.length);
            } while (t.every(function (b) { return b === 0; }));
            var c2 = new Uint8Array(msgBytes.length);
            for (var i = 0; i < msgBytes.length; i++) c2[i] = msgBytes[i] ^ t[i];
            var c3in = new Uint8Array(32 + msgBytes.length + 32);
            c3in.set(x2y2.subarray(0, 32));
            c3in.set(msgBytes, 32);
            c3in.set(x2y2.subarray(32), 32 + msgBytes.length);
            var c3 = sm3Digest(c3in);
            var out = new Uint8Array(c1.length + c3.length + c2.length);
            out.set(c1); out.set(c3, c1.length); out.set(c2, c1.length + c3.length);
            return out;
        },
        decrypt: function (dataBytes, privHex) {
            var d = hexToBigInt(privHex);
            var c1 = dataBytes.subarray(0, 65);
            if (c1[0] !== 4) throw new Error('密文 C1 格式错误');
            var p1 = [hexToBigInt(bytesToHex(c1.subarray(1, 33))), hexToBigInt(bytesToHex(c1.subarray(33, 65)))];
            if (!onCurve(p1)) throw new Error('C1 不在曲线上');
            var kP = pointMul(d, p1);
            var x2y2 = hexToBytes(bigIntToHex(kP[0], 64) + bigIntToHex(kP[1], 64));
            var c3 = dataBytes.subarray(65, 97);
            var c2 = dataBytes.subarray(97);
            var t = kdf(x2y2, c2.length);
            if (t.every(function (b) { return b === 0; })) throw new Error('KDF 输出全零');
            var msg = new Uint8Array(c2.length);
            for (var i = 0; i < c2.length; i++) msg[i] = c2[i] ^ t[i];
            var c3in = new Uint8Array(32 + msg.length + 32);
            c3in.set(x2y2.subarray(0, 32));
            c3in.set(msg, 32);
            c3in.set(x2y2.subarray(32), 32 + msg.length);
            if (bytesToHex(sm3Digest(c3in)) !== bytesToHex(c3)) throw new Error('C3 校验失败（密文或私钥错误）');
            return msg;
        }
    };

    window.SMCrypto = {
        sm3: function (input, isHex) { return sm3Hex(input, isHex); },
        sm4: {
            genKey: function () { return randomHex(16); },
            genIv: function () { return randomHex(16); },
            encryptText: function (text, keyHex, mode, ivHex) {
                return bytesToHex(sm4Encrypt(utf8ToBytes(text), keyHex, mode, ivHex));
            },
            decryptText: function (cipherHex, keyHex, mode, ivHex) {
                return bytesToUtf8(sm4Decrypt(hexToBytes(cipherHex), keyHex, mode, ivHex));
            }
        },
        sm2: {
            generateKeyPair: sm2.generateKeyPair,
            signText: function (text, privHex, id) { return sm2.sign(utf8ToBytes(text), privHex, id); },
            verifyText: function (text, sigHex, pubHex, id) { return sm2.verify(utf8ToBytes(text), sigHex, pubHex, id); },
            encryptText: function (text, pubHex) { return bytesToHex(sm2.encrypt(utf8ToBytes(text), pubHex)); },
            decryptText: function (cipherHex, privHex) { return bytesToUtf8(sm2.decrypt(hexToBytes(cipherHex), privHex)); }
        },
        utils: { hexToBytes: hexToBytes, bytesToHex: bytesToHex, randomHex: randomHex }
    };
})();
