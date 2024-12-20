const buttonEncrypt = document.querySelector('#encrypt');
const buttonDecrypt = document.querySelector('#decrypt');
const buttonClear = document.querySelector('#clear');
const keyInput = document.querySelector('#key');
const textarea = document.querySelector('#text');
const buttonGenerateKey = document.querySelector('#generate-key');


function randomPrime(bits) {
    const min = bigInt(1).shiftLeft(bits - 1);
    const max = bigInt(1).shiftLeft(bits).prev();
    while (true) {
        const p = bigInt.randBetween(min, max);
        if (p.isProbablePrime(256)) return p;
    }
}

function generateRSAKeys(bits) {
    const e = bigInt(65537); 
    let p, q, totient;

    do {
        p = randomPrime(bits / 2);
        q = randomPrime(bits / 2);
        totient = bigInt.lcm(p.prev(), q.prev());
    } while (bigInt.gcd(e, totient).notEquals(1) || p.minus(q).abs().shiftRight(bits / 2 - 100).isZero());

    const n = p.multiply(q);
    const d = e.modInv(totient);

    return {
        publicKey: [e, n],
        privateKey: [d, n],
    };
}


function encrypt(char, publicKey) {
    const [e, n] = publicKey;
    const m = bigInt(char.charCodeAt(0)); 
    return m.modPow(e, n).toString();
}


function decrypt(ciphertext, privateKey) {
    const [d, n] = privateKey;
    const c = bigInt(ciphertext);
    const decryptedCharCode = c.modPow(d, n).toJSNumber(); 
    return String.fromCharCode(decryptedCharCode); 
}


buttonGenerateKey.addEventListener('click', () => {
    const bits = 256; 
    const { publicKey, privateKey } = generateRSAKeys(bits);
    keyInput.value = `Публичный ключ: ${publicKey.map(key => key.toString()).join(', ')}\nПриватный ключ: ${privateKey.map(key => key.toString()).join(', ')}`;
});


buttonEncrypt.addEventListener('click', () => {
    const keyLines = keyInput.value.split('\n');
    if (keyLines.length < 1) {
        alert("Отсутствует публичный ключ!");
        return;
    }
    const [e, n] = keyLines[0].split(': ')[1].split(', ').map(num => bigInt(num));
    try {
        const message = textarea.value;
        let encryptedText = '';
      for (let i = 0; i < message.length; i++) {
            const encryptedChar = encrypt(message[i], [e, n]);
            encryptedText += encryptedChar + ' '; 
        }
        textarea.value = encryptedText.trim(); 
    } catch (error) {
        alert(error.message);
    }
});


buttonDecrypt.addEventListener('click', () => {
    const keyLines = keyInput.value.split('\n');
    if (keyLines.length < 2) {
        alert("Отсутствует приватный ключ!");
        return;
    }
    const [d, n] = keyLines[1].split(': ')[1].split(', ').map(num => bigInt(num));
    try {
        const ciphertext = textarea.value.split(' ');
        let decryptedText = '';
        for (let i = 0; i < ciphertext.length; i++) {
            const decryptedChar = decrypt(ciphertext[i], [d, n]);
            decryptedText += decryptedChar;
        }
        textarea.value = decryptedText;
    } catch (error) {
        alert(error.message);
    }
});

buttonClear.addEventListener('click', () => {
    textarea.value = '';
    keyInput.value = '';
});