const { NotImplementedError } = require('../extensions/index.js');

/**
 * Implement class VigenereCipheringMachine that allows us to create
 * direct and reverse ciphering machines according to task description
 *
 * @example
 *
 * const directMachine = new VigenereCipheringMachine();
 *
 * const reverseMachine = new VigenereCipheringMachine(false);
 *
 * directMachine.encrypt('attack at dawn!', 'alphonse') => 'AEIHQX SX DLLU!'
 *
 * directMachine.decrypt('AEIHQX SX DLLU!', 'alphonse') => 'ATTACK AT DAWN!'
 *
 * reverseMachine.encrypt('attack at dawn!', 'alphonse') => '!ULLD XS XQHIEA'
 *
 * reverseMachine.decrypt('AEIHQX SX DLLU!', 'alphonse') => '!NWAD TA KCATTA'
 *
 */
class VigenereCipheringMachine {

  constructor(isDirect = true) {
    this.isDirect = isDirect;
  }

  checkArguments(message, key) {
    if (!message || !key) {
      throw new Error('Incorrect arguments!');
    }
  }

  transformMessage(message, key, encrypt) {
    this.checkArguments(message, key);

    const messageUpper = message.toUpperCase();
    const keyUpper = key.toUpperCase();
    let result = '';

    for (let i = 0, j = 0; i < messageUpper.length; i++) {
      const char = messageUpper[i];

      if (char >= 'A' && char <= 'Z') {
        const shift = keyUpper[j % keyUpper.length].charCodeAt(0) - 'A'.charCodeAt(0);
        const charCode = encrypt
          ? (char.charCodeAt(0) + shift - 'A'.charCodeAt(0)) % 26 + 'A'.charCodeAt(0)
          : (char.charCodeAt(0) - shift + 26 - 'A'.charCodeAt(0)) % 26 + 'A'.charCodeAt(0);
        result += String.fromCharCode(charCode);
        j++;
      } else {
        result += char;
      }
    }

    return this.isDirect ? result : result.split('').reverse().join('');
  }

  encrypt(message, key) {
    return this.transformMessage(message, key, true);
  }
  decrypt(encryptedMessage, key) {
    return this.transformMessage(encryptedMessage, key, false);
  }
}

module.exports = {
  VigenereCipheringMachine
};
