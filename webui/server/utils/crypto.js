const crypto = require('crypto');

class CryptoService {
  constructor() {
    // Получение ключа шифрования из переменной окружения или использование значения по умолчанию для разработки
    this.encryptionKey = process.env.OPEN5GS_CRYPTO_KEY || 'open5gs_default_key_32_chars!!!';
    this.algorithm = 'aes-256-gcm';
    this.keyBuffer = crypto.scryptSync(this.encryptionKey, 'salt', 32);
  }

  /**
   * Шифрование чувствительных ключей аутентификации
   * @param {string} text - Открытый текст для шифрования
   * @returns {string} - Зашифрованный текст с IV и тегом аутентификации
   */
  encrypt(text) {
    if (!text || text === '') return text;
    
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(this.algorithm, this.keyBuffer);
      cipher.setAAD(Buffer.from('open5gs-auth-data', 'utf8'));
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Объединение IV, тега аутентификации и зашифрованных данных
      const combined = iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
      return combined;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt authentication key');
    }
  }

  /**
   * Дешифрование чувствительных ключей аутентификации
   * @param {string} encryptedText - Зашифрованный текст с IV и тегом аутентификации
   * @returns {string} - Расшифрованный открытый текст
   */
  decrypt(encryptedText) {
    if (!encryptedText || encryptedText === '') return encryptedText;
    
    // Проверка, не расшифрованы ли уже данные (обратная совместимость)
    if (!encryptedText.includes(':')) {
      return encryptedText;
    }
    
    try {
      const parts = encryptedText.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const authTag = Buffer.from(parts[1], 'hex');
      const encrypted = parts[2];
      
      const decipher = crypto.createDecipher(this.algorithm, this.keyBuffer);
      decipher.setAAD(Buffer.from('open5gs-auth-data', 'utf8'));
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt authentication key');
    }
  }

  /**
   * Шифрование объекта безопасности аутентификации
   * @param {Object} security - Объект безопасности, содержащий k, op, opc
   * @returns {Object} - Объект безопасности с зашифрованными ключами
   */
  encryptSecurityData(security) {
    if (!security) return security;
    
    const encryptedSecurity = { ...security };
    
    if (security.k) {
      encryptedSecurity.k = this.encrypt(security.k);
    }
    if (security.op) {
      encryptedSecurity.op = this.encrypt(security.op);
    }
    if (security.opc) {
      encryptedSecurity.opc = this.encrypt(security.opc);
    }
    
    return encryptedSecurity;
  }

  /**
   * Дешифрование объекта безопасности аутентификации
   * @param {Object} security - Объект безопасности с зашифрованными ключами
   * @returns {Object} - Объект безопасности с расшифрованными ключами
   */
  decryptSecurityData(security) {
    if (!security) return security;
    
    const decryptedSecurity = { ...security };
    
    if (security.k) {
      decryptedSecurity.k = this.decrypt(security.k);
    }
    if (security.op) {
      decryptedSecurity.op = this.decrypt(security.op);
    }
    if (security.opc) {
      decryptedSecurity.opc = this.decrypt(security.opc);
    }
    
    return decryptedSecurity;
  }

  /**
   * ДОБАВЛЕНО: Проверка конфигурации ключа шифрования и возврат предупреждений
   * @returns {Array} - Массив предупреждений о безопасности
   */
  checkEncryptionKey() {
    const warnings = [];
    const defaultKey = 'open5gs_default_key_32_chars!!!';
    
    // Проверка, используется ли ключ по умолчанию
    if (this.encryptionKey === defaultKey) {
      warnings.push('Default encryption key is being used!');
      warnings.push('Set OPEN5GS_CRYPTO_KEY environment variable for production.');
      warnings.push('Example: export OPEN5GS_CRYPTO_KEY="your_secret_key_32_characters"');
    }
    
    // Проверка отсутствия переменной окружения
    if (!process.env.OPEN5GS_CRYPTO_KEY) {
      warnings.push('OPEN5GS_CRYPTO_KEY environment variable is not set.');
    }
    
    // Проверка длины ключа
    if (this.encryptionKey.length < 32) {
      warnings.push('Encryption key is too short. Minimum 32 characters recommended.');
    }
    
    return warnings;
  }
}



module.exports = new CryptoService();