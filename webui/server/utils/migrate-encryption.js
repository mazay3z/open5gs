// webui/server/utils/migrate-encryption.js
const mongoose = require('mongoose');
const cryptoService = require('./crypto');

// Функция миграции существующих подписчиков в зашифрованный формат
async function migrateExistingSubscribers() {
  try {
    const Subscriber = require('../models/subscriber');
    
    console.log('Starting migration of existing subscribers to encrypted format...');
    
    // Поиск всех подписчиков с данными безопасности в открытом тексте
    const subscribers = await Subscriber.find({}).lean();
    
    let migratedCount = 0;
    
    for (const subscriber of subscribers) {
      if (subscriber.security) {
        let needsUpdate = false;
        const updates = {};
        
        // Проверка, не зашифрованы ли ключи (не содержат разделитель ':')
        if (subscriber.security.k && !subscriber.security.k.includes(':')) {
          try {
            updates['security.k'] = cryptoService.encrypt(subscriber.security.k);
            needsUpdate = true;
          } catch (error) {
            console.error(`Failed to encrypt KI for subscriber ${subscriber.imsi}:`, error.message);
          }
        }
        
        if (subscriber.security.op && !subscriber.security.op.includes(':')) {
          try {
            updates['security.op'] = cryptoService.encrypt(subscriber.security.op);
            needsUpdate = true;
          } catch (error) {
            console.error(`Failed to encrypt OP for subscriber ${subscriber.imsi}:`, error.message);
          }
        }
        
        if (subscriber.security.opc && !subscriber.security.opc.includes(':')) {
          try {
            updates['security.opc'] = cryptoService.encrypt(subscriber.security.opc);
            needsUpdate = true;
          } catch (error) {
            console.error(`Failed to encrypt OPC for subscriber ${subscriber.imsi}:`, error.message);
          }
        }
        
        if (needsUpdate) {
          try {
            // Обновление записи в базе данных напрямую, минуя хуки Mongoose для избежания двойного шифрования
            await Subscriber.collection.updateOne(
              { _id: subscriber._id }, 
              { $set: updates }
            );
            migratedCount++;
            console.log(`Migrated subscriber: ${subscriber.imsi}`);
          } catch (error) {
            console.error(`Failed to update subscriber ${subscriber.imsi}:`, error.message);
          }
        }
      }
    }
    
    console.log(`Migration completed. Migrated ${migratedCount} subscribers.`);
    return migratedCount;
    
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  }
}

// Функция проверки количества незашифрованных записей
async function checkUnencryptedCount() {
  try {
    const Subscriber = require('../models/subscriber');
    
    const subscribers = await Subscriber.find({}).lean();
    let unencryptedCount = 0;
    
    for (const subscriber of subscribers) {
      if (subscriber.security) {
        if ((subscriber.security.k && !subscriber.security.k.includes(':')) ||
            (subscriber.security.op && !subscriber.security.op.includes(':')) ||
            (subscriber.security.opc && !subscriber.security.opc.includes(':'))) {
          unencryptedCount++;
        }
      }
    }
    
    console.log(`Found ${unencryptedCount} subscribers with unencrypted authentication keys.`);
    return unencryptedCount;
    
  } catch (error) {
    console.error('Check failed:', error);
    throw error;
  }
}

// Запуск миграции при прямом вызове скрипта
if (require.main === module) {
  // Проверка переменной окружения для ключа шифрования
  if (!process.env.OPEN5GS_CRYPTO_KEY) {
    console.warn('WARNING: OPEN5GS_CRYPTO_KEY environment variable not set. Using default key.');
    console.warn('For production use, please set OPEN5GS_CRYPTO_KEY environment variable.');
  }

  mongoose.connect(process.env.DB_URI || 'mongodb://localhost/open5gs', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  }).then(async () => {
    console.log('Connected to MongoDB');
    
    // Сначала проверяем количество незашифрованных записей
    const unencryptedCount = await checkUnencryptedCount();
    
    if (unencryptedCount === 0) {
      console.log('No migration needed. All authentication keys are already encrypted.');
      process.exit(0);
    }
    
    // Запрашиваем подтверждение пользователя
    console.log(`About to migrate ${unencryptedCount} subscribers. Press Ctrl+C to cancel or wait 5 seconds to continue...`);
    
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Выполняем миграцию
    await migrateExistingSubscribers();
    
    process.exit(0);
  }).catch(error => {
    console.error('Database connection failed:', error);
    process.exit(1);
  });
}

module.exports = { 
  migrateExistingSubscribers,
  checkUnencryptedCount 
};