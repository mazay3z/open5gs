const mongoose = require('mongoose');
const Schema = mongoose.Schema;
require('mongoose-long')(mongoose);
// ДОБАВЛЕНО: Импорт криптографического сервиса для шифрования ключей аутентификации
const cryptoService = require('../utils/crypto');


const Subscriber = new Schema({

  schema_version: {
    $type: Number,
    default: 1  // Current Schema Version
  },

  imsi: { $type: String, unique: true, required: true },

  msisdn: [ String ],
  imeisv: [ String ],
  mme_host: [ String ],
  mme_realm: [ String ],
  purge_flag: [ Boolean ],

  security: {
    k: String,
    op: String,
    opc: String,
    amf: String,
    rand: String,
    sqn: Schema.Types.Long
  },

  ambr: {
    downlink: { value: Number, unit: Number },
    uplink: { value: Number, unit: Number }
  },

  slice: [{
    sst: { $type: Number, required: true },
    sd: String,
    default_indicator: Boolean,
    session: [{
      name: { $type: String, required: true }, // DNN or APN
      type: Number,
      qos: {
        index: Number, // 5QI or QCI
        arp: {
          priority_level: Number,
          pre_emption_capability: Number,
          pre_emption_vulnerability: Number,
        }
      },
      ambr: {
        downlink: { value: Number, unit: Number },
        uplink: { value: Number, unit: Number }
      },
      ue: {
        ipv4: String,
        ipv6: String
      },
      smf: {
        ipv4: String,
        ipv6: String
      },
      pcc_rule: [{
        flow: [{
          direction: Number,
          description: String
        }],
        qos: {
          index: Number, // 5QI or QCI
          arp: {
            priority_level: Number,
            pre_emption_capability: Number,
            pre_emption_vulnerability: Number,
          },
          mbr: {
            downlink: { value: Number, unit: Number },
            uplink: { value: Number, unit: Number }
          },
          gbr: {
            downlink: { value: Number, unit: Number },
            uplink: { value: Number, unit: Number }
          },
        },
      }],

      lbo_roaming_allowed: Boolean

    }]
  }],

  access_restriction_data: {
    $type: Number,
    default: 32 // Handover to Non-3GPP Access Not Allowed
  },
  subscriber_status: {
    $type: Number,
    default: 0  // Service Granted
  },
  operator_determined_barring: {
    $type: Number,
    default: 0 // No barring
  },
  network_access_mode: {
    $type: Number,
    default: 0 // Packet and Circuit
  },
  subscribed_rau_tau_timer: {
    $type: Number,
    default: 12 // minites
  }

}, { typeKey: '$type' });

// ДОБАВЛЕНО: Хук перед сохранением для шифрования ключей аутентификации
Subscriber.pre('save', function(next) {
  if (this.security) {
    try {
      // Шифровать только если данные были изменены или являются новыми
      if (this.isModified('security.k') && this.security.k) {
        // Удаление пробелов и проверка, не зашифрован ли уже ключ
        const cleanKey = this.security.k.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          this.security.k = cryptoService.encrypt(cleanKey);
        }
      }
      if (this.isModified('security.op') && this.security.op) {
        const cleanKey = this.security.op.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          this.security.op = cryptoService.encrypt(cleanKey);
        }
      }
      if (this.isModified('security.opc') && this.security.opc) {
        const cleanKey = this.security.opc.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          this.security.opc = cryptoService.encrypt(cleanKey);
        }
      }
    } catch (error) {
      console.error('Authentication key encryption error for subscriber:', this.imsi, error);
      return next(error);
    }
  }
  next();
});

// ДОБАВЛЕНО: Хуки перед обновлением для findOneAndUpdate и updateOne
Subscriber.pre(['findOneAndUpdate', 'updateOne'], function(next) {
  const update = this.getUpdate();
  
  if (update.$set && update.$set.security) {
    try {
      if (update.$set.security.k) {
        const cleanKey = update.$set.security.k.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.$set.security.k = cryptoService.encrypt(cleanKey);
        }
      }
      if (update.$set.security.op) {
        const cleanKey = update.$set.security.op.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.$set.security.op = cryptoService.encrypt(cleanKey);
        }
      }
      if (update.$set.security.opc) {
        const cleanKey = update.$set.security.opc.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.$set.security.opc = cryptoService.encrypt(cleanKey);
        }
      }
    } catch (error) {
      console.error('Authentication key encryption error during update:', error);
      return next(error);
    }
  }
  
  if (update.security) {
    try {
      if (update.security.k) {
        const cleanKey = update.security.k.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.security.k = cryptoService.encrypt(cleanKey);
        }
      }
      if (update.security.op) {
        const cleanKey = update.security.op.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.security.op = cryptoService.encrypt(cleanKey);
        }
      }
      if (update.security.opc) {
        const cleanKey = update.security.opc.replace(/\s/g, '');
        if (!cleanKey.includes(':')) {
          update.security.opc = cryptoService.encrypt(cleanKey);
        }
      }
    } catch (error) {
      console.error('Authentication key encryption error during update:', error);
      return next(error);
    }
  }
  
  next();
});

// ДОБАВЛЕНО: Хуки после поиска для дешифрования данных при чтении из базы данных
Subscriber.post(['find', 'findOne', 'findOneAndUpdate'], function(docs) {
  if (!docs) return;
  
  const processDoc = (doc) => {
    if (doc && doc.security) {
      try {
        doc.security = cryptoService.decryptSecurityData(doc.security);
      } catch (error) {
        console.error('Authentication key decryption error for subscriber:', doc.imsi, error);
        // Не выбрасывать ошибку, чтобы не сломать приложение
        // В случае ошибки дешифрования, данные остаются зашифрованными
      }
    }
  };
  
  if (Array.isArray(docs)) {
    docs.forEach(processDoc);
  } else {
    processDoc(docs);
  }
});

module.exports = mongoose.model('Subscriber', Subscriber);
