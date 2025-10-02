const express = require('express');
const router = express.Router();
// ДОБАВЛЕНО: Импорт криптографического сервиса для валидации ключей
const cryptoService = require('../utils/crypto');


const restify = require('express-restify-mongoose')

const Subscriber = require('../models/subscriber');


// ДОБАВЛЕНО: Промежуточное ПО для предварительной обработки данных подписчиков
const preprocessSubscriber = (req, res, next) => {
  if (req.body && req.body.security) {
    try {
      // Проверка, являются ли ключи замаскированными (звездочками)
      const isMasked = (key) => key && key.startsWith('*') && key.length === 32;
      
      // Если ключи замаскированы, удаляем их из запроса, чтобы не перезаписывать существующие значения
      if (isMasked(req.body.security.k)) {
        delete req.body.security.k;
      }
      if (isMasked(req.body.security.op)) {
        delete req.body.security.op;
      }
      if (isMasked(req.body.security.opc)) {
        delete req.body.security.opc;
      }
      
      // Валидация формата ключей аутентификации перед шифрованием (только для незамаскированных ключей)
      const { k, op, opc } = req.body.security || {};
      
      if (k && !/^[A-Fa-f0-9\s]{32,}$/.test(k.replace(/\s/g, ''))) {
        return res.status(400).json({
          error: 'Неверный формат KI. Должно быть 32 шестнадцатеричных символа.'
        });
      }
      
      if (op && !/^[A-Fa-f0-9\s]{32,}$/.test(op.replace(/\s/g, ''))) {
        return res.status(400).json({
          error: 'Неверный формат OP. Должно быть 32 шестнадцатеричных символа.'
        });
      }
      
      if (opc && !/^[A-Fa-f0-9\s]{32,}$/.test(opc.replace(/\s/g, ''))) {
        return res.status(400).json({
          error: 'Неверный формат OPC. Должно быть 32 шестнадцатеричных символа.'
        });
      }
      
      // Удаление пробелов из ключей перед шифрованием (только для незамаскированных ключей)
      if (req.body.security && req.body.security.k) {
        req.body.security.k = req.body.security.k.replace(/\s/g, '');
      }
      if (req.body.security && req.body.security.op) {
        req.body.security.op = req.body.security.op.replace(/\s/g, '');
      }
      if (req.body.security && req.body.security.opc) {
        req.body.security.opc = req.body.security.opc.replace(/\s/g, '');
      }
      
    } catch (error) {
      return res.status(500).json({
        error: 'Failed to process authentication keys: ' + error.message
      });
    }
  }
  next();
};

// ДОБАВЛЕНО: Применение промежуточного ПО предварительной обработки к маршрутам подписчиков
router.use('/Subscriber*', preprocessSubscriber);

// ИЗМЕНЕНО: Расширенные настройки для маршрутов подписчиков с логированием
restify.serve(router, Subscriber, {
  prefix: '',
  version: '',
  idProperty: 'imsi',
  preMiddleware: function(req, res, next) {
    // Дополнительное логирование операций безопасности
    if (req.method === 'POST' || req.method === 'PUT') {
      console.log(`Authentication key operation: ${req.method} for subscriber`);
    }
    next();
  },
  postProcess: function(req, res, next) {
    // Логирование успешных операций
    if (res.statusCode >= 200 && res.statusCode < 300) {
      console.log(`Successfully processed ${req.method} request for subscriber`);
    }
    // Проверяем, что next существует и является функцией перед вызовом
    if (next && typeof next === 'function') {
      next();
    }
  }
});


// restify.serve(router, Subscriber, {
//   prefix: '',
//   version: '',
//   idProperty: 'imsi'
// });

const Profile = require('../models/profile');
restify.serve(router, Profile, {
  prefix: '',
  version: ''
});

const Account = require('../models/account');
restify.serve(router, Account, {
  prefix: '',
  version: '',
  idProperty: 'username'
});

module.exports = router;