'use strict';

const basic = require('./lib/groupBased/basicSecurityHandler');
const bearer = require('./lib/groupBased/bearerSecurityHandler');
const common = require('./lib/groupBased/groupBasedHandler');
const security = require('./lib/security');

module.exports = {
  security,
  SecurityHandler: common.GroupBasedHandler,
  Basic: basic.Basic,
  BasicAdm: basic.BasicAdm,
  Bearer: bearer.Bearer,
  BearerAdm: bearer.BearerAdm,
};
