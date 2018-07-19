const expect = require('chai').expect;
const jwt = require('jsonwebtoken');
process.env.NODE_ENV = 'test';
const config = require('config');
const customParams = require('req-custom')();
const security = require('../index').security;



const parametersBearerWithIssAud = {
  bearer: {
    secret: "secret",
    options: {
      issuer: "test",
      audience: /test/
    }
  },
  adminGroupRoleMapping: { admin: ["adm"] },
};
const bearerSecurityHandler1 = require('../index').Bearer(['adm'], parametersBearerWithIssAud);

const parametersBearer = {
  bearer: {
    secret: "secret",
    options: {}
  },
  adminGroupRoleMapping: { admin: ["adm"] },
};
const bearerSecurityHandler2 = require('../index').Bearer(['adm'], parametersBearer);
const bearerSecurityHandler3 = require('../index').Bearer(['usr'], parametersBearer);

const parametersBasic = {
  adminGroupRoleMapping: { admin: ["adm"] },
};

const requestMock = {
  headers : {},
  get: () => undefined
};
customParams(requestMock);

const bearerRequestMock = (payload, parameters) => {
  const req = {
    headers : {
      authorization: "Bearer " + jwt.sign(payload, parameters.bearer.secret),
    },
    get: (header) => header.match(/^authorization$/i) ? "Bearer " + jwt.sign(payload, parameters.bearer.secret) : undefined
  };
  customParams(req);
  return req;
};

const adminPayload = {
  iss: "test",
  aud: "test and other value",
  sub: "test@example.com",
  Usr: "admin",
  Grp: { admin: [ "admin" ], test: ["admin"] },
};

const userPayload = {
  iss: "test",
  aud: "test and other value",
  sub: "test@example.com",
  Usr: "user",
  Grp: { admin: [ "users" ], test: ["users"] },
};

function userMatch(req) {
  expect(req.getPrm("user")).to.have.property('userId', "admin");
  expect(req.getPrm("user")).to.have.deep.property('groups', {  admin: ["admin"] });
  expect(req.getPrm("user")).to.have.deep.property('roles', ['adm', 'mng', 'snd', 'usr']);
}

describe('Bearer Security Handler', function() {
  function testValidUser(req, done, payload, groupName) {
    return function (err) {
      expect(err).to.be.null;
      expect(req.getPrm("user")).to.exist;
      expect(req.getPrm("user")).to.have.property('userId', payload.Usr);
      const groups = {};
      groups[groupName] = payload.Grp.admin;
      expect(req.getPrm("user")).to.have.deep.property('groups', groups);
      done();
    }
  }

  describe('Direct test with function without check of issuer and audience', function() {

    it('Valid token without check of issuer and audience', function(done) {
      const req = bearerRequestMock(Object.assign({}, adminPayload), parametersBearer);
      bearerSecurityHandler2.handle(req)
        .then(testValidUser(req, done, adminPayload, 'admin'));
    });

    it('Valid token without enough right', function(done) {
      const req = bearerRequestMock(Object.assign({}, userPayload), parametersBearer);
      bearerSecurityHandler2.handle(req)
        .then(function(err) {
          expect(err).to.exist;
          expect(err).to.have.property('statusCode', 403);
          expect(err).to.have.property('message');
          expect(err.message).to.match(/denies access/);
          done();
        });
    });

    it('Valid token with limited right with a tenant', function(done) {
      const req = bearerRequestMock(Object.assign({}, userPayload), parametersBearer);
      req.setPrm('tenant', { value: { id: 'test', groupRoleMapping: { users: ['usr'] } } });
      bearerSecurityHandler3.handle(req)
        .then(testValidUser(req, done, userPayload, 'test'));
    });

    it('Invalid token', function(done) {
      bearerSecurityHandler2.handle(requestMock)
        .then(function(err) {
          expect(err).to.exist;
          expect(err).to.have.property('statusCode', 401);
          expect(err).to.have.property('message');
          expect(err.message).to.match(/wrong Authorization protocol/);
          done();
        });
    });

  });

  describe('Direct test with function with issuer and audience', function() {

    it('Valid token', function(done) {
      const req = bearerRequestMock(Object.assign({}, adminPayload), parametersBearer);
      bearerSecurityHandler1.handle(req)
        .then(testValidUser(req, done, adminPayload, 'admin'));
    });

    it('Valid token with wrong issuer', function(done) {
      bearerSecurityHandler1.handle(bearerRequestMock(Object.assign({}, adminPayload, { iss: "wrongIssuer" }), parametersBearerWithIssAud))
        .then(function(err) {
          expect(err).to.exist;
          expect(err).to.have.property('statusCode', 401);
          expect(err).to.have.property('message');
          expect(err.message).to.match(/jwt issuer invalid/);
          done();
        });
    });

    it('Valid token with wrong aud', function(done) {
      bearerSecurityHandler1.handle(bearerRequestMock(Object.assign({}, adminPayload, { aud: "not the good one" }), parametersBearerWithIssAud))
        .then(function(err) {
          expect(err).to.exist;
          expect(err).to.have.property('statusCode', 401);
          expect(err).to.have.property('message');
          expect(err.message).to.match(/jwt audience invalid/);
          done();
        });
    });

  });

});

const basicRequestMock = (authorization) => {
  const req = {
    headers: {
      authorization: "Basic " + authorization,
    },
    get: (header) => header.match(/^authorization$/i) ? "Basic " + authorization : undefined
  };
  customParams(req);
  return req;
};

const basicSecurityHandler = require('../lib/groupBased/basicSecurityHandler').Basic(['adm'], {...config.get('security'), ...parametersBasic});

describe('Basic Security Handler', function() {

  describe('Direct test with function', function() {

    it('Valid authentification admin', function() {
      const req = basicRequestMock("YWRtaW46YWRtaW4=");
      const err = basicSecurityHandler.handle(req);
      expect(err).to.be.null;
      expect(req.getPrm("user")).to.exist;
      userMatch(req);
    });

    it('valid authentification but wrong user', function() {
      const err = basicSecurityHandler.handle(basicRequestMock("d2hhdGV2ZXI6d2hhdGV2ZXI="));// bad authentication
      expect(err).to.be.not.null;
      expect(err).to.have.property('statusCode', 401);
      expect(err).to.have.property('message');
      expect(err.message).to.match(/invalid name \/ password/);
    });

    it('Invalid authentification', function() {
      const err = basicSecurityHandler.handle(requestMock);// no authentication
      expect(err).to.exist;
      expect(err).be.not.equals(false);
      expect(err).to.have.property('statusCode', 401);
      expect(err).to.have.property('message');
      expect(err.message).to.match(/invalid basic authentication/);
    });

  });

});

const securityMiddleware = security(basicSecurityHandler, bearerSecurityHandler2);
const responseMock = callback => ({
  code: undefined,
  headers: {},
  result: undefined,
  status: function(c) {
    this.code = c;
    return this;
  },
  json: function(j) {
    this.result = j;
    callback(this);
    return this;
  },
  set: function(h, v) {
    this.headers[h.toLowerCase()] = v;
    return this;
  }
});

describe('Basic+Bearer Security Handler', function() {

  describe('Direct call to the middleware', function() {

    function testValidUser(req, done) {
      securityMiddleware(req, responseMock(() => {
        expect(req.getPrm("user")).to.exist;
        done();
      }), () => {
        expect(req.getPrm("user")).to.exist;
        userMatch(req);
        done();
      });
    }

    it('Valid Basic authentification admin', function(done) {
      const req = basicRequestMock("YWRtaW46YWRtaW4=");
      testValidUser(req, done);
    });

    it('Valid Bearer authentification admin', function(done) {
      const req = bearerRequestMock(Object.assign({}, adminPayload), parametersBearerWithIssAud);
      testValidUser(req, done);
    });

    it('Valid no authentification', function(done) {

      securityMiddleware(requestMock, responseMock(() => {}), (err) => {
        expect(requestMock.getPrm("user")).to.not.exist;
        expect(err).to.exist;
        expect(err).to.have.property('statusCode', 401);
        expect(err).to.have.property('message');
        expect(err.message).to.match(/Unauthorized/);
        done();
      });
    });
  });
});
