# Contrôle d'accès pour les routes
Ce middleware permet d'ajouter un contrôle d'accès à une route. Il lève
une Error si l'autorisation n'est pas acceptable, et initialise le
paramètre personnalisé `user` si l'accès est accordé.

## Présentation


## Exemples d'utilisation

### Installation
```
npm install --save git+ssh://git@git.intra-know.com/Yieloo/Copernik/middlewares/security-mw.git
```

### Ajout du middleware

```javascript
const express = require('express');
const security = require('./api/middlewares/security-mw');
const app = express();

app.use(require('./api/middlewares/customParams'));

// Restriction de la route pour les 'adm'
const basicAdm = security.Basic(['adm']);
const bearerAdm = security.Bearer(['adm']);
const securityAdm = new security.GroupBasedHandler(basicAdm, bearerAdm).mw();
app.use('/admin', securityAdm);

// Restriction de la route pour les 'usr'
const basicUsr = security.Basic(['urs']);
const bearerUsr = security.Bearer(['usr']);
const securityUsr = new security.GroupBasedHandler(basicUsr, bearerUsr).mw();
app.param('tenant', require('pre-loader-mw')(options));
app.use('/:tenant', securityUsr);
app.use('/:tenant', (req, res, next) => {
  //...
  const tenant = req.getPrm('tenant');
  const user = req.getPrm('user');
});

// Gestion des erreurs
app.use((err, res, req, next) => {

  let msg = 'Unknow server error';
  let status = 500;
  // An Error with statusCode
  if (err instanceof Error) {
    if (err.statusCode) {
      status = err.statusCode;
    }
    message = err.message;
  }
  else {
    // try to find message and status
    // else error 500
    if (err.message) {
      message = err.message;
      status = err.statusCode || err.status || 500;
    }
    else if(typeof err === 'string') {
      message = err;
    }
  }
  if (status === 401) {
    res.set("WWW-Authenticate", `Basic realm="Authentication requise", charset="UTF-8"`);
  }
  res.status(status).json({ status, message });

});
```
