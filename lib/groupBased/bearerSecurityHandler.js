
const jwt = require('jsonwebtoken');
const fs = require('fs');
const createError = require('http-errors');
const GroupBasedHandler = require('./groupBasedHandler').GroupBasedHandler;
const TenantFn = require('./groupBasedHandler').TenantFn;
const AdmFn = require('./groupBasedHandler').AdmFn;

// Paramètres de configuration initalement vide se remplit lorsque la promesse d'initialisation est remplie
const defaultParameters = {
  bearer: {
    sharedSecret: "secret",
    options: {
    }
  },
  // mapping utilisé lorsqu'il n'y a pas de tenant i.e. l'administration du service
  adminGroupRoleMapping: {},
};

/**
 * @param parameters définissant le secret et les options de décodage du JWT
 * @param fn object contenant les fonctions
 * @returns {function(*=, *, *=, *=)} le handler pour la sécurité
 */
class BearerSecurityHandler extends GroupBasedHandler {

  /**
   * Handler de l'authentification par JWT. Génère une erreur si aucun token ou un token invalide est transmit. Sinon les
   * informations (user, roles,...) du token sont disponibles dans le champ req.authenticationToken, ensuite la main est
   * passée au controller qui doit vérifier que l'utilisateur à bien les droits nécessaires.
   * @param req requête
   */
  handle(req) {
    const usedParameters = {
      adminGroupRoleMapping: this.parameters &&
        this.parameters.adminGroupRoleMapping || defaultParameters.adminGroupRoleMapping,
      bearer: Object.assign({}, defaultParameters.bearer, this.parameters && this.parameters.bearer)
    };

    const authorizationHeader = req.get('Authorization');
    return new Promise((resolve) => {
      if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
        resolve(createError(401,`Unauthorized "wrong Authorization protocol"`));
      }
      else {
        jwt.verify(authorizationHeader.split(' ')[1], usedParameters.bearer.sharedSecret, usedParameters.bearer.options, (err, token) => {
          if (err) {
            resolve(createError(401,`Unauthorized "${err.name}: ${err.message}"`));
          }
          else {
            resolve(this.$authentification(req, usedParameters.adminGroupRoleMapping, {authorization: authorizationHeader, userId: token.Usr, groups: token.Grp}));
          }
        });
      }
    });
  }
}



/**
 * Handler pour le securityDefinitions Bearer
 */
module.exports = {
  Bearer: (allowedRoles, parameters) => new BearerSecurityHandler('Bearer for Tenant', new TenantFn(), allowedRoles, parameters),
  BearerAdm: (allowedRoles, parameters) => new BearerSecurityHandler('Bearer for Admin', new AdmFn(), allowedRoles, parameters),
};
