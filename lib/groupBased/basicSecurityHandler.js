
const basicAuth = require('basic-auth');
const createError = require('http-errors');
const config = require('config');
const GroupBasedHandler = require('./groupBasedHandler').GroupBasedHandler;
const AdmFn = require('./groupBasedHandler').AdmFn;
const TenantFn = require('./groupBasedHandler').TenantFn;

/**
 * fonction de test des mots de passse.
 * Il est possible de modifier cette méthode si on souhaite encoder le mot de passe ou le contrôle
 * @param password fourni par l'utilisateur
 * @param control fourni par les crédentials
 * @returns {boolean} true si le mot de passe correspond au contrôle
 */
class PasswordChecker {
  check(password, control) {
    return password === control;
  }
}
const defaultParameters = {
  basic: {
    users: config.has('basic.users') ? config.get('basic.users') : [],
    PasswordChecker: PasswordChecker,
  },
  adminGroupRoleMapping: config.has('adminGroupRoleMapping') ? config.get('adminGroupRoleMapping') : {}
};

/**
 * @param parameters définissant le secret et les options de décodage du JWT
 * @param fn object contenant les fonctions
 * @returns {function(*=, *, *=, *=)} le handler pour la sécurité
 */
class BasicSecurityHandler extends GroupBasedHandler{
/**
 * Handler de l'authentification par username/password. Génère une erreur si les données transmises sont invalides.
 * Sinon les informations (user, roles,...) sont disponibles dans la configuration ensuite la main est passée au
 * controller qui doit vérifier que l'utilisateur à bien les droits nécessaires.
 * @param req requête
 */
  handle(req) {
    try {
      const credential = basicAuth(req);
      if (!credential) throw Error("no authorization");
      const basicParameters = Object.assign({},
        defaultParameters.basic,
        this.parameters && this.parameters.basic);

      // Recherche de l'utilisateur dans la table
      const passwordChecker = new basicParameters.PasswordChecker();
      const user = credential && basicParameters.users.find(u =>
        u.username === credential.name && passwordChecker.check(u.password, credential.pass)
      );

      if (user) {
        const adminGroupRoleMapping = (this.parameters || defaultParameters).adminGroupRoleMapping;
        return this.$authentification(
          req,
          adminGroupRoleMapping,
          Object.assign(user, { authorization: req.headers.authorization })
        );
      }
      else {
        return createError(401,`Unauthorized "invalid name / password"`);
      }
    }
    catch (err) {
      return createError(401,`Unauthorized "invalid basic authentication"`);
    }
  }
}


/**
 * Handler pour le securityDefinitions Bearer
 * Si d'autres modèles de sécurités sont créés il faut les ajouter ici
 */
module.exports = {
  Basic: (allowedRoles, parameters) => new BasicSecurityHandler('Basic for Tenant', new TenantFn(), allowedRoles, parameters),
  BasicAdm: (allowedRoles, parameters) => new BasicSecurityHandler('Basic for Admin', new AdmFn(), allowedRoles, parameters),
  BasicSecurityHandler,
};
