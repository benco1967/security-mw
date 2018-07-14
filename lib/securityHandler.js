
const error = require('debug')("security-mw:error");
const createError = require('http-errors');

/**
 * Classe abstraite de base d'un handler de sécurité. Pour que ce mécanisme puisse fonctionner avec un multi-tenant, il
 * faut que le tenant ait été extrait au préalable par le middleware TenantLoader
 */
class SecurityHandler {
  /**
   *
   * @param name le nom d'identification utilisé dans les traces
   * @param parameters optionnels permettant de redéfinir les paramètres de la configuration (utilisé pour le test)
   */
  constructor(name, parameters) {
    this.name = name;
    this.parameters = parameters;
  }

  /**
   * Méthode principale retournant si la requête est authentifiée et autorisée
   * @param req requête à traiter
   * @returns {boolean|Error} l'erreur, false si l'authentification est ok, sinon retourne un object Error
   */
  handle(req) {
    error('No authorization protocols defined, you should define one');
    return createError(401,`Unauthorized "No authorization protocols defined"`);
  }

}

module.exports = {
  SecurityHandler
};
