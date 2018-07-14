const info = require('debug')("security-mw:security");
const createError = require('http-errors');

/**
 * Retourne la fonction de middleware celle-ci demande à chaque handler si l'autorisation est accordée ou non
 * @param handlers liste des handlers gérant l'authentification, chaque handler étend la classe SecurityHandler.
 * @returns {Function} la fonction de middleware utilisable par express
 */
module.exports = (...handlers) => {
  return (req, res, next) => {
    Promise
      // récupère toutes les promesses
      .all(handlers.map(h => h.handle(req)))
      // trouve la première autorisation qui passe ou le message d'erreur avec le code le plus élevé 403 > 401
      .then(errs => errs.reduce(
        (a, err) => !a || !err ? null : a.statusCode > err.statusCode ? a : err,
        new createError.Unauthorized('No security provided'))
      )
      // gestion de la réponse finale
      .then(err => {
        if (err) {
          // si err existe c'est qu'il a refus d'accès et on retourne une erreur d'authentification 401 ou 403 selon le cas
          info(`not allowed ${err}`);
          next(err);
        }
        else {
          // sinon c'est que l'un des handlers a répondu positivement à la demande d'accès
          next();
        }
      });
    };
  };
