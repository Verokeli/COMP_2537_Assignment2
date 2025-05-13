function requireAuth(req, res, next) {
  if (!req.session || !req.session.name) {
    return res.redirect("/");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403");
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
