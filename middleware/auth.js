function requireAuth(req, res, next) {
  if (!req.session || !req.session.name) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  if (req.session.userType !== 'admin') {
    return res.status(403).send('Forbidden: Admins only');
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
