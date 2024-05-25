const roleValidation = (roles) => {
    return (req, res, next) => {
      if (!roles.includes(req.payload.role)) {
        return res.status(403).json({ message: "Access forbidden: insufficient rights" });
      }
      next();
    };
  };
  
  module.exports = { roleValidation };
