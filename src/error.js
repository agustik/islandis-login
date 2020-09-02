class ValidationError extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'ValidationError';
    this.reason = reason;
  }
}

class CertificateError extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'CertificateError';
    this.reason = reason;
  }
}


module.exports = {
  ValidationError,
  CertificateError
}
