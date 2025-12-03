export default class FireCryptError extends Error {
  constructor(message, code) {
    super(message);
    this.firecrypt = code;
  }
}
