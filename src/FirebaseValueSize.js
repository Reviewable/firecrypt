// Measures Firebase's val() output before FireCrypt transforms it.
export default class FirebaseValueSize {
  constructor() {
    this.containers = 0;
    this.scalars = 0;
    this.numbers = 0;
    this.stringBytes = 0;
  }

  get entries() {
    return Math.max(0, this.containers + this.scalars - 1);
  }

  addScalar(value, type) {
    this.scalars++;
    if (type === 'number') this.numbers++;
    if (type === 'string') this.stringBytes += Math.ceil((16 + value.length) / 8) * 8;
  }

  count(value) {
    if (value === null || value === undefined) return;
    const type = typeof value;
    if (type === 'object') {
      const scalarsBefore = this.scalars;
      for (const key of Object.keys(value)) this.count(value[key]);
      if (this.scalars > scalarsBefore) this.containers++;
    } else {
      this.addScalar(value, type);
    }
  }
}
