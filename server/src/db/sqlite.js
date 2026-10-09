const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let dbState = null;
const modelRegistry = new Map();
let saveTimeout = null;

function generateId() {
  return crypto.randomBytes(12).toString('hex');
}

function getDbPath() {
  const isVercel = Boolean(process.env.VERCEL);
  const localDataDir = path.resolve(__dirname, '../../data');
  const bundledFile = path.resolve(localDataDir, 'soc_platform.json');

  if (isVercel) {
    const tmpFile = path.resolve('/tmp', 'soc_platform.json');
    if (!fs.existsSync(tmpFile)) {
      if (fs.existsSync(bundledFile)) {
        try {
          fs.copyFileSync(bundledFile, tmpFile);
        } catch (e) {}
      }
    }
    return fs.existsSync(tmpFile) ? tmpFile : bundledFile;
  }

  if (!fs.existsSync(localDataDir)) {
    fs.mkdirSync(localDataDir, { recursive: true });
  }
  return bundledFile;
}

function loadDatabase() {
  if (dbState) return dbState;
  const filePath = getDbPath();
  let tables = {};

  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      tables = JSON.parse(content);
    } catch (e) {
      tables = {};
    }
  }

  dbState = {
    filePath,
    tables,
    dirty: false
  };

  return dbState;
}

function scheduleSave() {
  if (!dbState) return;
  dbState.dirty = true;
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    persistSync();
  }, 100);
}

function persistSync() {
  if (!dbState || !dbState.dirty) return;
  try {
    const isVercel = Boolean(process.env.VERCEL);
    let target = dbState.filePath;
    if (isVercel && !target.startsWith('/tmp')) {
      target = path.resolve('/tmp', 'soc_platform.json');
    }
    const dir = path.dirname(target);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(target, JSON.stringify(dbState.tables, null, 2), 'utf8');
    dbState.dirty = false;
  } catch (err) {
    // In read-only environments, mutations stay in-memory
  }
}

function getTable(tableName) {
  const state = loadDatabase();
  const name = tableName.toLowerCase();
  if (!state.tables[name]) {
    state.tables[name] = {};
  }
  return state.tables[name];
}

function getNestedValue(obj, keyPath) {
  if (!obj || typeof obj !== 'object') return undefined;
  if (!keyPath.includes('.')) return obj[keyPath];
  const parts = keyPath.split('.');
  let current = obj;
  for (const p of parts) {
    if (current === null || current === undefined) return undefined;
    current = current[p];
  }
  return current;
}

function setNestedValue(obj, keyPath, val) {
  const parts = keyPath.split('.');
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    if (!current[p] || typeof current[p] !== 'object') {
      current[p] = {};
    }
    current = current[p];
  }
  current[parts[parts.length - 1]] = val;
}

function matchFilter(record, filter) {
  if (!filter || Object.keys(filter).length === 0) return true;

  for (const [key, expected] of Object.entries(filter)) {
    if (key === '$or') {
      if (!Array.isArray(expected) || !expected.some(cond => matchFilter(record, cond))) {
        return false;
      }
      continue;
    }
    if (key === '$and') {
      if (!Array.isArray(expected) || !expected.every(cond => matchFilter(record, cond))) {
        return false;
      }
      continue;
    }

    const actual = key === '_id' ? record._id : getNestedValue(record, key);

    if (expected instanceof RegExp) {
      if (typeof actual !== 'string' || !expected.test(actual)) return false;
      continue;
    }

    if (expected !== null && typeof expected === 'object' && !Array.isArray(expected)) {
      if ('$in' in expected) {
        const inArr = expected.$in.map(String);
        if (Array.isArray(actual)) {
          if (!actual.some(item => inArr.includes(String(item)))) return false;
        } else if (!inArr.includes(String(actual))) {
          return false;
        }
        continue;
      }
      if ('$nin' in expected) {
        const ninArr = expected.$nin.map(String);
        if (Array.isArray(actual)) {
          if (actual.some(item => ninArr.includes(String(item)))) return false;
        } else if (ninArr.includes(String(actual))) {
          return false;
        }
        continue;
      }
      if ('$ne' in expected) {
        if (String(actual) === String(expected.$ne)) return false;
        continue;
      }
      if ('$exists' in expected) {
        const exists = actual !== undefined && actual !== null;
        if (expected.$exists !== exists) return false;
        continue;
      }
      if ('$gt' in expected || '$gte' in expected || '$lt' in expected || '$lte' in expected) {
        const compActual = actual instanceof Date ? actual.getTime() : (typeof actual === 'string' && !isNaN(Date.parse(actual)) ? new Date(actual).getTime() : Number(actual));
        if ('$gt' in expected) {
          const exp = expected.$gt instanceof Date ? expected.$gt.getTime() : Number(expected.$gt);
          if (!(compActual > exp)) return false;
        }
        if ('$gte' in expected) {
          const exp = expected.$gte instanceof Date ? expected.$gte.getTime() : Number(expected.$gte);
          if (!(compActual >= exp)) return false;
        }
        if ('$lt' in expected) {
          const exp = expected.$lt instanceof Date ? expected.$lt.getTime() : Number(expected.$lt);
          if (!(compActual < exp)) return false;
        }
        if ('$lte' in expected) {
          const exp = expected.$lte instanceof Date ? expected.$lte.getTime() : Number(expected.$lte);
          if (!(compActual <= exp)) return false;
        }
        continue;
      }
    }

    // Array field contains value (Mongoose convention)
    if (Array.isArray(actual) && !Array.isArray(expected)) {
      if (!actual.some(v => String(v) === String(expected))) return false;
      continue;
    }

    if (String(actual) !== String(expected)) {
      return false;
    }
  }

  return true;
}

function applyUpdate(record, update) {
  if (!update || typeof update !== 'object') return record;
  const now = new Date().toISOString();

  if (update.$set) {
    for (const [k, v] of Object.entries(update.$set)) {
      setNestedValue(record, k, v);
    }
  }
  if (update.$inc) {
    for (const [k, v] of Object.entries(update.$inc)) {
      const cur = getNestedValue(record, k) || 0;
      setNestedValue(record, k, cur + Number(v));
    }
  }
  if (update.$push) {
    for (const [k, v] of Object.entries(update.$push)) {
      let arr = getNestedValue(record, k);
      if (!Array.isArray(arr)) {
        arr = [];
        setNestedValue(record, k, arr);
      }
      arr.push(v);
    }
  }

  for (const [k, v] of Object.entries(update)) {
    if (!k.startsWith('$')) {
      setNestedValue(record, k, v);
    }
  }

  record.updatedAt = now;
  return record;
}

function projectRecord(record, select) {
  if (!select) return record;
  let fields = typeof select === 'string' ? select.trim().split(/\s+/) : (Array.isArray(select) ? select : Object.keys(select));
  if (fields.length === 0) return record;

  const isExclusion = fields.some(f => f.startsWith('-'));
  const res = { ...record };

  if (isExclusion) {
    for (const f of fields) {
      if (f.startsWith('-')) {
        delete res[f.slice(1)];
      }
    }
    return res;
  }

  const included = { _id: record._id };
  for (const f of fields) {
    if (f in record) included[f] = record[f];
  }
  return included;
}

class Query {
  constructor(model, filter = {}, single = false) {
    this.model = model;
    this.filter = filter;
    this.isSingle = single;
    this._sort = null;
    this._limit = null;
    this._skip = 0;
    this._select = null;
    this._populate = [];
  }

  sort(sortCriteria) {
    this._sort = sortCriteria;
    return this;
  }

  limit(limitCount) {
    this._limit = limitCount;
    return this;
  }

  skip(skipCount) {
    this._skip = skipCount;
    return this;
  }

  select(selectFields) {
    this._select = selectFields;
    return this;
  }

  populate(pathOrObj, selectFields) {
    if (typeof pathOrObj === 'string') {
      this._populate.push({ path: pathOrObj, select: selectFields });
    } else if (pathOrObj && typeof pathOrObj === 'object') {
      this._populate.push(pathOrObj);
    }
    return this;
  }

  lean() {
    return this;
  }

  maxTimeMS(ms) {
    return this;
  }

  async exec() {
    const table = getTable(this.model.tableName);
    let records = [];

    if (this.filter._id && typeof this.filter._id === 'string' && Object.keys(this.filter).length === 1) {
      const rec = table[this.filter._id];
      if (rec) records = [{ ...rec }];
    } else {
      for (const rec of Object.values(table)) {
        if (matchFilter(rec, this.filter)) {
          records.push({ ...rec });
        }
      }
    }

    // Sort
    if (this._sort) {
      const sortEntries = typeof this._sort === 'string'
        ? [[this._sort.replace(/^-/, ''), this._sort.startsWith('-') ? -1 : 1]]
        : Object.entries(this._sort);

      records.sort((a, b) => {
        for (const [key, dir] of sortEntries) {
          const valA = getNestedValue(a, key);
          const valB = getNestedValue(b, key);
          if (valA === valB) continue;
          if (valA === undefined || valA === null) return 1;
          if (valB === undefined || valB === null) return -1;
          const cmp = valA > valB ? 1 : -1;
          return dir === -1 || dir === 'desc' ? -cmp : cmp;
        }
        return 0;
      });
    }

    if (this._skip > 0) {
      records = records.slice(this._skip);
    }

    if (this._limit !== null && this._limit !== undefined) {
      records = records.slice(0, this._limit);
    }

    // Populate
    for (const pop of this._populate) {
      const targetModel = this.model.schemaRefs?.[pop.path] || modelRegistry.get(pop.path) || modelRegistry.get(pop.path.replace(/Id$/, '').replace(/^./, c => c.toUpperCase()));
      if (targetModel) {
        for (const rec of records) {
          const refId = rec[pop.path];
          if (refId) {
            if (Array.isArray(refId)) {
              const populatedList = [];
              for (const singleId of refId) {
                const popDoc = await targetModel.findById(singleId).select(pop.select);
                if (popDoc) populatedList.push(popDoc);
              }
              rec[pop.path] = populatedList;
            } else {
              const popDoc = await targetModel.findById(refId).select(pop.select);
              if (popDoc) rec[pop.path] = popDoc;
            }
          }
        }
      }
    }

    if (this.isSingle) {
      if (records.length === 0) return null;
      const doc = projectRecord(records[0], this._select);
      return this.model.createDocument(doc);
    }

    return records.map(r => this.model.createDocument(projectRecord(r, this._select)));
  }

  then(resolve, reject) {
    return this.exec().then(resolve, reject);
  }

  catch(reject) {
    return this.exec().catch(reject);
  }
}

class Document {
  constructor(data, model) {
    Object.assign(this, data);
    Object.defineProperty(this, '_model', { value: model, enumerable: false, writable: true });
  }

  async save() {
    const table = getTable(this._model.tableName);
    const now = new Date().toISOString();
    if (!this.createdAt) this.createdAt = now;
    this.updatedAt = now;
    if (!this._id) this._id = generateId();

    const plain = this.toObject();
    table[this._id] = plain;
    scheduleSave();
    return this;
  }

  toObject() {
    const res = {};
    for (const k of Object.keys(this)) {
      if (!k.startsWith('_model')) {
        res[k] = this[k];
      }
    }
    return res;
  }

  toJSON() {
    return this.toObject();
  }
}

function createModel(modelName, tableName, schemaRefs = {}) {
  const modelObj = {
    name: modelName,
    tableName: tableName.toLowerCase(),
    schemaRefs,

    createDocument(data) {
      if (!data) return null;
      return new Document(data, Model);
    },

    find(filter = {}) {
      return new Query(Model, filter, false);
    },

    findOne(filter = {}) {
      return new Query(Model, filter, true);
    },

    findById(id) {
      return new Query(Model, { _id: String(id) }, true);
    },

    async countDocuments(filter = {}) {
      const q = new Query(Model, filter, false);
      const res = await q.exec();
      return res.length;
    },

    async distinct(field, filter = {}) {
      const q = new Query(Model, filter, false);
      const res = await q.exec();
      const set = new Set();
      for (const item of res) {
        const val = getNestedValue(item, field);
        if (val !== undefined && val !== null) {
          set.add(val);
        }
      }
      return Array.from(set);
    },

    async create(docOrDocs) {
      const table = getTable(Model.tableName);
      if (Array.isArray(docOrDocs)) {
        return Promise.all(docOrDocs.map(d => Model.create(d)));
      }
      const data = { ...docOrDocs };
      if (!data._id) data._id = generateId();
      const now = new Date().toISOString();
      if (!data.createdAt) data.createdAt = now;
      if (!data.updatedAt) data.updatedAt = now;

      table[data._id] = { ...data };
      scheduleSave();
      return new Document(data, Model);
    },

    async insertMany(docs) {
      const table = getTable(Model.tableName);
      const created = [];
      const now = new Date().toISOString();

      for (const item of docs) {
        const d = { ...item };
        if (!d._id) d._id = generateId();
        if (!d.createdAt) d.createdAt = now;
        if (!d.updatedAt) d.updatedAt = now;
        table[d._id] = { ...d };
        created.push(new Document(d, Model));
      }

      scheduleSave();
      return created;
    },

    async findByIdAndUpdate(id, update, options = {}) {
      const doc = await Model.findById(id);
      if (!doc) {
        if (options.upsert) {
          const newDoc = { _id: String(id) };
          applyUpdate(newDoc, update);
          return Model.create(newDoc);
        }
        return null;
      }
      applyUpdate(doc, update);
      await doc.save();
      return doc;
    },

    async findOneAndUpdate(filter, update, options = {}) {
      let doc = await Model.findOne(filter);
      if (!doc) {
        if (options.upsert) {
          const newDoc = {};
          for (const [k, v] of Object.entries(filter)) {
            if (typeof v !== 'object') newDoc[k] = v;
          }
          applyUpdate(newDoc, update);
          return Model.create(newDoc);
        }
        return null;
      }
      applyUpdate(doc, update);
      await doc.save();
      return doc;
    },

    async updateOne(filter, update, options = {}) {
      const doc = await Model.findOne(filter);
      if (!doc) return { matchedCount: 0, modifiedCount: 0 };
      applyUpdate(doc, update);
      await doc.save();
      return { matchedCount: 1, modifiedCount: 1 };
    },

    async updateMany(filter, update, options = {}) {
      const docs = await Model.find(filter);
      for (const d of docs) {
        applyUpdate(d, update);
        await d.save();
      }
      return { matchedCount: docs.length, modifiedCount: docs.length };
    },

    async deleteOne(filter) {
      const doc = await Model.findOne(filter);
      if (!doc) return { deletedCount: 0 };
      const table = getTable(Model.tableName);
      delete table[doc._id];
      scheduleSave();
      return { deletedCount: 1 };
    },

    async deleteMany(filter = {}) {
      const table = getTable(Model.tableName);
      if (Object.keys(filter).length === 0) {
        const count = Object.keys(table).length;
        const state = loadDatabase();
        state.tables[Model.tableName] = {};
        scheduleSave();
        return { deletedCount: count };
      }
      const docs = await Model.find(filter);
      for (const d of docs) {
        delete table[d._id];
      }
      scheduleSave();
      return { deletedCount: docs.length };
    },

    aggregate(pipeline) {
      const query = {
        option: () => query,
        async exec() {
          const all = await Model.find();
          let results = all.map(d => d.toObject());

          for (const stage of pipeline) {
            if (stage.$match) {
              results = results.filter(r => matchFilter(r, stage.$match));
            } else if (stage.$group) {
              const groups = new Map();
              const groupKeyExpr = stage.$group._id;

              for (const r of results) {
                let groupKey;
                if (typeof groupKeyExpr === 'string' && groupKeyExpr.startsWith('$')) {
                  groupKey = getNestedValue(r, groupKeyExpr.slice(1));
                } else if (typeof groupKeyExpr === 'object' && groupKeyExpr !== null) {
                  if (groupKeyExpr.$dateToString) {
                    const dateVal = getNestedValue(r, groupKeyExpr.$dateToString.date.slice(1));
                    const d = dateVal ? new Date(dateVal) : new Date();
                    const hours = String(d.getUTCHours()).padStart(2, '0');
                    groupKey = `${hours}:00`;
                  } else {
                    groupKey = JSON.stringify(groupKeyExpr);
                  }
                } else {
                  groupKey = groupKeyExpr;
                }

                if (!groups.has(groupKey)) {
                  groups.set(groupKey, []);
                }
                groups.get(groupKey).push(r);
              }

              const newResults = [];
              for (const [key, groupItems] of groups.entries()) {
                const groupDoc = { _id: key };
                for (const [field, expr] of Object.entries(stage.$group)) {
                  if (field === '_id') continue;
                  if (expr.$sum) {
                    if (expr.$sum === 1) {
                      groupDoc[field] = groupItems.length;
                    } else if (typeof expr.$sum === 'object' && expr.$sum.$cond) {
                      const [cond, ifTrue, ifFalse] = expr.$sum.$cond;
                      let sum = 0;
                      for (const item of groupItems) {
                        let matches = false;
                        if (cond.$eq) {
                          const [fieldExpr, val] = cond.$eq;
                          const actual = getNestedValue(item, fieldExpr.slice(1));
                          matches = String(actual) === String(val);
                        } else if (cond.$in) {
                          const [fieldExpr, arr] = cond.$in;
                          const actual = getNestedValue(item, fieldExpr.slice(1));
                          matches = arr.includes(actual);
                        }
                        sum += (matches ? ifTrue : ifFalse);
                      }
                      groupDoc[field] = sum;
                    }
                  }
                }
                newResults.push(groupDoc);
              }
              results = newResults;
            } else if (stage.$sort) {
              const [key, dir] = Object.entries(stage.$sort)[0];
              results.sort((a, b) => {
                const valA = a[key] ?? 0;
                const valB = b[key] ?? 0;
                return dir === -1 ? (valB > valA ? 1 : -1) : (valA > valB ? 1 : -1);
              });
            } else if (stage.$limit) {
              results = results.slice(0, stage.$limit);
            } else if (stage.$project) {
              results = results.map(r => {
                const proj = {};
                for (const [k, v] of Object.entries(stage.$project)) {
                  if (v === 1) {
                    proj[k] = r[k];
                  } else if (typeof v === 'string' && v.startsWith('$')) {
                    proj[k] = getNestedValue(r, v.slice(1));
                  }
                }
                return proj;
              });
            }
          }
          return results;
        },
        then(resolve, reject) {
          return query.exec().then(resolve, reject);
        }
      };
      return query;
    }
  };

  function Model(data) {
    if (!(this instanceof Model)) {
      return new Document(data, Model);
    }
    return new Document(data, Model);
  }

  for (const [k, v] of Object.entries(modelObj)) {
    if (k !== 'name') {
      Model[k] = v;
    }
  }
  Model.modelName = modelName;
  modelRegistry.set(modelName, Model);
  return Model;
}

module.exports = {
  loadDatabase,
  persistSync,
  createModel,
  modelRegistry,
  generateId
};
