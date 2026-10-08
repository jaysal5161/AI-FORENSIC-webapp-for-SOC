const Account = require('../models/Account');
const { escapeRegex } = require('../utils/sanitize');

async function getAccounts(req, res, next) {
  try {
    const { status, privilege, search } = req.query;
    const query = {};

    if (status && typeof status === 'string') query.status = status;
    if (privilege && typeof privilege === 'string') query.privilege = privilege;
    if (search && typeof search === 'string') {
      const safeSearch = escapeRegex(search);
      query.$or = [
        { username: new RegExp(safeSearch, 'i') },
        { domain: new RegExp(safeSearch, 'i') }
      ];
    }

    const accounts = await Account.find(query)
      .populate('associatedAlerts', 'alertId title severity status')
      .sort({ riskScore: -1 });

    res.json(accounts);
  } catch (err) {
    next(err);
  }
}

async function getAccountById(req, res, next) {
  try {
    const account = await Account.findById(req.params.id)
      .populate('associatedAlerts');
    if (!account) return res.status(404).json({ error: 'NotFound', message: 'Account not found' });
    res.json(account);
  } catch (err) {
    next(err);
  }
}

async function updateAccount(req, res, next) {
  try {
    const allowedUpdates = {};
    if (req.body.status !== undefined) allowedUpdates.status = req.body.status;
    if (req.body.riskScore !== undefined) allowedUpdates.riskScore = Math.min(100, Math.max(0, parseInt(req.body.riskScore, 10) || 0));
    if (req.body.privilege !== undefined) allowedUpdates.privilege = req.body.privilege;
    if (req.body.notes !== undefined) allowedUpdates.notes = req.body.notes;

    const account = await Account.findByIdAndUpdate(req.params.id, { $set: allowedUpdates }, { new: true });
    if (!account) return res.status(404).json({ error: 'NotFound', message: 'Account not found' });
    res.json(account);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getAccounts,
  getAccountById,
  updateAccount
};
