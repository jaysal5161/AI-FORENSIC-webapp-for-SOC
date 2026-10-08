const Endpoint = require('../models/Endpoint');
const { escapeRegex } = require('../utils/sanitize');

async function getEndpoints(req, res, next) {
  try {
    const { status, search } = req.query;
    const query = {};

    if (status && typeof status === 'string') query.status = status;
    if (search && typeof search === 'string') {
      const safeSearch = escapeRegex(search);
      query.$or = [
        { hostname: new RegExp(safeSearch, 'i') },
        { os: new RegExp(safeSearch, 'i') },
        { ipAddresses: new RegExp(safeSearch, 'i') }
      ];
    }

    const endpoints = await Endpoint.find(query)
      .populate('associatedAlerts', 'alertId title severity status')
      .sort({ riskScore: -1 });

    res.json(endpoints);
  } catch (err) {
    next(err);
  }
}

async function getEndpointById(req, res, next) {
  try {
    const endpoint = await Endpoint.findById(req.params.id)
      .populate('associatedAlerts');
    if (!endpoint) return res.status(404).json({ error: 'NotFound', message: 'Endpoint not found' });
    res.json(endpoint);
  } catch (err) {
    next(err);
  }
}

async function updateEndpoint(req, res, next) {
  try {
    const allowedUpdates = {};
    if (req.body.status !== undefined) allowedUpdates.status = req.body.status;
    if (req.body.riskScore !== undefined) allowedUpdates.riskScore = Math.min(100, Math.max(0, parseInt(req.body.riskScore, 10) || 0));
    if (req.body.isolated !== undefined) allowedUpdates.isolated = Boolean(req.body.isolated);
    if (req.body.notes !== undefined) allowedUpdates.notes = req.body.notes;

    const endpoint = await Endpoint.findByIdAndUpdate(req.params.id, { $set: allowedUpdates }, { new: true });
    if (!endpoint) return res.status(404).json({ error: 'NotFound', message: 'Endpoint not found' });
    res.json(endpoint);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getEndpoints,
  getEndpointById,
  updateEndpoint
};
