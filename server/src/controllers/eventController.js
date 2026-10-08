const Event = require('../models/Event');
const { escapeRegex } = require('../utils/sanitize');

async function getEvents(req, res, next) {
  try {
    const {
      source,
      eventType,
      status,
      severity,
      host,
      username,
      sourceIP,
      dateFrom,
      dateTo,
      search,
      rawFile,
      page = 1,
      limit = 50
    } = req.query;

    const query = {};

    if (source && typeof source === 'string') query.source = source;
    if (eventType && typeof eventType === 'string') query.eventType = eventType;
    if (status && typeof status === 'string') query.status = status;
    if (severity && typeof severity === 'string') query.severity = severity;
    if (host && typeof host === 'string') query.host = new RegExp(escapeRegex(host), 'i');
    if (username && typeof username === 'string') query.username = new RegExp(escapeRegex(username), 'i');
    if (sourceIP && typeof sourceIP === 'string') query.sourceIP = new RegExp(escapeRegex(sourceIP), 'i');
    if (rawFile && typeof rawFile === 'string') {
      query.rawFile = new RegExp(escapeRegex(rawFile), 'i');
    }

    if (dateFrom || dateTo) {
      const timeQuery = {};
      if (dateFrom && !isNaN(new Date(dateFrom).getTime())) {
        timeQuery.$gte = new Date(dateFrom);
      }
      if (dateTo && !isNaN(new Date(dateTo).getTime())) {
        timeQuery.$lte = new Date(dateTo);
      }
      if (Object.keys(timeQuery).length > 0) {
        query.timestamp = timeQuery;
      }
    }

    if (search && typeof search === 'string') {
      const safeSearch = escapeRegex(search);
      query.$or = [
        { description: new RegExp(safeSearch, 'i') },
        { techniqueId: new RegExp(safeSearch, 'i') },
        { host: new RegExp(safeSearch, 'i') },
        { username: new RegExp(safeSearch, 'i') },
        { sourceIP: new RegExp(safeSearch, 'i') },
        { rawFile: new RegExp(safeSearch, 'i') }
      ];
    }

    const pageNum = parseInt(page, 10) || 1;
    const limitNum = Math.min(parseInt(limit, 10) || 100, 1000);
    const skip = (pageNum - 1) * limitNum;

    const [events, total] = await Promise.all([
      Event.find(query).sort({ timestamp: -1 }).skip(skip).limit(limitNum),
      Event.countDocuments(query)
    ]);

    res.json({
      events,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      }
    });
  } catch (err) {
    next(err);
  }
}

async function getEventById(req, res, next) {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ error: 'NotFound', message: 'Event not found' });
    res.json(event);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getEvents,
  getEventById
};
