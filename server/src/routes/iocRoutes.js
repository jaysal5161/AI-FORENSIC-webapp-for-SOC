const express = require('express');
const router = express.Router();
const iocController = require('../controllers/iocController');
const { authenticate, authorize } = require('../middleware/auth');

router.get('/', authenticate, iocController.getIOCs);
router.post('/', authenticate, authorize('admin', 'analyst'), iocController.createIOC);
router.post('/lookup', authenticate, iocController.lookupIOC);
router.post('/sql', authenticate, iocController.executeSqlQuery);
router.post('/query', authenticate, iocController.executeSqlQuery);

// AI Natural Language to SQL Assistant endpoints
router.post('/ai/generate', authenticate, iocController.generateAiQueryHandler);
router.get('/ai/schema', authenticate, iocController.getSchemaHandler);
router.get('/ai/history', authenticate, iocController.getAiHistoryHandler);

router.patch('/:id', authenticate, authorize('admin', 'analyst'), iocController.updateIOC);
router.delete('/:id', authenticate, authorize('admin'), iocController.deleteIOC);

module.exports = router;
