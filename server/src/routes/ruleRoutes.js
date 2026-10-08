const express = require('express');
const router = express.Router();
const ruleController = require('../controllers/ruleController');
const { authenticate, authorize } = require('../middleware/auth');

router.get('/', authenticate, ruleController.getRules);
router.post('/', authenticate, authorize('admin', 'analyst'), ruleController.createRule);
router.post('/run-all', authenticate, authorize('admin', 'analyst'), ruleController.runAllRules);
router.get('/:id', authenticate, ruleController.getRuleById);
router.patch('/:id', authenticate, authorize('admin', 'analyst'), ruleController.updateRule);
router.delete('/:id', authenticate, authorize('admin'), ruleController.deleteRule);

module.exports = router;

