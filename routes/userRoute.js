const express = require('express');
const { getRequestCount, updateRequestCount, getHealthAdvice, translateText } = require('../controllers/userController');
const verifyToken = require('../utils/verifyToken');
const validateRequest = require('../utils/validators');
const router = express.Router();

router.get('/requestCount', verifyToken, getRequestCount);
router.put('/updateRequestCount', verifyToken, validateRequest, updateRequestCount);
router.post('/getAdvice', verifyToken, validateRequest, getHealthAdvice);
router.post('/translate', verifyToken, translateText);

module.exports = router;
