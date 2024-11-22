const express = require('express');
const { getUserRequests, getApiStats } = require('../controllers/adminController');
const verifyToken = require('../utils/verifyToken');
const router = express.Router();

router.get('/userRequests', verifyToken, getUserRequests);
router.get('/apiStats', verifyToken, getApiStats);

module.exports = router;
