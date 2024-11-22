const express = require('express');
const {
    register,
    login,
    forgotPassword,
    resetPassword,
    deleteProfile,
} = require('../controllers/authController');
const verifyToken = require('../utils/verifyToken');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.delete('/deleteProfile', verifyToken, deleteProfile);

module.exports = router;
