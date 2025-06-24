import express from 'express';
import { signup, login, logout, getMe, updatePassword, deleteAccount, googleLogin } from '../controllers/auth.controller.js';
import { protect } from '../../middleware/authMiddleware.js';

const router = express.Router();
router.post('/signup', signup);
router.post('/login', login);
router.post('/google', googleLogin);
router.get('/logout', logout);
router.get('/me', protect, getMe);
router.put('/updatepassword', protect, updatePassword);
router.delete('/deleteaccount', protect, deleteAccount);

export default router;