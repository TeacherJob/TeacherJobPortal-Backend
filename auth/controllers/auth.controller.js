import { User } from '../../models/User.model.js';
import { EmployerProfile } from '../../employer/models/profile.model.js';
import { CollegeProfile } from '../../college/models/profile.model.js';
import { AdminProfile } from '../../admin/models/profile.model.js';
import { Application } from '../../employer/models/application.model.js';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateToken = (id, role) => {
    return jwt.sign({ id, role }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

const sendTokenResponse = (user, statusCode, res) => {
    const token = generateToken(user._id, user.role);

    const cookieOptions = {
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        httpOnly: true,
        path: '/',
        // sameSite: 'none',
    };

    if (process.env.NODE_ENV === 'production') {
        cookieOptions.secure = true;
        cookieOptions.sameSite = 'None';
    }

    res.status(statusCode)
        .cookie('token', token, cookieOptions)
        .json({
            success: true,
            user: { id: user._id, email: user.email, role: user.role }
        });
};

export const signup = async (req, res) => {
    const { fullName, email, password, confirmPassword, role, termsAccepted } = req.body;

    if (!fullName || !email || !password || !confirmPassword || !role) {
        return res.status(400).json({ success: false, message: 'Please provide all fields' });
    }
    if (termsAccepted !== true) {
        return res.status(400).json({ success: false, message: 'You must accept the terms and conditions' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    try {
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ success: false, message: 'User with this email already exists' });
        }

        const user = await User.create({ email, password, role, termsAccepted });

        if (role === 'employer') {
            await EmployerProfile.create({ user: user._id, name: fullName });
        } else if (role === 'college') {
            await CollegeProfile.create({ user: user._id, name: fullName });
        } else if (role === 'admin') {
            await AdminProfile.create({ user: user._id, name: fullName });
        }

        sendTokenResponse(user, 201, res);
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }
    try {
        const user = await User.findOne({ email }).select('+password');
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        sendTokenResponse(user, 200, res);
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export const googleLogin = async (req, res) => {
    const { token, role } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const { email, name, picture } = ticket.getPayload();
        let user = await User.findOne({ email });

        if (user) {
            sendTokenResponse(user, 200, res);
        } else {
            if (!role) {
                return res.status(400).json({ success: false, message: 'Role is required for new user signup.' });
            }
            const randomPassword = crypto.randomBytes(16).toString('hex');
            user = await User.create({ email, password: randomPassword, role, termsAccepted: true });

            if (role === 'employer') {
                await EmployerProfile.create({ user: user._id, name: name, profilePicture: { url: picture } });
            } else if (role === 'college') {
                await CollegeProfile.create({ user: user._id, name: name, logo: { url: picture } });
            } else {
                return res.status(400).json({ success: false, message: 'Invalid role for Google signup.' });
            }

            sendTokenResponse(user, 201, res);
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Google Sign-In failed.' });
    }
};

export const logout = (req, res) => {
    const cookieOptions = {
        expires: new Date(0), // Set expiration to a past date
        httpOnly: true,
        path: '/',
    };

    if (process.env.NODE_ENV === 'production') {
        cookieOptions.secure = true;
        cookieOptions.sameSite = 'None';
    }

    res.status(200)
        .cookie('token', '', cookieOptions) // Set cookie to an empty value
        .json({ success: true, message: 'Logged out successfully' });
};

export const getMe = async (req, res) => {
    const user = await User.findById(req.user.id);
    res.status(200).json({ success: true, data: { id: user._id, email: user.email, role: user.role } });
};

export const updatePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.user.id).select('+password');
        if (!(await user.comparePassword(currentPassword))) {
            return res.status(401).json({ success: false, message: 'Incorrect current password' });
        }
        user.password = newPassword;
        await user.save();
        res.status(200).json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export const deleteAccount = async (req, res) => {
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ success: false, message: 'Password is required to delete account' });
    }
    try {
        const user = await User.findById(req.user.id).select('+password');
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ success: false, message: 'Incorrect password' });
        }

        if (user.role === 'employer') {
            await EmployerProfile.deleteOne({ user: req.user.id });
            await Application.deleteMany({ user: req.user.id });
        } else if (user.role === 'college') {
            await CollegeProfile.deleteOne({ user: req.user.id });
        } else if (user.role === 'admin') {
            await AdminProfile.deleteOne({ user: req.user.id });
        }

        await user.deleteOne();
        
        const cookieOptions = {
            expires: new Date(0),
            httpOnly: true,
            path: '/',
        };
        if (process.env.NODE_ENV === 'production') {
            cookieOptions.secure = true;
            cookieOptions.sameSite = 'None';
        }

        res.status(200)
            .cookie('token', '', cookieOptions)
            .json({ success: true, message: 'Account deleted successfully' });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};
