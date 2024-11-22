const { sendEmail } = require('../utils/emailSender');
const { hashToken, validateToken } = require('../utils/cryptoUtils');
const bcrypt = require('bcryptjs');
const dynamoDB = require('../utils/dynamoDB');
const messages = require('../utils/messages');

exports.register = async (req, res) => {
    const { name, email, password } = req.body;

    // Check if the user with the given email already exists
    const checkParams = {
        TableName: 'authentication',
        Key: {
            email: email,
        },
    };

    try {
        const existingUser = await dynamoDB.send(new GetCommand(checkParams));

        if (existingUser.Item) {
            return res.status(400).json({ error: messages.errors.emailExists });
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 10);

        const params = {
            TableName: 'authentication',
            Item: {
                email,
                isAdmin: false,
                name,
                password: hashedPassword,
            },
        };

        await dynamoDB.send(new PutCommand(params));

        res.status(201).json({ message: messages.success.userRegistered });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    const params = {
        TableName: 'authentication',
        Key: { email },
    };

    try {
        const data = await dynamoDB.send(new GetCommand(params));
        const user = data.Item;

        if (!user) {
            return res.status(401).json({ error: messages.errors.invalidCredentials });
        }

        // Compare the provided password with the hashed password in the database
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).json({ error: messages.errors.invalidCredentials });
        }

        // Generate a JWT
        const token = jwt.sign({ email: user.email, name: user.name, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Log the user request with user's name
        await logUserRequest(email, user.name); // Pass the user's name here

        res.json({ token ,isAdmin:user.isAdmin}); // Return the JWT to the client
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error logging in' });
    }
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Email is required." });
    }

    try {
        // Check if user exists
        const params = {
            TableName: 'authentication',
            Key: { email },
        };
        const user = await dynamoDB.send(new GetCommand(params));

        if (!user.Item) {
            return res.status(404).json({ error: "User not found." });
        }

        // Generate reset token
        const resetToken = hashToken();
        const tokenExpiry = Date.now() + parseInt(process.env.RESET_PASSWORD_TOKEN_EXPIRY) * 1000;

        // Save the token and expiry in the database
        const updateParams = {
            TableName: 'authentication',
            Key: { email },
            UpdateExpression: 'SET resetToken = :token, resetTokenExpiry = :expiry',
            ExpressionAttributeValues: {
                ':token': resetToken.hashed,
                ':expiry': tokenExpiry,
            },
        };
        await dynamoDB.send(new UpdateCommand(updateParams));

        // Send reset email
        const resetURL = `${process.env.CLIENT_URL}/${resetToken.raw}`;
        await sendEmail(email, 'Password Reset Request', `
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <a href="${resetURL}">${resetURL}</a>
            <p>This link will expire in 1 hour.</p>
        `);

        res.status(200).json({ message: "Password reset link sent to your email." });
    } catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).json({ error: "An error occurred while processing your request." });
    }
};

exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: "Token and new password are required." });
    }

    try {
        const hashedToken = validateToken(token);

        // Find the user with the reset token
        const params = {
            TableName: 'authentication',
            FilterExpression: 'resetToken = :token AND resetTokenExpiry > :now',
            ExpressionAttributeValues: {
                ':token': hashedToken,
                ':now': Date.now(),
            },
        };
        const data = await dynamoDB.send(new ScanCommand(params));
        const user = data.Items[0];

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired token." });
        }

        // Hash new password and update user record
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        const updateParams = {
            TableName: 'authentication',
            Key: { email: user.email },
            UpdateExpression: 'SET password = :password REMOVE resetToken, resetTokenExpiry',
            ExpressionAttributeValues: {
                ':password': hashedPassword,
            },
        };
        await dynamoDB.send(new UpdateCommand(updateParams));

        res.status(200).json({ message: "Password reset successfully." });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ error: "An error occurred while resetting the password." });
    }
};

exports.deleteProfile = async (req, res) => {
    const email = req.userEmail;
    // Logic for deleting user profile
};
