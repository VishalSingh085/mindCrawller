// // // // routes/authRoutes.js
// // // import express from "express";
// // // import {
// // //     loginUser,
// // //     registerUserOnly,
// // //     registerCounsellor,
// // //     updateUser,
// // //     deleteUser,
// // //     getUser,
// // //     getAlluser,
// // //     logout,
// // //     getAllCounsellors,
// // //     getCounsellorById,
// // //     getMyProfile,
// // //     verifyEmailOTP,
   
// // //     resendOTPS,
// // //     checkVerificationStatus,
// // // } from "../controllers/authController.js";
// // // import { verifyOtp } from "../middleware/verifyOtp.js";
// // // import { refreshAccessToken } from "../middleware/refreshToken.js";
// // // import { authMiddleware } from "../middleware/authMiddleware.js";
// // // import { generateOtp } from "../utils/generateOtp.js";
// // // import { resendOtp } from "../utils/resendOtp.js";
// // // import { uploadProfilePhoto } from "../middleware/multerConfig.js";

// // // export const authRoutes = express.Router();

// // // // ================= PUBLIC ROUTES =================
// // // // User registration - NO PHOTO UPLOAD (no multer middleware)
// // // authRoutes.post("/register/user", registerUserOnly);

// // // // Counsellor registration - WITH PHOTO UPLOAD (multer middleware)
// // // authRoutes.post("/register/counsellor", uploadProfilePhoto, registerCounsellor);
// // // // GET route for counsellor signup page (returns form data/config)
// // // authRoutes.post("/verify-email", verifyEmailOTP);
// // // // authRoutes.post("/verify-phone", verifyPhoneOTP);
// // // authRoutes.post("/resend-otp", resendOTPS);
// // // authRoutes.get("/verification-status/:userId", checkVerificationStatus);

// // // // Optional: GET route to fetch registration data (specializations, modes, etc.)
// // // // authRoutes.get("/counsellor/registration-data", getCounsellorRegistrationData);
// // // authRoutes.post("/login", loginUser);
// // // authRoutes.post("/logout", authMiddleware, logout);

// // // // OTP Routes
// // // authRoutes.post("/generateOtp", generateOtp);
// // // authRoutes.post("/verifyOtp", verifyOtp);
// // // authRoutes.post("/resendOtp", resendOtp);
// // // authRoutes.post("/refreshToken", refreshAccessToken);

// // // // ================= PUBLIC COUNSELLOR ROUTES =================
// // // authRoutes.get("/counsellors", getAllCounsellors);
// // // authRoutes.get("/counsellors/:counsellorId", getCounsellorById);

// // // // ================= PROTECTED ROUTES =================
// // // authRoutes.get("/me", authMiddleware, getMyProfile);
// // // authRoutes.get("/getUser/:userId", getUser);
// // // authRoutes.get("/getAllUser", authMiddleware, getAlluser);
// // // authRoutes.patch("/update", authMiddleware, uploadProfilePhoto, updateUser);
// // // authRoutes.delete("/delete", authMiddleware, deleteUser);

// // // export default authRoutes;


// // // routes/authRoutes.js
// // import express from "express";
// // import {
// //     loginUser,
// //     registerUserOnly,
// //     registerCounsellor,
// //     updateUser,
// //     deleteUser,
// //     getUser,
// //     getAlluser,
// //     logout,
// //     getAllCounsellors,
// //     getCounsellorById,
// //     getMyProfile,
// //     verifyEmailOTP, 
// //     sendEmailOTP,
// //     sendPhoneOTP,
// //     verifyPhoneOTP,
// //     completeRegistration,
// //     forgotPassword,
// //     resetPassword
// // } from "../controllers/authController.js";
// // import { body } from 'express-validator';
// // import { verifyOtp } from "../middleware/verifyOtp.js";
// // import { refreshAccessToken } from "../middleware/refreshToken.js";
// // import { authMiddleware } from "../middleware/authMiddleware.js";
// // import { generateOtp } from "../utils/generateOtp.js";
// // import { resendOtp } from "../utils/resendOtp.js";
// // import { uploadProfilePhoto } from "../middleware/multerConfig.js";

// // export const authRoutes = express.Router();

// // authRoutes.post("/send-email-otp", sendEmailOTP);

// // // Step 2: Verify Email OTP
// // authRoutes.post("/verify-email-otp", verifyEmailOTP);

// // // Step 3: Send Phone OTP
// // authRoutes.post("/send-phone-otp", sendPhoneOTP);

// // // Step 4: Verify Phone OTP
// // authRoutes.post("/verify-phone-otp", verifyPhoneOTP);

// // // Step 5: Complete Registration (after both verifications)
// // authRoutes.post("/complete-registration", uploadProfilePhoto, completeRegistration);
// // // // ================= NEW REGISTRATION FLOW (Verify Email First) =================
// // // // Step 1: Send OTP to email
// // // authRoutes.post("/registration", uploadProfilePhoto, initiateRegistration);
// // // // Step 2: Verify OTP and create user
// // // authRoutes.post("/verifyUser", verifyAndCreateUser);
// // // // Resend OTP
// // // authRoutes.post("/resendOtp", resendRegistrationOTP);
// // // // Check registration status
// // // authRoutes.get("/registration/:email", checkRegistrationStatus);

// // // ================= LEGACY ROUTES (Deprecated - for backward compatibility) =================
// // // authRoutes.post("/register/user", registerUserOnly);
// // // authRoutes.post("/register/counsellor", uploadProfilePhoto, registerCounsellor);
// // // authRoutes.post("/verify-email", verifyEmailOTP);
// // // authRoutes.post("/resend-otp", resendOTPS);
// // // authRoutes.get("/verification-status/:userId", checkVerificationStatus);

// // // ================= PUBLIC ROUTES =================
// // authRoutes.post("/login", loginUser);
// // authRoutes.post("/logout", authMiddleware, logout);

// // // OTP Routes
// // authRoutes.post("/generateOtp", generateOtp);
// // authRoutes.post("/verifyOtp", verifyOtp);
// // authRoutes.post("/resendOtp", resendOtp);
// // authRoutes.post("/refreshToken", refreshAccessToken);

// // // ================= PUBLIC COUNSELLOR ROUTES =================
// // authRoutes.get("/counsellors", getAllCounsellors);
// // authRoutes.get("/counsellors/:counsellorId", getCounsellorById);

// // // ================= PROTECTED ROUTES =================
// // authRoutes.get("/me", authMiddleware, getMyProfile);
// // authRoutes.get("/getUser/:userId", getUser);
// // authRoutes.get("/getAllUser", authMiddleware, getAlluser);
// // authRoutes.patch("/update", authMiddleware, uploadProfilePhoto, updateUser);
// // authRoutes.delete("/delete", authMiddleware, deleteUser);

// // // password reset and forgot password
// // authRoutes.post('/forgotPassword', [
// //     body('email').isEmail().withMessage('Please provide a valid email')
// // ], forgotPassword);

// // // Reset password route
// // authRoutes.post('/resetPassword/:token', [
// //     body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
// //     body('confirmPassword').custom((value, { req }) => {
// //         if (value !== req.body.password) {
// //             throw new Error('Passwords do not match');
// //         }
// //         return true;
// //     })
// // ], resetPassword);


// // authRoutes.post('/refresh-token', refreshAccessToken);
// // // authRoutes.post("/forgotPassword",forgotPassword);
// // // authRoutes.post("/resetPassword",resetPassword);

// // export default authRoutes;


// // routes/authRoutes.js
// import express from "express";
// import {
//     loginUser,
//     // registerUserOnly,
//     // registerCounsellor,
//     // updateUser,
//     deleteUser,
//     getUser,
//     getAlluser,
//     logout,
//     getAllCounsellors,
//     getCounsellorById,
//     getMyProfile,
//     verifyEmailOTP, 
//     sendEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeRegistration,
//     forgotPassword,
//     resetPassword,
//     // New token management functions
//     refreshAccessTokenHandler,
//     logoutAllDevices,
//     getMySessions,
//     updateUserById
// } from "../controllers/authController.js";
// import { body } from 'express-validator';
// import { verifyOtp } from "../middleware/verifyOtp.js";
// import { refreshAccessToken } from "../middleware/refreshToken.js";
// import { authMiddleware } from "../middleware/authMiddleware.js";
// import { generateOtp } from "../utils/generateOtp.js";
// import { resendOtp } from "../utils/resendOtp.js";
// import { upload, uploadProfilePhoto } from "../middleware/multerConfig.js";

// export const authRoutes = express.Router();

// // ================= OTP & REGISTRATION FLOW =================
// authRoutes.post("/send-email-otp", sendEmailOTP);
// authRoutes.post("/verify-email-otp", verifyEmailOTP);
// authRoutes.post("/send-phone-otp", sendPhoneOTP);
// authRoutes.post("/verify-phone-otp", verifyPhoneOTP);
// authRoutes.post("/complete-registration", uploadProfilePhoto, completeRegistration);

// // ================= AUTHENTICATION ROUTES =================
// authRoutes.post("/login", loginUser);
// authRoutes.post("/logout", authMiddleware, logout);
// authRoutes.post("/refresh-token", refreshAccessTokenHandler); // New: Refresh token endpoint
// authRoutes.post("/logout-all", authMiddleware, logoutAllDevices); // New: Logout from all devices
// authRoutes.get("/my-sessions", authMiddleware, getMySessions); // New: Get all active sessions

// // ================= OTP ROUTES =================
// authRoutes.post("/generateOtp", generateOtp);
// authRoutes.post("/verifyOtp", verifyOtp);
// authRoutes.post("/resendOtp", resendOtp);

// // ================= PUBLIC COUNSELLOR ROUTES =================
// authRoutes.get("/counsellors", getAllCounsellors);
// authRoutes.get("/counsellors/:counsellorId", getCounsellorById);

// // ================= PROTECTED ROUTES =================
// authRoutes.get("/me", authMiddleware, getMyProfile);
// authRoutes.get("/getUser/:userId", getUser);
// authRoutes.get("/getAllUser", authMiddleware, getAlluser);
// // authRoutes.patch("/update", authMiddleware, uploadProfilePhoto, updateUser);
// authRoutes.patch('/update/:userId', authMiddleware, upload.single('profilePhoto'), updateUserById);
// authRoutes.patch('/update/:consellorId', authMiddleware, upload.single('profilePhoto'), updateUserById);
// authRoutes.delete("/delete", authMiddleware, deleteUser);

// // ================= PASSWORD RESET ROUTES =================
// authRoutes.post('/forgotPassword', [
//     body('email').isEmail().withMessage('Please provide a valid email')
// ], forgotPassword);

// authRoutes.post('/resetPassword/:token', [
//     body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
//     body('confirmPassword').custom((value, { req }) => {
//         if (value !== req.body.password) {
//             throw new Error('Passwords do not match');
//         }
//         return true;
//     })
// ], resetPassword);

// export default authRoutes;



// routes/authRoutes.js
// import express from "express";
// import {
//     loginUser,
//     deleteUser,
//     getUser,
//     getAlluser,
//     logout,
//     getAllCounsellors,
//     getCounsellorById,
//     getMyProfile,
//     verifyEmailOTP, 
//     sendEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeRegistration,
//     forgotPassword,
//     resetPassword,
//     refreshAccessTokenHandler,
//     logoutAllDevices,
//     getMySessions,
//     updateUserById  // Make sure this is imported
// } from "../controllers/authController.js";
// import { body } from 'express-validator';
// import { verifyOtp } from "../middleware/verifyOtp.js";
// import { refreshAccessToken } from "../middleware/refreshToken.js";
// import { authMiddleware } from "../middleware/authMiddleware.js";
// import { generateOtp } from "../utils/generateOtp.js";
// import { resendOtp } from "../utils/resendOtp.js";
// import { upload, uploadProfilePhoto } from "../middleware/multerConfig.js";
// import { handleUserUpload } from "../middleware/multerConfig.js";
// export const authRoutes = express.Router();

// // ================= OTP & REGISTRATION FLOW =================
// authRoutes.post("/send-email-otp", sendEmailOTP);
// authRoutes.post("/verify-email-otp", verifyEmailOTP);
// authRoutes.post("/send-phone-otp", sendPhoneOTP);
// authRoutes.post("/verify-phone-otp", verifyPhoneOTP);
// authRoutes.post("/complete-registration", uploadProfilePhoto, completeRegistration);
// // authRoutes.post("/complete-registration", upload.single('profilePhoto'), completeRegistration);
// // ================= AUTHENTICATION ROUTES =================
// authRoutes.post("/login", loginUser);
// authRoutes.post("/logout", authMiddleware, logout);
// authRoutes.post("/refresh-token", refreshAccessTokenHandler);
// authRoutes.post("/logout-all", authMiddleware, logoutAllDevices);
// authRoutes.get("/my-sessions", authMiddleware, getMySessions);

// // ================= OTP ROUTES =================
// authRoutes.post("/generateOtp", generateOtp);
// authRoutes.post("/verifyOtp", verifyOtp);
// authRoutes.post("/resendOtp", resendOtp);

// // ================= PUBLIC COUNSELLOR ROUTES =================
// authRoutes.get("/counsellors", getAllCounsellors);
// authRoutes.get("/counsellors/:counsellorId", getCounsellorById);

// // ================= PROTECTED ROUTES =================
// authRoutes.get("/me", authMiddleware, getMyProfile);
// authRoutes.get("/getUser/:userId", getUser);
// authRoutes.get("/getAllUser", authMiddleware, getAlluser);

// // FIXED: Single update route - not two with different params
// // authRoutes.patch("/update/:userId", authMiddleware, upload.single('profilePhoto'), updateUserById);
// authRoutes.patch("/update/:userId", 
//     authMiddleware, 
//     handleUserUpload,  // This handles BOTH profile photo AND certification files
//     updateUserById
// );
// authRoutes.delete("/delete", authMiddleware, deleteUser);

// // ================= PASSWORD RESET ROUTES =================
// authRoutes.post('/forgotPassword', [
//     body('email').isEmail().withMessage('Please provide a valid email')
// ], forgotPassword);

// authRoutes.post('/resetPassword/:token', [
//     body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
//     body('confirmPassword').custom((value, { req }) => {
//         if (value !== req.body.password) {
//             throw new Error('Passwords do not match');
//         }
//         return true;
//     })
// ], resetPassword);

// export default authRoutes;


// routes/authRoutes.js
import express from "express";
import {
    loginUser,
    deleteUser,
    getUser,
    getAlluser,
    logout,
    getAllCounsellors,
    getCounsellorById,
    getMyProfile,
    verifyEmailOTP, 
    sendEmailOTP,
    sendPhoneOTP,
    verifyPhoneOTP,
    completeRegistration,
    forgotPassword,
    resetPassword,
    refreshAccessTokenHandler,
    logoutAllDevices,
    getMySessions,
    updateUserById
} from "../controllers/authController.js";
import { body } from 'express-validator';
import { verifyOtp } from "../middleware/verifyOtp.js";
// refreshToken middleware import removed — route uses refreshAccessTokenHandler from authController
import { authMiddleware } from "../middleware/authMiddleware.js";
import { generateOtp } from "../utils/generateOtp.js";
import { resendOtp } from "../utils/resendOtp.js";
import { handleUserUpload, uploadProfilePhoto } from "../middleware/multerConfig.js";

export const authRoutes = express.Router();

// OTP & REGISTRATION FLOW
authRoutes.post("/send-email-otp", sendEmailOTP);
authRoutes.post("/verify-email-otp", verifyEmailOTP);
authRoutes.post("/send-phone-otp", sendPhoneOTP);
authRoutes.post("/verify-phone-otp", verifyPhoneOTP);
authRoutes.post("/complete-registration", uploadProfilePhoto, completeRegistration);

// AUTHENTICATION ROUTES
authRoutes.post("/login", loginUser);
authRoutes.post("/logout", authMiddleware, logout);
authRoutes.post("/refresh-token", refreshAccessTokenHandler);
authRoutes.post("/logout-all", authMiddleware, logoutAllDevices);
authRoutes.get("/my-sessions", authMiddleware, getMySessions);

// OTP ROUTES
authRoutes.post("/generateOtp", generateOtp);
authRoutes.post("/verifyOtp", verifyOtp);
authRoutes.post("/resendOtp", resendOtp);

// PUBLIC COUNSELLOR ROUTES
authRoutes.get("/counsellors", getAllCounsellors);
authRoutes.get("/counsellors/:counsellorId", getCounsellorById);

// PROTECTED ROUTES
authRoutes.get("/me", authMiddleware, getMyProfile);
authRoutes.get("/getUser/:userId", getUser);
authRoutes.get("/getAllUser", authMiddleware, getAlluser);

// UPDATE ROUTE - Uses handleUserUpload for both profile photo and certifications
authRoutes.patch("/update/:userId", 
    authMiddleware, 
    handleUserUpload,
    updateUserById
);

authRoutes.delete("/delete", authMiddleware, deleteUser);

// PASSWORD RESET ROUTES
authRoutes.post('/forgotPassword', [
    body('email').isEmail().withMessage('Please provide a valid email')
], forgotPassword);

authRoutes.post('/resetPassword/:token', [
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], resetPassword);

export default authRoutes;