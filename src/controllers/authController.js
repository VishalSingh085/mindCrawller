// // controllers/authController.js
// import User from "../models/userModel.js";
// import bcrypt from "bcryptjs";
// import Session from "../models/sessionModel.js";
// import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";
// import otpService from "../services/otpService.js";
// import twilio from 'twilio';

// // Initialize Twilio client
// const twilioClient = twilio(
//     process.env.TWILIO_ACCOUNT_SID,
//     process.env.TWILIO_AUTH_TOKEN
// );
// const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// // ================= TEMPORARY STORAGE FOR VERIFIED USERS =================
// const verifiedUsersStore = new Map(); // Key: email, Value: { isEmailVerified, isPhoneVerified, expiresAt, phoneNumber }
// // This line uses tempUserStore but it's never defined

// // Clean up expired verified users every hour
// setInterval(() => {
//     const now = Date.now();
//     for (const [email, data] of verifiedUsersStore.entries()) {
//         if (data.expiresAt < now) {
//             verifiedUsersStore.delete(email);
//         }
//     }
// }, 60 * 60 * 1000);

// // ================= STEP 1: SEND EMAIL OTP =================
// export const sendEmailOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         // Check if user already exists
//         const existingUser = await User.findOne({ email });
//         if (existingUser) {
//             return res.status(409).json({
//                 message: "User already exists with this email",
//                 success: false
//             });
//         }

//         // Generate OTP
//         const otp = otpService.generateOTP();

//         // Send OTP via email
//         try {
//             await otpService.sendEmailOTP(email, otp, "User");

//             // Store OTP temporarily
//             emailOTPStore.set(email, {
//                 otp,
//                 expiresAt: Date.now() + 10 * 60 * 1000
//             });

//             return res.status(200).json({
//                 message: "Email OTP sent successfully",
//                 success: true,
//                 email: email
//             });
//         } catch (sendError) {
//             console.error("OTP sending error:", sendError);
//             return res.status(500).json({
//                 message: "Failed to send OTP. Please try again.",
//                 success: false
//             });
//         }
//     } catch (error) {
//         console.error("Send email OTP error:", error);
//         return res.status(500).json({
//             message: "Error sending OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 2: VERIFY EMAIL OTP =================
// export const verifyEmailOTP = async (req, res) => {
//     try {
//         const { email, otp } = req.body;

//         if (!email || !otp) {
//             return res.status(400).json({
//                 message: "Email and OTP are required",
//                 success: false
//             });
//         }

//         const storedData = emailOTPStore.get(email);

//         if (!storedData) {
//             return res.status(400).json({
//                 message: "No OTP found. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (Date.now() > storedData.expiresAt) {
//             emailOTPStore.delete(email);
//             return res.status(400).json({
//                 message: "OTP has expired. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (storedData.otp !== otp) {
//             return res.status(400).json({
//                 message: "Invalid OTP",
//                 success: false
//             });
//         }

//         // OTP verified - store email verification status
//         let userVerification = verifiedUsersStore.get(email);
//         if (!userVerification) {
//             userVerification = {
//                 isEmailVerified: true,
//                 isPhoneVerified: false,
//                 expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour to complete phone verification
//             };
//         } else {
//             userVerification.isEmailVerified = true;
//         }

//         verifiedUsersStore.set(email, userVerification);

//         // Clean up email OTP
//         emailOTPStore.delete(email);

//         return res.status(200).json({
//             message: "Email verified successfully. Please verify your phone number next.",
//             success: true,
//             email: email,
//             nextStep: "phone_verification"
//         });

//     } catch (error) {
//         console.error("Verify email OTP error:", error);
//         return res.status(500).json({
//             message: "Error verifying OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 3: SEND PHONE OTP (Using Twilio) =================
// export const sendPhoneOTP = async (req, res) => {
//     try {
//         const { phoneNumber } = req.body;

//         // Validate phone number
//         if (!phoneNumber) {
//             return res.status(400).json({
//                 message: "Phone number is required",
//                 success: false
//             });
//         }

//         // Clean phone number (remove non-digits)
//         const cleanedPhone = phoneNumber.replace(/\D/g, '');

//         if (cleanedPhone.length !== 10) {
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Format to E.164 format (Indian numbers +91)
//         const formattedPhone = `+91${cleanedPhone}`;

//         // Find which email is associated with this phone number
//         let foundEmail = null;
//         let userVerification = null;

//         for (const [email, data] of verifiedUsersStore.entries()) {
//             if (data.phoneNumber === cleanedPhone) {
//                 foundEmail = email;
//                 userVerification = data;
//                 break;
//             }
//         }

//         // If not found by phone, get the first pending verification
//         if (!userVerification) {
//             for (const [email, data] of verifiedUsersStore.entries()) {
//                 if (data.isEmailVerified && !data.isPhoneVerified) {
//                     foundEmail = email;
//                     userVerification = data;
//                     break;
//                 }
//             }
//         }

//         if (!userVerification || !userVerification.isEmailVerified) {
//             return res.status(400).json({
//                 message: "Please verify your email first. Request email OTP before phone verification.",
//                 success: false,
//                 requiresEmailFirst: true
//             });
//         }

//         // Check if phone already exists
//         const existingUser = await User.findOne({ phoneNumber: cleanedPhone });
//         if (existingUser) {
//             return res.status(409).json({
//                 message: "Phone number already registered",
//                 success: false
//             });
//         }

//         // Generate OTP
//         const otp = otpService.generateOTP();

//         // Log OTP for debugging
//         console.log(`=================================`);
//         console.log(`📱 Sending Phone OTP`);
//         console.log(`📧 Email: ${foundEmail}`);
//         console.log(`📱 Phone: ${formattedPhone}`);
//         console.log(`🔢 OTP: ${otp}`);
//         console.log(`=================================`);

//         // Send SMS via Twilio
//         try {
//             const message = await twilioClient.messages.create({
//                 body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
//                 from: TWILIO_PHONE_NUMBER,
//                 to: formattedPhone
//             });

//             console.log(`✅ Phone OTP sent successfully! SID: ${message.sid}`);

//             // Update verification store with phone number
//             userVerification.phoneNumber = cleanedPhone;
//             userVerification.formattedPhone = formattedPhone;
//             verifiedUsersStore.set(foundEmail, userVerification);

//             // Store phone OTP
//             phoneOTPStore.set(foundEmail, {
//                 otp,
//                 phoneNumber: cleanedPhone,
//                 formattedPhone,
//                 expiresAt: Date.now() + 10 * 60 * 1000
//             });

//             return res.status(200).json({
//                 message: "Phone OTP sent successfully via SMS",
//                 success: true,
//                 phoneNumber: cleanedPhone
//             });
//         } catch (sendError) {
//             console.error("Phone OTP sending error:", sendError);

//             // Handle Twilio errors
//             if (sendError.code === 21211) {
//                 return res.status(400).json({
//                     message: "Invalid phone number format. Please check your phone number.",
//                     success: false,
//                     error: sendError.message
//                 });
//             } else if (sendError.message && sendError.message.includes("unverified")) {
//                 return res.status(400).json({
//                     message: "This phone number is not verified in your Twilio trial account. Please verify your phone number in Twilio console or upgrade your account.",
//                     success: false,
//                     error: sendError.message,
//                     twilioTrialMode: true
//                 });
//             }

//             return res.status(500).json({
//                 message: "Failed to send phone OTP. Please try again.",
//                 success: false,
//                 error: sendError.message
//             });
//         }
//     } catch (error) {
//         console.error("Send phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error sending phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 4: VERIFY PHONE OTP =================
// export const verifyPhoneOTP = async (req, res) => {
//     try {
//         const { phoneNumber, otp } = req.body;

//         if (!phoneNumber || !otp) {
//             return res.status(400).json({
//                 message: "Phone number and OTP are required",
//                 success: false
//             });
//         }

//         // Clean phone number
//         const cleanedPhone = phoneNumber.replace(/\D/g, '');

//         // Find which email has this phone number
//         let foundEmail = null;
//         let storedData = null;

//         for (const [email, data] of phoneOTPStore.entries()) {
//             if (data.phoneNumber === cleanedPhone && Date.now() <= data.expiresAt) {
//                 foundEmail = email;
//                 storedData = data;
//                 break;
//             }
//         }

//         if (!storedData) {
//             return res.status(400).json({
//                 message: "No OTP found. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (Date.now() > storedData.expiresAt) {
//             phoneOTPStore.delete(foundEmail);
//             return res.status(400).json({
//                 message: "OTP has expired. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (storedData.otp !== otp) {
//             return res.status(400).json({
//                 message: "Invalid OTP",
//                 success: false
//             });
//         }

//         // Update verification status
//         const userVerification = verifiedUsersStore.get(foundEmail);
//         if (userVerification) {
//             userVerification.isPhoneVerified = true;
//             userVerification.phoneNumber = cleanedPhone;
//             userVerification.formattedPhone = storedData.formattedPhone;
//             verifiedUsersStore.set(foundEmail, userVerification);
//         }

//         // Clean up phone OTP
//         phoneOTPStore.delete(foundEmail);

//         return res.status(200).json({
//             message: "Phone verified successfully. You can now complete your registration.",
//             success: true,
//             email: foundEmail,
//             nextStep: "complete_registration"
//         });

//     } catch (error) {
//         console.error("Verify phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error verifying phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 5: COMPLETE REGISTRATION =================
// export const completeRegistration = async (req, res) => {
//     try {
//         const {
//             fullName,
//             email,
//             password,
//             age,
//             gender,
//             // Counsellor fields
//             qualification,
//             specialization,
//             experience,
//             location,
//             consultationMode,
//             languages,
//             aboutMe
//         } = req.body;

//         // VALIDATE REQUIRED FIELDS
//         if (!fullName || !email || !password) {
//             return res.status(400).json({
//                 message: "Full name, email, and password are required",
//                 success: false,
//                 required: ["fullName", "email", "password"]
//             });
//         }

//         if (password.length < 6) {
//             return res.status(400).json({
//                 message: "Password must be at least 6 characters",
//                 success: false
//             });
//         }

//         // Check if user is verified
//         const userVerification = verifiedUsersStore.get(email);

//         if (!userVerification) {
//             return res.status(400).json({
//                 message: "No verification found. Please verify your email and phone first.",
//                 success: false,
//                 requiresVerification: true,
//                 steps: {
//                     emailVerified: false,
//                     phoneVerified: false
//                 }
//             });
//         }

//         if (!userVerification.isEmailVerified) {
//             return res.status(400).json({
//                 message: "Email not verified. Please verify your email first.",
//                 success: false,
//                 requiresEmailVerification: true
//             });
//         }

//         if (!userVerification.isPhoneVerified) {
//             return res.status(400).json({
//                 message: "Phone number not verified. Please verify your phone number first.",
//                 success: false,
//                 requiresPhoneVerification: true
//             });
//         }

//         // Check if phone number exists in verification
//         if (!userVerification.phoneNumber) {
//             return res.status(400).json({
//                 message: "Phone number not found. Please verify your phone number again.",
//                 success: false
//             });
//         }

//         // Check if user already exists
//         const existingUser = await User.findOne({
//             $or: [{ email }, { phoneNumber: userVerification.phoneNumber }]
//         });

//         if (existingUser) {
//             verifiedUsersStore.delete(email);
//             return res.status(409).json({
//                 message: "User already exists with this email or phone number",
//                 success: false
//             });
//         }

//         // AUTO-DETECT ROLE
//         const hasCounsellorFields = qualification && specialization && experience && location;
//         const role = hasCounsellorFields ? "counsellor" : "user";

//         // Validate counsellor required fields if role is counsellor
//         if (role === "counsellor") {
//             if (!qualification || !specialization || !experience || !location) {
//                 return res.status(400).json({
//                     message: "Counsellor requires: qualification, specialization, experience, and location",
//                     success: false,
//                     required: ["qualification", "specialization", "experience", "location"]
//                 });
//             }
//         }

//         // Hash password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Prepare user data
//         const userData = {
//             fullName,
//             email,
//             phoneNumber: userVerification.phoneNumber,
//             password: hashedPassword,
//             age: age || null,
//             gender: gender || "male",
//             role,
//             profileCompleted: true,
//             isEmailVerified: true,
//             isActive: true
//         };

//         // Add counsellor-specific fields if role is counsellor
//         if (role === "counsellor") {
//             userData.qualification = qualification;
//             userData.specialization = typeof specialization === 'string'
//                 ? specialization.split(',').map(s => s.trim())
//                 : specialization;
//             userData.experience = Number(experience);
//             userData.location = location;
//             userData.consultationMode = typeof consultationMode === 'string'
//                 ? consultationMode.split(',').map(m => m.trim())
//                 : consultationMode || ["online"];
//             userData.languages = typeof languages === 'string'
//                 ? languages.split(',').map(l => l.trim())
//                 : languages || [];
//             userData.aboutMe = aboutMe || "";

//             // Handle profile photo if uploaded
//             if (req.file) {
//                 userData.profilePhoto = saveLocalFile(req.file);
//             }
//         } else {
//             // For users, allow optional fields
//             if (specialization) {
//                 userData.specialization = typeof specialization === 'string'
//                     ? specialization.split(',').map(s => s.trim())
//                     : specialization;
//             }
//             if (languages) {
//                 userData.languages = typeof languages === 'string'
//                     ? languages.split(',').map(l => l.trim())
//                     : languages || [];
//             }
//             if (consultationMode) {
//                 userData.consultationMode = typeof consultationMode === 'string'
//                     ? consultationMode.split(',').map(m => m.trim())
//                     : consultationMode || ["online"];
//             }
//         }

//         // Create user
//         const newUser = await User.create(userData);

//         // Clean up verification data
//         verifiedUsersStore.delete(email);

//         // Clean up any remaining OTPs
//         emailOTPStore.delete(email);
//         phoneOTPStore.delete(email);

//         // Auto-login after registration
//         const accessToken = generateAccessToken(newUser._id);
//         const refreshToken = generateRefreshToken(newUser._id);

//         await Session.create({
//             userId: newUser._id,
//             refreshToken,
//             isActive: true
//         });

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });
//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 7 * 24 * 60 * 60 * 1000
//         });

//         return res.status(201).json({
//             message: "Registration completed successfully!",
//             success: true,
//             user: newUser.toJSON(),
//             accessToken,
//             refreshToken,
//             role: newUser.role
//         });

//     } catch (error) {
//         console.error("Complete registration error:", error);
//         if (req.file) {
//             deleteLocalFile(saveLocalFile(req.file));
//         }
//         return res.status(500).json({
//             message: "Error completing registration",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= RESEND OTP ENDPOINTS =================
// export const resendEmailOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const userVerification = verifiedUsersStore.get(email);
//         if (!userVerification) {
//             return res.status(404).json({
//                 message: "No pending verification found",
//                 success: false
//             });
//         }

//         const otp = otpService.generateOTP();

//         await otpService.sendEmailOTP(email, otp, "User");

//         emailOTPStore.set(email, {
//             otp,
//             expiresAt: Date.now() + 10 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Email OTP resent successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Resend email OTP error:", error);
//         return res.status(500).json({
//             message: "Error resending OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// export const resendPhoneOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const userVerification = verifiedUsersStore.get(email);
//         if (!userVerification || !userVerification.phoneNumber) {
//             return res.status(404).json({
//                 message: "No phone number found for verification",
//                 success: false
//             });
//         }

//         const otp = otpService.generateOTP();

//         let formattedPhone = userVerification.phoneNumber;
//         if (!formattedPhone.startsWith('+')) {
//             formattedPhone = `+91${formattedPhone}`;
//         }

//         await twilioClient.messages.create({
//             body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
//             from: TWILIO_PHONE_NUMBER,
//             to: formattedPhone
//         });

//         phoneOTPStore.set(email, {
//             otp,
//             phoneNumber: userVerification.phoneNumber,
//             formattedPhone,
//             expiresAt: Date.now() + 10 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Phone OTP resent successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Resend phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error resending phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // OTP temporary storage
// const emailOTPStore = new Map();
// const phoneOTPStore = new Map();

// // Clean up expired OTPs every hour
// setInterval(() => {
//     const now = Date.now();
//     for (const [email, data] of emailOTPStore.entries()) {
//         if (data.expiresAt < now) {
//             emailOTPStore.delete(email);
//         }
//     }
//     for (const [email, data] of phoneOTPStore.entries()) {
//         if (data.expiresAt < now) {
//             phoneOTPStore.delete(email);
//         }
//     }
// }, 60 * 60 * 1000);

// // Keep all your existing functions (getAllCounsellors, getCounsellorById, loginUser, etc.)
// // ... (these remain the same as in your original code)
// // // controllers/authController.js
// // // controllers/authController.js
// // import User from "../models/userModel.js";
// // import bcrypt from "bcryptjs";
// // import Session from "../models/sessionModel.js";
// // import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// // import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";
// // import otpService from "../services/otpService.js";
// // import twilio from 'twilio';

// // // Initialize Twilio client
// // const twilioClient = twilio(
// //     process.env.TWILIO_ACCOUNT_SID,
// //     process.env.TWILIO_AUTH_TOKEN
// // );
// // const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// // // ================= TEMPORARY STORAGE FOR VERIFIED USERS =================
// // const verifiedUsersStore = new Map(); // Key: email, Value: { isEmailVerified, isPhoneVerified, expiresAt, fullName, phoneNumber }

// // // Clean up expired verified users every hour
// // setInterval(() => {
// //     const now = Date.now();
// //     for (const [email, data] of verifiedUsersStore.entries()) {
// //         if (data.expiresAt < now) {
// //             verifiedUsersStore.delete(email);
// //         }
// //     }
// // }, 60 * 60 * 1000);

// // // ================= STEP 1: SEND EMAIL OTP =================
// // // export const sendEmailOTP = async (req, res) => {
// // //     try {
// // //         const { email} = req.body;

// // //         if (!email) {
// // //             return res.status(400).json({
// // //                 message: "Email is required",
// // //                 success: false
// // //             });
// // //         }

// // //         // Check if user already exists
// // //         const existingUser = await User.findOne({ email });
// // //         if (existingUser) {
// // //             return res.status(409).json({
// // //                 message: "User already exists with this email",
// // //                 success: false
// // //             });
// // //         }

// // //         // Generate OTP
// // //         const otp = otpService.generateOTP();

// // //         // Send OTP via email
// // //         try {
// // //             await otpService.sendEmailOTP(email, otp,);

// // //             // Store OTP temporarily
// // //             emailOTPStore.set(email, {
// // //                 otp,
// // //                 expiresAt: Date.now() + 10 * 60 * 1000
// // //             });

// // //             return res.status(200).json({
// // //                 message: "Email OTP sent successfully",
// // //                 success: true,
// // //                 email: email
// // //             });
// // //         } catch (sendError) {
// // //             console.error("OTP sending error:", sendError);
// // //             return res.status(500).json({
// // //                 message: "Failed to send OTP. Please try again.",
// // //                 success: false
// // //             });
// // //         }
// // //     } catch (error) {
// // //         console.error("Send email OTP error:", error);
// // //         return res.status(500).json({
// // //             message: "Error sending OTP",
// // //             success: false,
// // //             error: error.message
// // //         });
// // //     }
// // // };

// // // ================= STEP 1: SEND EMAIL OTP =================
// // export const sendEmailOTP = async (req, res) => {
// //     try {
// //         const { email } = req.body;  // Remove fullName from destructuring

// //         if (!email) {
// //             return res.status(400).json({
// //                 message: "Email is required",  // Update message
// //                 success: false
// //             });
// //         }

// //         // Check if user already exists
// //         const existingUser = await User.findOne({ email });
// //         if (existingUser) {
// //             return res.status(409).json({
// //                 message: "User already exists with this email",
// //                 success: false
// //             });
// //         }

// //         // Generate OTP
// //         const otp = otpService.generateOTP();

// //         // Send OTP via email
// //         try {
// //             await otpService.sendEmailOTP(email, otp, "User");

// //             // Store OTP temporarily
// //             emailOTPStore.set(email, {
// //                 otp,
// //                 expiresAt: Date.now() + 10 * 60 * 1000
// //             });

// //             return res.status(200).json({
// //                 message: "Email OTP sent successfully",
// //                 success: true,
// //                 email: email
// //             });
// //         } catch (sendError) {
// //             console.error("OTP sending error:", sendError);
// //             return res.status(500).json({
// //                 message: "Failed to send OTP. Please try again.",
// //                 success: false
// //             });
// //         }
// //     } catch (error) {
// //         console.error("Send email OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error sending OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };
// // // ================= STEP 2: VERIFY EMAIL OTP =================
// // export const verifyEmailOTP = async (req, res) => {
// //     try {
// //         const { email, otp } = req.body;

// //         if (!email || !otp) {
// //             return res.status(400).json({
// //                 message: "Email and OTP are required",
// //                 success: false
// //             });
// //         }

// //         const storedData = emailOTPStore.get(email);

// //         if (!storedData) {
// //             return res.status(400).json({
// //                 message: "No OTP found. Please request a new OTP.",
// //                 success: false
// //             });
// //         }

// //         if (Date.now() > storedData.expiresAt) {
// //             emailOTPStore.delete(email);
// //             return res.status(400).json({
// //                 message: "OTP has expired. Please request a new OTP.",
// //                 success: false
// //             });
// //         }

// //         if (storedData.otp !== otp) {
// //             return res.status(400).json({
// //                 message: "Invalid OTP",
// //                 success: false
// //             });
// //         }

// //         // OTP verified - store email verification status
// //         let userVerification = verifiedUsersStore.get(email);
// //         if (!userVerification) {
// //             userVerification = {
// //                 isEmailVerified: true,
// //                 isPhoneVerified: false,
// //                 expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour to complete phone verification
// //             };
// //         } else {
// //             userVerification.isEmailVerified = true;
// //         }

// //         verifiedUsersStore.set(email, userVerification);

// //         // Clean up email OTP
// //         emailOTPStore.delete(email);

// //         return res.status(200).json({
// //             message: "Email verified successfully. Please verify your phone number next.",
// //             success: true,
// //             email: email,
// //             nextStep: "phone_verification"
// //         });

// //     } catch (error) {
// //         console.error("Verify email OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error verifying OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= STEP 3: SEND PHONE OTP (Using Twilio) =================
// // // ================= STEP 3: SEND PHONE OTP (Using Twilio) =================
// // export const sendPhoneOTP = async (req, res) => {
// //     try {
// //         const { phoneNumber } = req.body;

// //         // Validate phone number
// //         if (!phoneNumber) {
// //             return res.status(400).json({
// //                 message: "Phone number is required",
// //                 success: false
// //             });
// //         }

// //         // Clean phone number (remove non-digits)
// //         const cleanedPhone = phoneNumber.replace(/\D/g, '');

// //         if (cleanedPhone.length !== 10) {
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Format to E.164 format (Indian numbers +91)
// //         const formattedPhone = `+91${cleanedPhone}`;

// //         // Find which email is associated with this phone number
// //         let foundEmail = null;
// //         let userVerification = null;

// //         for (const [email, data] of verifiedUsersStore.entries()) {
// //             if (data.phoneNumber === cleanedPhone) {
// //                 foundEmail = email;
// //                 userVerification = data;
// //                 break;
// //             }
// //         }

// //         // If not found by phone, get the first pending verification
// //         if (!userVerification) {
// //             for (const [email, data] of verifiedUsersStore.entries()) {
// //                 if (data.isEmailVerified && !data.isPhoneVerified) {
// //                     foundEmail = email;
// //                     userVerification = data;
// //                     break;
// //                 }
// //             }
// //         }

// //         if (!userVerification || !userVerification.isEmailVerified) {
// //             return res.status(400).json({
// //                 message: "Please verify your email first. Request email OTP before phone verification.",
// //                 success: false,
// //                 requiresEmailFirst: true
// //             });
// //         }

// //         // Check if phone already exists
// //         const existingUser = await User.findOne({ phoneNumber: cleanedPhone });
// //         if (existingUser) {
// //             return res.status(409).json({
// //                 message: "Phone number already registered",
// //                 success: false
// //             });
// //         }

// //         // Generate OTP
// //         const otp = otpService.generateOTP();

// //         // Log OTP for debugging
// //         console.log(`=================================`);
// //         console.log(`📱 Sending Phone OTP`);
// //         console.log(`📧 Email: ${foundEmail}`);
// //         console.log(`📱 Phone: ${formattedPhone}`);
// //         console.log(`🔢 OTP: ${otp}`);
// //         console.log(`=================================`);

// //         // ALWAYS SEND SMS - Remove development bypass
// //         try {
// //             const message = await twilioClient.messages.create({
// //                 body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
// //                 from: TWILIO_PHONE_NUMBER,
// //                 to: formattedPhone
// //             });

// //             console.log(`✅ Phone OTP sent successfully! SID: ${message.sid}`);

// //             // Update verification store with phone number
// //             userVerification.phoneNumber = cleanedPhone;
// //             userVerification.formattedPhone = formattedPhone;
// //             verifiedUsersStore.set(foundEmail, userVerification);

// //             // Store phone OTP
// //             phoneOTPStore.set(foundEmail, {
// //                 otp,
// //                 phoneNumber: cleanedPhone,
// //                 formattedPhone,
// //                 expiresAt: Date.now() + 10 * 60 * 1000
// //             });

// //             return res.status(200).json({
// //                 message: "Phone OTP sent successfully via SMS",
// //                 success: true,
// //                 phoneNumber: cleanedPhone
// //             });
// //         } catch (sendError) {
// //             console.error("Phone OTP sending error:", sendError);

// //             // Handle Twilio errors
// //             if (sendError.code === 21211) {
// //                 return res.status(400).json({
// //                     message: "Invalid phone number format. Please check your phone number.",
// //                     success: false,
// //                     error: sendError.message
// //                 });
// //             } else if (sendError.message && sendError.message.includes("unverified")) {
// //                 return res.status(400).json({
// //                     message: "This phone number is not verified in your Twilio trial account. Please verify your phone number in Twilio console or upgrade your account.",
// //                     success: false,
// //                     error: sendError.message,
// //                     twilioTrialMode: true
// //                 });
// //             }

// //             return res.status(500).json({
// //                 message: "Failed to send phone OTP. Please try again.",
// //                 success: false,
// //                 error: sendError.message
// //             });
// //         }
// //     } catch (error) {
// //         console.error("Send phone OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error sending phone OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // export const verifyPhoneOTP = async (req, res) => {
// //     try {
// //         const { phoneNumber, otp } = req.body;

// //         if (!phoneNumber || !otp) {
// //             return res.status(400).json({
// //                 message: "Phone number and OTP are required",
// //                 success: false
// //             });
// //         }

// //         // Clean phone number
// //         const cleanedPhone = phoneNumber.replace(/\D/g, '');

// //         // Find which email has this phone number
// //         let foundEmail = null;
// //         let storedData = null;

// //         for (const [email, data] of phoneOTPStore.entries()) {
// //             if (data.phoneNumber === cleanedPhone && Date.now() <= data.expiresAt) {
// //                 foundEmail = email;
// //                 storedData = data;
// //                 break;
// //             }
// //         }

// //         if (!storedData) {
// //             return res.status(400).json({
// //                 message: "No OTP found. Please request a new OTP.",
// //                 success: false
// //             });
// //         }

// //         if (Date.now() > storedData.expiresAt) {
// //             phoneOTPStore.delete(foundEmail);
// //             return res.status(400).json({
// //                 message: "OTP has expired. Please request a new OTP.",
// //                 success: false
// //             });
// //         }

// //         if (storedData.otp !== otp) {
// //             return res.status(400).json({
// //                 message: "Invalid OTP",
// //                 success: false
// //             });
// //         }

// //         // Update verification status
// //         const userVerification = verifiedUsersStore.get(foundEmail);
// //         if (userVerification) {
// //             userVerification.isPhoneVerified = true;
// //             userVerification.phoneNumber = cleanedPhone;
// //             userVerification.formattedPhone = storedData.formattedPhone;
// //             verifiedUsersStore.set(foundEmail, userVerification);
// //         }

// //         // Clean up phone OTP
// //         phoneOTPStore.delete(foundEmail);

// //         return res.status(200).json({
// //             message: "Phone verified successfully. You can now complete your registration.",
// //             success: true,
// //             email: foundEmail,
// //             nextStep: "complete_registration"
// //         });

// //     } catch (error) {
// //         console.error("Verify phone OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error verifying phone OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= STEP 5: COMPLETE REGISTRATION =================
// // // ================= STEP 5: COMPLETE REGISTRATION =================
// // export const completeRegistration = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             password,
// //             age,
// //             gender,
// //             // Counsellor fields
// //             qualification,
// //             specialization,
// //             experience,
// //             location,
// //             consultationMode,
// //             languages,
// //             aboutMe
// //         } = req.body;

// //         // VALIDATE REQUIRED FIELDS - FULLNAME IS REQUIRED
// //         if (!fullName || !email || !password) {
// //             return res.status(400).json({
// //                 message: "Full name, email, and password are required",
// //                 success: false,
// //                 required: ["fullName", "email", "password"]
// //             });
// //         }

// //         if (password.length < 6) {
// //             return res.status(400).json({
// //                 message: "Password must be at least 6 characters",
// //                 success: false
// //             });
// //         }

// //         // Check if user is verified
// //         const userVerification = verifiedUsersStore.get(email);

// //         if (!userVerification) {
// //             return res.status(400).json({
// //                 message: "No verification found. Please verify your email and phone first.",
// //                 success: false,
// //                 requiresVerification: true,
// //                 steps: {
// //                     emailVerified: false,
// //                     phoneVerified: false
// //                 }
// //             });
// //         }

// //         if (!userVerification.isEmailVerified) {
// //             return res.status(400).json({
// //                 message: "Email not verified. Please verify your email first.",
// //                 success: false,
// //                 requiresEmailVerification: true
// //             });
// //         }

// //         if (!userVerification.isPhoneVerified) {
// //             return res.status(400).json({
// //                 message: "Phone number not verified. Please verify your phone number first.",
// //                 success: false,
// //                 requiresPhoneVerification: true
// //             });
// //         }

// //         // Check if phone number exists in verification
// //         if (!userVerification.phoneNumber) {
// //             return res.status(400).json({
// //                 message: "Phone number not found. Please verify your phone number again.",
// //                 success: false
// //             });
// //         }

// //         // Check if user already exists
// //         const existingUser = await User.findOne({
// //             $or: [{ email }, { phoneNumber: userVerification.phoneNumber }]
// //         });

// //         if (existingUser) {
// //             verifiedUsersStore.delete(email);
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         // AUTO-DETECT ROLE
// //         const hasCounsellorFields = qualification && specialization && experience && location;
// //         const role = hasCounsellorFields ? "counsellor" : "user";

// //         // Validate counsellor required fields if role is counsellor
// //         if (role === "counsellor") {
// //             if (!qualification || !specialization || !experience || !location) {
// //                 return res.status(400).json({
// //                     message: "Counsellor requires: qualification, specialization, experience, and location",
// //                     success: false,
// //                     required: ["qualification", "specialization", "experience", "location"]
// //                 });
// //             }
// //         }

// //         // Hash password
// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Prepare user data - use fullName from request body
// //         const userData = {
// //             fullName,  // Use fullName from request body, NOT from verification
// //             email,
// //             phoneNumber: userVerification.phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role,
// //             profileCompleted: true,
// //             isEmailVerified: true,
// //             isActive: true
// //         };

// //         // Add counsellor-specific fields if role is counsellor
// //         if (role === "counsellor") {
// //             userData.qualification = qualification;
// //             userData.specialization = typeof specialization === 'string'
// //                 ? specialization.split(',').map(s => s.trim())
// //                 : specialization;
// //             userData.experience = Number(experience);
// //             userData.location = location;
// //             userData.consultationMode = typeof consultationMode === 'string'
// //                 ? consultationMode.split(',').map(m => m.trim())
// //                 : consultationMode || ["online"];
// //             userData.languages = typeof languages === 'string'
// //                 ? languages.split(',').map(l => l.trim())
// //                 : languages || [];
// //             userData.aboutMe = aboutMe || "";

// //             // Handle profile photo if uploaded
// //             if (req.file) {
// //                 userData.profilePhoto = saveLocalFile(req.file);
// //             }
// //         } else {
// //             // For users, allow optional fields
// //             if (specialization) {
// //                 userData.specialization = typeof specialization === 'string'
// //                     ? specialization.split(',').map(s => s.trim())
// //                     : specialization;
// //             }
// //             if (languages) {
// //                 userData.languages = typeof languages === 'string'
// //                     ? languages.split(',').map(l => l.trim())
// //                     : languages || [];
// //             }
// //             if (consultationMode) {
// //                 userData.consultationMode = typeof consultationMode === 'string'
// //                     ? consultationMode.split(',').map(m => m.trim())
// //                     : consultationMode || ["online"];
// //             }
// //         }

// //         // Create user
// //         const newUser = await User.create(userData);

// //         // Clean up verification data
// //         verifiedUsersStore.delete(email);

// //         // Clean up any remaining OTPs
// //         emailOTPStore.delete(email);
// //         phoneOTPStore.delete(email);

// //         // Auto-login after registration
// //         const accessToken = generateAccessToken(newUser._id);
// //         const refreshToken = generateRefreshToken(newUser._id);

// //         await Session.create({
// //             userId: newUser._id,
// //             refreshToken,
// //             isActive: true
// //         });

// //         // Set cookies
// //         res.cookie("accessToken", accessToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 15 * 60 * 1000
// //         });
// //         res.cookie("refreshToken", refreshToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 7 * 24 * 60 * 60 * 1000
// //         });

// //         return res.status(201).json({
// //             message: "Registration completed successfully!",
// //             success: true,
// //             user: newUser.toJSON(),
// //             accessToken,
// //             refreshToken,
// //             role: newUser.role
// //         });

// //     } catch (error) {
// //         console.error("Complete registration error:", error);
// //         if (req.file) {
// //             deleteLocalFile(saveLocalFile(req.file));
// //         }
// //         return res.status(500).json({
// //             message: "Error completing registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= RESEND OTP ENDPOINTS =================
// // export const resendEmailOTP = async (req, res) => {
// //     try {
// //         const { email } = req.body;

// //         if (!email) {
// //             return res.status(400).json({
// //                 message: "Email is required",
// //                 success: false
// //             });
// //         }

// //         const userVerification = verifiedUsersStore.get(email);
// //         if (!userVerification) {
// //             return res.status(404).json({
// //                 message: "No pending verification found",
// //                 success: false
// //             });
// //         }

// //         const otp = otpService.generateOTP();

// //         await otpService.sendEmailOTP(email, otp);

// //         emailOTPStore.set(email, {
// //             otp,
// //             expiresAt: Date.now() + 10 * 60 * 1000
// //         });

// //         return res.status(200).json({
// //             message: "Email OTP resent successfully",
// //             success: true
// //         });

// //     } catch (error) {
// //         console.error("Resend email OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error resending OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // export const resendPhoneOTP = async (req, res) => {
// //     try {
// //         const { email } = req.body;

// //         if (!email) {
// //             return res.status(400).json({
// //                 message: "Email is required",
// //                 success: false
// //             });
// //         }

// //         const userVerification = verifiedUsersStore.get(email);
// //         if (!userVerification || !userVerification.phoneNumber) {
// //             return res.status(404).json({
// //                 message: "No phone number found for verification",
// //                 success: false
// //             });
// //         }

// //         const otp = otpService.generateOTP();

// //         let formattedPhone = userVerification.phoneNumber;
// //         if (!formattedPhone.startsWith('+')) {
// //             formattedPhone = `+91${formattedPhone}`;
// //         }

// //         await twilioClient.messages.create({
// //             body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
// //             from: TWILIO_PHONE_NUMBER,
// //             to: formattedPhone
// //         });

// //         phoneOTPStore.set(email, {
// //             otp,
// //             phoneNumber: userVerification.phoneNumber,
// //             formattedPhone,
// //             expiresAt: Date.now() + 10 * 60 * 1000
// //         });

// //         return res.status(200).json({
// //             message: "Phone OTP resent successfully",
// //             success: true
// //         });

// //     } catch (error) {
// //         console.error("Resend phone OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error resending phone OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // OTP temporary storage
// // const emailOTPStore = new Map();
// // const phoneOTPStore = new Map();

// // // Clean up expired OTPs every hour
// // setInterval(() => {
// //     const now = Date.now();
// //     for (const [email, data] of emailOTPStore.entries()) {
// //         if (data.expiresAt < now) {
// //             emailOTPStore.delete(email);
// //         }
// //     }
// //     for (const [email, data] of phoneOTPStore.entries()) {
// //         if (data.expiresAt < now) {
// //             phoneOTPStore.delete(email);
// //         }
// //     }
// // }, 60 * 60 * 1000);

// // Keep all your existing functions (getAllCounsellors, getCounsellorById, loginUser, etc.)
// // ... (these remain the same as in your original code)
// // ================= TEMPORARY STORAGE FOR UNVERIFIED USERS =================
// // Store unverified user data temporarily (in memory or Redis, but for simplicity use a Map)
// // const tempUserStore = new Map(); // Key: email, Value: { userData, otp, expiresAt }

// // // Clean up expired temp users every hour
// // setInterval(() => {
// //     const now = Date.now();
// //     for (const [email, data] of tempUserStore.entries()) {
// //         if (data.expiresAt < now) {
// //             tempUserStore.delete(email);
// //         }
// //     }
// // }, 60 * 60 * 1000);

// // // ================= STEP 1: INITIATE REGISTRATION - SEND OTP =================
// // export const initiateRegistration = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             age,
// //             gender,
// //             role = "user",
// //             // Counsellor fields
// //             qualification,
// //             specialization,
// //             experience,
// //             location,
// //             consultationMode,
// //             languages,
// //             aboutMe
// //         } = req.body;

// //         // Validate required fields
// //         if (!fullName || !email || !phoneNumber) {
// //             return res.status(400).json({
// //                 message: "Full name, email, and phone number are required",
// //                 success: false
// //             });
// //         }

// //         if (phoneNumber.length !== 10) {
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Check if user already exists and is verified
// //         const existingUser = await User.findOne({
// //             $or: [{ email }, { phoneNumber }]
// //         });

// //         if (existingUser) {
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         // Generate OTP
// //         const emailOTP = otpService.generateOTP();

// //         // Send OTP
// //         try {
// //             await otpService.sendEmailOTP(email, emailOTP, fullName);
// //         } catch (sendError) {
// //             console.error("OTP sending error:", sendError);
// //             return res.status(500).json({
// //                 message: "Failed to send verification code. Please try again.",
// //                 success: false,
// //                 error: sendError.message
// //             });
// //         }

// //         // Prepare user data for temporary storage
// //         const userData = {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             age: age || null,
// //             gender: gender || "male",
// //             role,
// //             profilePhoto: null
// //         };

// //         // Add counsellor-specific fields if role is counsellor
// //         if (role === "counsellor") {
// //             // Validate counsellor required fields
// //             if (!qualification || !specialization || !experience || !location) {
// //                 return res.status(400).json({
// //                     message: "Counsellor requires additional information",
// //                     success: false,
// //                     required: ["qualification", "specialization", "experience", "location"]
// //                 });
// //             }

// //             userData.qualification = qualification;
// //             userData.specialization = typeof specialization === 'string'
// //                 ? specialization.split(',').map(s => s.trim())
// //                 : specialization;
// //             userData.experience = Number(experience);
// //             userData.location = location;
// //             userData.consultationMode = typeof consultationMode === 'string'
// //                 ? consultationMode.split(',').map(m => m.trim())
// //                 : consultationMode || ["online"];
// //             userData.languages = typeof languages === 'string'
// //                 ? languages.split(',').map(l => l.trim())
// //                 : languages || [];
// //             userData.aboutMe = aboutMe || "";

// //             // Handle profile photo if uploaded
// //             if (req.file) {
// //                 userData.profilePhoto = saveLocalFile(req.file);
// //             }
// //         }

// //         // Store in temporary storage with expiry (10 minutes)
// //         tempUserStore.set(email, {
// //             userData,
// //             otp: emailOTP,
// //             expiresAt: Date.now() + 10 * 60 * 1000
// //         });

// //         return res.status(200).json({
// //             message: "Verification code sent to your email. Please verify to complete registration.",
// //             success: true,
// //             email: email,
// //             requiresVerification: true
// //         });

// //     } catch (error) {
// //         console.log("Initiate registration error:", error);
// //         if (req.file) {
// //             deleteLocalFile(saveLocalFile(req.file));
// //         }
// //         return res.status(500).json({
// //             message: "Error initiating registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= STEP 2: VERIFY OTP AND CREATE USER =================
// // export const verifyAndCreateUser = async (req, res) => {
// //     try {
// //         const {  otp, pass } = req.body;

// //         if (!email || !otp || !password) {
// //             return res.status(400).json({
// //                 message: "Email, OTP, and password are required",
// //                 success: false
// //             });
// //         }

// //         if (password !== confirmPassword) {
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password and confirmPassword should match"
// //             });
// //         }

// //         if (password.length < 6) {
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password must be at least 6 characters"
// //             });
// //         }

// //         // Get temporary user data
// //         const tempData = tempUserStore.get(email);

// //         if (!tempData) {
// //             return res.status(404).json({
// //                 message: "Registration session expired or not found. Please start over.",
// //                 success: false
// //             });
// //         }

// //         // Check if OTP expired
// //         if (Date.now() > tempData.expiresAt) {
// //             tempUserStore.delete(email);
// //             return res.status(400).json({
// //                 message: "OTP has expired. Please start registration again.",
// //                 success: false
// //             });
// //         }

// //         // Verify OTP
// //         if (tempData.otp !== otp) {
// //             return res.status(400).json({
// //                 message: "Invalid OTP. Please try again.",
// //                 success: false
// //             });
// //         }

// //         // Check again if user already exists (double-check)
// //         const existingUser = await User.findOne({
// //             $or: [{ email }, { phoneNumber: tempData.userData.phoneNumber }]
// //         });

// //         if (existingUser) {
// //             tempUserStore.delete(email);
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         // Hash password
// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Create permanent user
// //         const userData = {
// //             ...tempData.userData,
// //             password: hashedPassword,
// //             profileCompleted: true,
// //             isEmailVerified: true,
// //             isPhoneVerified: true // Phone is considered verified since we have it
// //         };

// //         const newUser = await User.create(userData);

// //         // Delete temporary data
// //         tempUserStore.delete(email);

// //         // Auto-login after registration
// //         const accessToken = generateAccessToken(newUser._id);
// //         const refreshToken = generateRefreshToken(newUser._id);

// //         await Session.create({
// //             userId: newUser._id,
// //             refreshToken,
// //             isActive: true
// //         });

// //         // Set cookies
// //         res.cookie("accessToken", accessToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 15 * 60 * 1000
// //         });
// //         res.cookie("refreshToken", refreshToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 7 * 24 * 60 * 60 * 1000
// //         });

// //         return res.status(201).json({
// //             message: "Registration completed successfully!",
// //             success: true,
// //             user: newUser.toJSON(),
// //             accessToken,
// //             refreshToken,
// //             role: newUser.role
// //         });

// //     } catch (error) {
// //         console.error("Complete registration error:", error);
// //         return res.status(500).json({
// //             message: "Error completing registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= RESEND REGISTRATION OTP =================
// // export const resendRegistrationOTP = async (req, res) => {
// //     try {
// //         const { email } = req.body;

// //         if (!email) {
// //             return res.status(400).json({
// //                 message: "Email is required",
// //                 success: false
// //             });
// //         }

// //         const tempData = tempUserStore.get(email);

// //         if (!tempData) {
// //             return res.status(404).json({
// //                 message: "Registration session not found. Please start over.",
// //                 success: false
// //             });
// //         }

// //         const newOTP = otpService.generateOTP();

// //         // Send new OTP
// //         await otpService.sendEmailOTP(email, newOTP, tempData.userData.fullName);

// //         // Update OTP and expiry
// //         tempData.otp = newOTP;
// //         tempData.expiresAt = Date.now() + 10 * 60 * 1000;
// //         tempUserStore.set(email, tempData);

// //         return res.status(200).json({
// //             message: "New verification code sent to your email",
// //             success: true
// //         });

// //     } catch (error) {
// //         console.error("Resend OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error resending OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // ================= CHECK REGISTRATION STATUS =================
// export const checkRegistrationStatus = async (req, res) => {
//     try {
//         const { email } = req.params;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const tempData = tempUserStore.get(email);

//         if (!tempData) {
//             return res.status(404).json({
//                 message: "No active registration session found",
//                 success: false,
//                 exists: false
//             });
//         }

//         const timeRemaining = Math.max(0, Math.floor((tempData.expiresAt - Date.now()) / 1000));

//         return res.status(200).json({
//             success: true,
//             exists: true,
//             email: email,
//             role: tempData.userData.role,
//             otpExpiresIn: timeRemaining,
//             expiresAt: tempData.expiresAt
//         });

//     } catch (error) {
//         console.error("Check status error:", error);
//         return res.status(500).json({
//             message: "Error checking registration status",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= REGISTER USER (Deprecated - use new flow) =================
// export const registerUserOnly = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use the new registration flow: POST /api/auth/initiate-registration first, then POST /api/auth/verify-and-create-user",
//         success: false,
//         instructions: {
//             step1: "POST /api/auth/initiate-registration with user details",
//             step2: "POST /api/auth/verify-and-create-user with email, otp, and password"
//         }
//     });
// };

// // ================= REGISTER COUNSELLOR (Deprecated - use new flow) =================
// export const registerCounsellor = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use the new registration flow: POST /api/auth/initiate-registration first, then POST /api/auth/verify-and-create-user",
//         success: false,
//         instructions: {
//             step1: "POST /api/auth/initiate-registration with counsellor details (including role='counsellor')",
//             step2: "POST /api/auth/verify-and-create-user with email, otp, and password"
//         }
//     });
// };

// // ================= VERIFY EMAIL OTP (Legacy - use new flow) =================
// // export const verifyEmailOTP = async (req, res) => {
// //     return res.status(400).json({
// //         message: "This endpoint is deprecated. Please use the new flow: POST /api/auth/verify-and-create-user",
// //         success: false
// //     });
// // };

// // ================= RESEND OTP (Legacy) =================
// export const resendOTPS = async (req, res) => {
//     return res.status(400).json({
//         message: "This endpoint is deprecated. Please use POST /api/auth/resend-registration-otp",
//         success: false
//     });
// };

// // ================= CHECK VERIFICATION STATUS (Legacy) =================
// export const checkVerificationStatus = async (req, res) => {
//     return res.status(400).json({
//         message: "This endpoint is deprecated. Please use GET /api/auth/registration-status/:email",
//         success: false
//     });
// };

// // ================= LOGIN USER (Unchanged) =================
// export const loginUser = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({
//                 message: "Email and password are required",
//                 success: false
//             });
//         }

//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         if (!user.isActive) {
//             return res.status(401).json({
//                 message: "Account is deactivated. Please contact support.",
//                 success: false
//             });
//         }

//         const match = await bcrypt.compare(password, user.password);

//         if (!match) {
//             return res.status(401).json({
//                 message: "Invalid password",
//                 success: false
//             });
//         }

//         const activeSession = await Session.findOne({
//             userId: user._id,
//             isActive: true
//         });

//         if (activeSession) {
//             return res.status(400).json({
//                 message: "User already logged in. Please use OTP login",
//                 success: false
//             });
//         }

//         const accessToken = generateAccessToken(user._id);
//         const refreshToken = generateRefreshToken(user._id);

//         await Session.create({
//             userId: user._id,
//             refreshToken,
//             isActive: true
//         });

//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });
//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 7 * 24 * 60 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Login successful",
//             success: true,
//             accessToken,
//             refreshToken,
//             user: user.toJSON(),
//             role: user.role
//         });

//     } catch (error) {
//         console.log("Login error:", error);
//         return res.status(500).json({
//             message: "Error in login",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // // controllers/authController.js
// // import User from "../models/userModel.js";
// // import bcrypt from "bcryptjs";
// // import Session from "../models/sessionModel.js";
// // import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// // import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";
// // import otpService from "../services/otpService.js";

// // // ================= REGISTER USER WITH OTP =================
// // export const registerUserOnly = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password,
// //             confirmPassword,
// //             age,
// //             gender
// //         } = req.body;

// //         // Validate required fields
// //         if (!fullName || !email || !phoneNumber || !password) {
// //             return res.status(400).json({
// //                 message: "Please fill all required fields",
// //                 success: false,
// //                 required: ["fullName", "email", "phoneNumber", "password"]
// //             });
// //         }

// //         if (password !== confirmPassword) {
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password and confirmPassword should match"
// //             });
// //         }

// //         if (phoneNumber.length !== 10) {
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Check if user exists
// //         const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }] });

// //         if (existingUser) {
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Generate OTPs
// //         const emailOTP = otpService.generateOTP();
// //         const phoneOTP = otpService.generateOTP();

// //         // Send OTPs
// //         try {
// //             await Promise.all([
// //                 otpService.sendEmailOTP(email, emailOTP, fullName),
// //                 otpService.sendPhoneOTP(phoneNumber, phoneOTP)
// //             ]);
// //         } catch (sendError) {
// //             console.error("OTP sending error:", sendError);
// //             return res.status(500).json({
// //                 message: "Failed to send verification codes. Please try again.",
// //                 success: false,
// //                 error: sendError.message
// //             });
// //         }

// //         // Create user with OTP data
// //         const userData = {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role: "user",
// //             profileCompleted: false, // Will be completed after verification
// //             profilePhoto: null,
// //             isEmailVerified: false,
// //             // isPhoneVerified: false,
// //             emailOTP: {
// //                 code: emailOTP,
// //                 expiresAt: new Date(Date.now() + 10 * 60 * 1000)
// //             },
// //             phoneOTP: {
// //                 code: phoneOTP,
// //                 expiresAt: new Date(Date.now() + 10 * 60 * 1000)
// //             }
// //         };

// //         const newUser = await User.create(userData);

// //         return res.status(201).json({
// //             message: "Registration successful. Please verify your email and phone with OTPs.",
// //             success: true,
// //             userId: newUser._id,
// //             email: newUser.email,
// //             phoneNumber: newUser.phoneNumber,
// //             requiresVerification: true
// //         });

// //     } catch (error) {
// //         console.log("User registration error:", error);
// //         return res.status(500).json({
// //             message: "Error in user registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= REGISTER COUNSELLOR WITH OTP =================
// // export const registerCounsellor = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password,
// //             confirmPassword,
// //             age,
// //             gender,
// //             qualification,
// //             specialization,
// //             experience,
// //             location,
// //             consultationMode,
// //             languages,
// //             aboutMe
// //         } = req.body;

// //         // Validate required fields for counsellor
// //         if (!fullName || !email || !phoneNumber || !password) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 message: "Please fill all required fields",
// //                 success: false,
// //                 required: ["fullName", "email", "phoneNumber", "password"]
// //             });
// //         }

// //         if (password !== confirmPassword) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password and confirmPassword should match"
// //             });
// //         }

// //         if (phoneNumber.length !== 10) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Check if counsellor exists
// //         const existingCounsellor = await User.findOne({ $or: [{ email }, { phoneNumber }] });

// //         if (existingCounsellor) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(409).json({
// //                 message: "Counsellor already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Handle profile photo upload for counsellor only
// //         let profilePhotoUrl = null;
// //         if (req.file) {
// //             profilePhotoUrl = saveLocalFile(req.file);
// //         }

// //         // Generate OTPs
// //         const emailOTP = otpService.generateOTP();
// //         // const phoneOTP = otpService.generateOTP();

// //         // Send OTPs
// //         try {
// //             await Promise.all([
// //                 otpService.sendEmailOTP(email, emailOTP, fullName),
// //                 // otpService.sendPhoneOTP(phoneNumber, phoneOTP)
// //             ]);
// //         } catch (sendError) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             console.error("OTP sending error:", sendError);
// //             return res.status(500).json({
// //                 message: "Failed to send verification codes. Please try again.",
// //                 success: false,
// //                 error: sendError.message
// //             });
// //         }

// //         // Parse arrays
// //         let parsedSpecialization = specialization;
// //         if (typeof specialization === 'string') {
// //             parsedSpecialization = specialization.split(',').map(s => s.trim());
// //         }

// //         let parsedConsultationMode = consultationMode;
// //         if (typeof consultationMode === 'string') {
// //             parsedConsultationMode = consultationMode.split(',').map(m => m.trim());
// //         }

// //         let parsedLanguages = languages;
// //         if (typeof languages === 'string') {
// //             parsedLanguages = languages.split(',').map(l => l.trim());
// //         }

// //         // Create counsellor with OTP data
// //         const counsellorData = {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role: "counsellor",
// //             profileCompleted: false, // Will be completed after verification
// //             profilePhoto: profilePhotoUrl,
// //             qualification,
// //             specialization: parsedSpecialization || [],
// //             experience: Number(experience),
// //             location,
// //             consultationMode: parsedConsultationMode || ["online"],
// //             languages: parsedLanguages || [],
// //             aboutMe: aboutMe || "",
// //             isEmailVerified: false,
// //             // isPhoneVerified: false,
// //             emailOTP: {
// //                 code: emailOTP,
// //                 expiresAt: new Date(Date.now() + 10 * 60 * 1000)
// //             },
// //             // phoneOTP: {
// //             //     code: phoneOTP,
// //             //     expiresAt: new Date(Date.now() + 10 * 60 * 1000)
// //             // }
// //         };

// //         const newCounsellor = await User.create(counsellorData);

// //         return res.status(201).json({
// //             message: "Counsellor registration successful. Please verify your email and phone with OTPs.",
// //             success: true,
// //             userId: newCounsellor._id,
// //             email: newCounsellor.email,
// //             requiresVerification: true
// //         });

// //     } catch (error) {
// //         if (req.file) {
// //             deleteLocalFile(saveLocalFile(req.file));
// //         }
// //         console.log("Counsellor registration error:", error);
// //         return res.status(500).json({
// //             message: "Error in counsellor registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= VERIFY EMAIL OTP =================
// // export const verifyEmailOTP = async (req, res) => {
// //     try {
// //         const { userId, otp } = req.body;

// //         if (!userId || !otp) {
// //             return res.status(400).json({
// //                 message: "User ID and OTP are required",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findById(userId);
// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         if (user.isEmailVerified) {
// //             return res.status(400).json({
// //                 message: "Email is already verified",
// //                 success: false
// //             });
// //         }

// //         const verification = otpService.verifyOTP(user, 'email', otp);

// //         if (!verification.valid) {
// //             return res.status(400).json({
// //                 message: verification.message,
// //                 success: false
// //             });
// //         }

// //         user.isEmailVerified = true;
// //         otpService.clearOTP(user, 'email');

// //         // Check if both verifications are complete
// //         // if (user.isPhoneVerified) {
// //         //     user.profileCompleted = true;
// //         //     user.isVerified = true;
// //         // }

// //         await user.save();

// //         return res.status(200).json({
// //             message: "Email verified successfully",
// //             success: true,
// //             profileCompleted: user.profileCompleted,
// //             // isPhoneVerified: user.isPhoneVerified
// //         });

// //     } catch (error) {
// //         console.error("Email verification error:", error);
// //         return res.status(500).json({
// //             message: "Error in email verification",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= VERIFY PHONE OTP =================
// // // export const verifyPhoneOTP = async (req, res) => {
// // //     try {
// // //         const { userId, otp } = req.body;

// // //         if (!userId || !otp) {
// // //             return res.status(400).json({
// // //                 message: "User ID and OTP are required",
// // //                 success: false
// // //             });
// // //         }

// // //         const user = await User.findById(userId);
// // //         if (!user) {
// // //             return res.status(404).json({
// // //                 message: "User not found",
// // //                 success: false
// // //             });
// // //         }

// // //         if (user.isPhoneVerified) {
// // //             return res.status(400).json({
// // //                 message: "Phone is already verified",
// // //                 success: false
// // //             });
// // //         }

// // //         const verification = otpService.verifyOTP(user, 'phone', otp);

// // //         if (!verification.valid) {
// // //             return res.status(400).json({
// // //                 message: verification.message,
// // //                 success: false
// // //             });
// // //         }

// // //         user.isPhoneVerified = true;
// // //         otpService.clearOTP(user, 'phone');

// // //         // Check if both verifications are complete
// // //         if (user.isEmailVerified) {
// // //             user.profileCompleted = true;
// // //             user.isVerified = true;
// // //         }

// // //         await user.save();

// // //         return res.status(200).json({
// // //             message: "Phone verified successfully",
// // //             success: true,
// // //             profileCompleted: user.profileCompleted,
// // //             isEmailVerified: user.isEmailVerified
// // //         });

// // //     } catch (error) {
// // //         console.error("Phone verification error:", error);
// // //         return res.status(500).json({
// // //             message: "Error in phone verification",
// // //             success: false,
// // //             error: error.message
// // //         });
// // //     }
// // // };

// // // ================= RESEND OTP =================
// // export const resendOTPS = async (req, res) => {
// //     try {
// //         const { userId, type } = req.body;

// //         if (!userId || !type) {
// //             return res.status(400).json({
// //                 message: "User ID and OTP type are required",
// //                 success: false
// //             });
// //         }

// //         if (type !== 'email' && type !== 'phone') {
// //             return res.status(400).json({
// //                 message: "Invalid OTP type. Must be 'email' or 'phone'",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findById(userId);
// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         // Check if already verified
// //         if (type === 'email' && user.isEmailVerified) {
// //             return res.status(400).json({
// //                 message: "Email is already verified",
// //                 success: false
// //             });
// //         }

// //         // if (type === 'phone' && user.isPhoneVerified) {
// //         //     return res.status(400).json({
// //         //         message: "Phone is already verified",
// //         //         success: false
// //         //     });
// //         // }

// //         const newOTP = otpService.generateOTP();

// //         if (type === 'email') {
// //             await otpService.sendEmailOTP(user.email, newOTP, user.fullName);
// //             otpService.storeOTP(user, 'email', newOTP);
// //         }
// //         //  else {
// //         //     await otpService.sendPhoneOTP(user.phoneNumber, newOTP);
// //         //     otpService.storeOTP(user, 'phone', newOTP);
// //         // }

// //         await user.save();

// //         return res.status(200).json({
// //             message: `${type === 'email' ? 'Email' : 'Phone'} OTP resent successfully`,
// //             success: true
// //         });

// //     } catch (error) {
// //         console.error("Resend OTP error:", error);
// //         return res.status(500).json({
// //             message: "Error resending OTP",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= CHECK VERIFICATION STATUS =================
// // export const checkVerificationStatus = async (req, res) => {
// //     try {
// //         const { userId } = req.params;

// //         if (!userId) {
// //             return res.status(400).json({
// //                 message: "User ID is required",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findById(userId).select("isEmailVerified  profileCompleted");

// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         return res.status(200).json({
// //             success: true,
// //             isEmailVerified: user.isEmailVerified,
// //             // isPhoneVerified: user.isPhoneVerified,
// //             profileCompleted: user.profileCompleted
// //         });

// //     } catch (error) {
// //         console.error("Verification status error:", error);
// //         return res.status(500).json({
// //             message: "Error checking verification status",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= UPDATE LOGIN TO CHECK VERIFICATION =================
// // export const loginUser = async (req, res) => {
// //     try {
// //         const { email, password } = req.body;

// //         if (!email || !password) {
// //             return res.status(400).json({
// //                 message: "Email and password are required",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findOne({ email });

// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         // Check if user is verified
// //         if (!user.isEmailVerified ) {
// //             return res.status(403).json({
// //                 message: "Account not verified. Please verify your email and phone number first.",
// //                 success: false,
// //                 requiresVerification: true,
// //                 userId: user._id,
// //                 isEmailVerified: user.isEmailVerified,
// //                 // isPhoneVerified: user.isPhoneVerified
// //             });
// //         }

// //         if (!user.isActive) {
// //             return res.status(401).json({
// //                 message: "Account is deactivated. Please contact support.",
// //                 success: false
// //             });
// //         }

// //         const match = await bcrypt.compare(password, user.password);

// //         if (!match) {
// //             return res.status(401).json({
// //                 message: "Invalid password",
// //                 success: false
// //             });
// //         }

// //         const activeSession = await Session.findOne({
// //             userId: user._id,
// //             isActive: true
// //         });

// //         if (activeSession) {
// //             return res.status(400).json({
// //                 message: "User already logged in. Please use OTP login",
// //                 success: false
// //             });
// //         }

// //         const accessToken = generateAccessToken(user._id);
// //         const refreshToken = generateRefreshToken(user._id);

// //         await Session.create({
// //             userId: user._id,
// //             refreshToken,
// //             isActive: true
// //         });

// //         res.cookie("accessToken", accessToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 15 * 60 * 1000
// //         })
// //         res.cookie("refreshToken", refreshToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 7 * 24 * 60 * 60 * 1000
// //         })
// //         .status(200)
// //         .json({
// //             message: "Login successful",
// //             success: true,
// //             accessToken,
// //             refreshToken,
// //             user: user.toJSON(),
// //             role: user.role
// //         });

// //     } catch (error) {
// //         console.log("Login error:", error);
// //         return res.status(500).json({
// //             message: "Error in login",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // Export all other existing functions (getAllCounsellors, getCounsellorById, etc.)
// // ... (keep all your existing functions)
// // // controllers/authController.js
// // import User from "../models/userModel.js";
// // import bcrypt from "bcryptjs";
// // import Session from "../models/sessionModel.js";
// // import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// // import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";

// // // ================= REGISTER USER (No Photo Upload) =================
// // export const registerUserOnly = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password,
// //             confirmPassword,
// //             age,
// //             gender
// //         } = req.body;

// //         // Validate required fields
// //         if (!fullName || !email || !phoneNumber || !password) {
// //             return res.status(400).json({
// //                 message: "Please fill all required fields",
// //                 success: false,
// //                 required: ["fullName", "email", "phoneNumber", "password"]
// //             });
// //         }

// //         if (password !== confirmPassword) {
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password and confirmPassword should match"
// //             });
// //         }

// //         if (phoneNumber.length !== 10) {
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Check if user exists
// //         const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }] });

// //         if (existingUser) {
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Create user with role "user" - NO PHOTO
// //         const userData = {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role: "user",
// //             profileCompleted: true,
// //             profilePhoto: null // No photo for users
// //         };

// //         const newUser = await User.create(userData);

// //         return res.status(201).json({
// //             message: "User registered successfully",
// //             success: true,
// //             user: newUser.toJSON()
// //         });

// //     } catch (error) {
// //         console.log("User registration error:", error);
// //         return res.status(500).json({
// //             message: "Error in user registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= REGISTER COUNSELLOR (With Photo Upload) =================
// // export const registerCounsellor = async (req, res) => {
// //     try {
// //         const {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password,
// //             confirmPassword,
// //             age,
// //             gender,
// //             qualification,
// //             specialization,
// //             experience,
// //             location,
// //             consultationMode,
// //             languages,
// //             aboutMe
// //         } = req.body;

// //         // Validate required fields for counsellor
// //         if (!fullName || !email || !phoneNumber || !password) {
// //             // Delete uploaded file if exists
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 message: "Please fill all required fields",
// //                 success: false,
// //                 required: ["fullName", "email", "phoneNumber", "password"]
// //             });
// //         }

// //         // Validate counsellor-specific required fields
// //         if (!qualification || !specialization || !experience || !location) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 message: "Counsellor requires additional information",
// //                 success: false,
// //                 required: ["qualification", "specialization", "experience", "location"]
// //             });
// //         }

// //         if (password !== confirmPassword) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 success: false,
// //                 message: "Password and confirmPassword should match"
// //             });
// //         }

// //         if (phoneNumber.length !== 10) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(400).json({
// //                 message: "Phone number must be 10 digits",
// //                 success: false
// //             });
// //         }

// //         // Check if counsellor exists
// //         const existingCounsellor = await User.findOne({ $or: [{ email }, { phoneNumber }] });

// //         if (existingCounsellor) {
// //             if (req.file) {
// //                 deleteLocalFile(saveLocalFile(req.file));
// //             }
// //             return res.status(409).json({
// //                 message: "Counsellor already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Handle profile photo upload for counsellor only
// //         let profilePhotoUrl = null;
// //         if (req.file) {
// //             profilePhotoUrl = saveLocalFile(req.file);
// //         }

// //         // Parse arrays if they come as strings
// //         let parsedSpecialization = specialization;
// //         if (typeof specialization === 'string') {
// //             parsedSpecialization = specialization.split(',').map(s => s.trim());
// //         }

// //         let parsedConsultationMode = consultationMode;
// //         if (typeof consultationMode === 'string') {
// //             parsedConsultationMode = consultationMode.split(',').map(m => m.trim());
// //         }

// //         let parsedLanguages = languages;
// //         if (typeof languages === 'string') {
// //             parsedLanguages = languages.split(',').map(l => l.trim());
// //         }

// //         // Create counsellor with role "counsellor" and photo
// //         const counsellorData = {
// //             fullName,
// //             email,
// //             phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role: "counsellor",
// //             profileCompleted: true,
// //             profilePhoto: profilePhotoUrl, // Only counsellors have photo
// //             qualification,
// //             specialization: parsedSpecialization || [],
// //             experience: Number(experience),
// //             location,
// //             consultationMode: parsedConsultationMode || ["online"],
// //             languages: parsedLanguages || [],
// //             aboutMe: aboutMe || ""
// //         };

// //         const newCounsellor = await User.create(counsellorData);

// //         return res.status(201).json({
// //             message: "Counsellor registered successfully",
// //             success: true,
// //             user: newCounsellor.toJSON()
// //         });

// //     } catch (error) {
// //         if (req.file) {
// //             deleteLocalFile(saveLocalFile(req.file));
// //         }
// //         console.log("Counsellor registration error:", error);
// //         return res.status(500).json({
// //             message: "Error in counsellor registration",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // // ================= LOGIN (Same for both) =================
// // export const loginUser = async (req, res) => {
// //     try {
// //         const { email, password } = req.body;

// //         if (!email || !password) {
// //             return res.status(400).json({
// //                 message: "Email and password are required",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findOne({ email });

// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         if (!user.isActive) {
// //             return res.status(401).json({
// //                 message: "Account is deactivated. Please contact support.",
// //                 success: false
// //             });
// //         }

// //         const match = await bcrypt.compare(password, user.password);

// //         if (!match) {
// //             return res.status(401).json({
// //                 message: "Invalid password",
// //                 success: false
// //             });
// //         }

// //         const activeSession = await Session.findOne({
// //             userId: user._id,
// //             isActive: true
// //         });

// //         if (activeSession) {
// //             return res.status(400).json({
// //                 message: "User already logged in. Please use OTP login",
// //                 success: false
// //             });
// //         }

// //         const accessToken = generateAccessToken(user._id);
// //         const refreshToken = generateRefreshToken(user._id);

// //         await Session.create({
// //             userId: user._id,
// //             refreshToken,
// //             isActive: true
// //         });

// //         res.cookie("accessToken", accessToken, {
// //                 httpOnly: true,
// //                 secure: process.env.NODE_ENV === "production",
// //                 sameSite: "strict",
// //                 maxAge: 15 * 60 * 1000
// //             })
// //         res.cookie("refreshToken", refreshToken, {
// //                 httpOnly: true,
// //                 secure: process.env.NODE_ENV === "production",
// //                 sameSite: "strict",
// //                 maxAge: 7 * 24 * 60 * 60 * 1000
// //             })
// //             .status(200)
// //             .json({
// //                 message: "Login successful",
// //                 success: true,
// //                 accessToken,
// //                 refreshToken,
// //                 user: user.toJSON(),
// //                 role: user.role
// //             });

// //     } catch (error) {
// //         console.log("Login error:", error);
// //         return res.status(500).json({
// //             message: "Error in login",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // ================= GET ALL COUNSELLORS =================
// export const getAllCounsellors = async (req, res) => {
//     try {
//         const { specialization, location, consultationMode, minExperience } = req.query;

//         let filter = {
//             role: "counsellor",
//             isActive: true,
//             profileCompleted: true
//         };

//         if (specialization) {
//             filter.specialization = { $in: [specialization] };
//         }

//         if (location) {
//             filter.location = { $regex: location, $options: 'i' };
//         }

//         if (consultationMode) {
//             filter.consultationMode = { $in: [consultationMode] };
//         }

//         if (minExperience) {
//             filter.experience = { $gte: Number(minExperience) };
//         }

//         const counsellors = await User.find(filter)
//             .select("-password")
//             .sort({ createdAt: -1 });

//         return res.status(200).json({
//             message: "Counsellors fetched successfully",
//             success: true,
//             counsellors,
//             count: counsellors.length
//         });

//     } catch (error) {
//         console.log("Get counsellors error:", error);
//         return res.status(500).json({
//             message: "Error in fetching counsellors",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET SINGLE COUNSELLOR =================
// export const getCounsellorById = async (req, res) => {
//     try {
//         const { counsellorId } = req.params;

//         if (!counsellorId) {
//             return res.status(400).json({
//                 message: "Counsellor ID is required",
//                 success: false
//             });
//         }

//         const counsellor = await User.findOne({
//             _id: counsellorId,
//             role: "counsellor",
//             isActive: true
//         }).select("-password");

//         if (!counsellor) {
//             return res.status(404).json({
//                 message: "Counsellor not found",
//                 success: false
//             });
//         }

//         return res.status(200).json({
//             message: "Counsellor fetched successfully",
//             success: true,
//             counsellor: counsellor.toJSON()
//         });

//     } catch (error) {
//         console.log("Get counsellor error:", error);
//         return res.status(500).json({
//             message: "Error in fetching counsellor",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET CURRENT USER PROFILE =================
// export const getMyProfile = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;

//         if (!userId) {
//             return res.status(401).json({
//                 message: "Authentication required",
//                 success: false
//             });
//         }

//         const user = await User.findById(userId).select("-password");

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         return res.status(200).json({
//             message: "Profile fetched successfully",
//             success: true,
//             user: user.toJSON()
//         });

//     } catch (error) {
//         console.log("Get profile error:", error);
//         return res.status(500).json({
//             message: "Error in fetching profile",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= UPDATE USER (With Photo Upload Only for Counsellors) =================
// export const updateUser = async (req, res) => {
//     try {
//         if (!req.userId && !req.user) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(401).json({
//                 message: "Authentication required",
//                 success: false
//             });
//         }

//         const userId = req.user?._id || req.userId;
//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         let allowedUpdates = [
//             'fullName',
//             'anonymous',
//             'phoneNumber',
//             'age',
//             'gender',
//         ];

//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push(
//                 'qualification',
//                 'specialization',
//                 'experience',
//                 'location',
//                 'consultationMode',
//                 'languages',
//                 'aboutMe'
//             );
//         }

//         const updates = {};
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") {
//                 updates[field] = req.body[field];
//             }
//         });

//         // Handle profile photo - ONLY for counsellors
//         if (req.file) {
//             if (currentUser.role !== "counsellor") {
//                 deleteLocalFile(saveLocalFile(req.file));
//                 return res.status(403).json({
//                     message: "Only counsellors can upload profile photos",
//                     success: false
//                 });
//             }

//             if (currentUser.profilePhoto) {
//                 deleteLocalFile(currentUser.profilePhoto);
//             }
//             const newPhotoUrl = saveLocalFile(req.file);
//             updates.profilePhoto = newPhotoUrl;
//         }

//         if (Object.keys(updates).length === 0 && !req.file) {
//             return res.status(400).json({
//                 message: "No valid fields to update",
//                 success: false
//             });
//         }

//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Convert arrays
//         if (updates.specialization && typeof updates.specialization === 'string') {
//             updates.specialization = updates.specialization.split(',').map(s => s.trim());
//         }
//         if (updates.consultationMode && typeof updates.consultationMode === 'string') {
//             updates.consultationMode = updates.consultationMode.split(',').map(m => m.trim());
//         }
//         if (updates.languages && typeof updates.languages === 'string') {
//             updates.languages = updates.languages.split(',').map(l => l.trim());
//         }
//         if (updates.experience) {
//             updates.experience = Number(updates.experience);
//         }

//         const updatedUser = await User.findByIdAndUpdate(
//             userId,
//             updates,
//             { new: true, runValidators: true }
//         ).select("-password");

//         return res.status(200).json({
//             message: "Profile updated successfully",
//             success: true,
//             user: updatedUser.toJSON()
//         });

//     } catch (error) {
//         console.error("Update error:", error);
//         if (req.file) {
//             deleteLocalFile(saveLocalFile(req.file));
//         }
//         return res.status(500).json({
//             message: "Error in updating profile",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= LOGOUT =================
// export const logout = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;

//         if (!userId) {
//             return res.status(401).json({
//                 message: "User not authenticated",
//                 success: false
//             });
//         }

//         const refreshToken = req.cookies.refreshToken;

//         if (refreshToken) {
//             await Session.updateOne(
//                 { userId, refreshToken, isActive: true },
//                 { isActive: false }
//             );
//         } else {
//             await Session.updateMany(
//                 { userId, isActive: true },
//                 { isActive: false }
//             );
//         }

//         res.clearCookie("accessToken", {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict"
//         });
//         res.clearCookie("refreshToken", {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict"
//         });

//         return res.status(200).json({
//             message: "Logged out successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Logout error:", error);
//         return res.status(500).json({
//             message: "Error in logout",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET ALL USERS =================
// export const getAlluser = async (req, res) => {
//     try {
//         const users = await User.find().select("-password");
//         return res.status(200).json({
//             message: "Got all users",
//             success: true,
//             users,
//             count: users.length
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error in getting all users",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET SINGLE USER =================
// export const getUser = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const user = await User.findById(userId).select("-password");

//         if (!user) {
//             return res.status(404).json({
//                 success: false,
//                 message: "User not found"
//             });
//         }

//         return res.status(200).json({
//             message: "User data fetched successfully",
//             success: true,
//             user: user.toJSON()
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error in getting user data",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= DELETE USER =================
// export const deleteUser = async (req, res) => {
//     try {
//         const { id } = req.body;
//         const user = await User.findById(id);

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         if (user.profilePhoto) {
//             deleteLocalFile(user.profilePhoto);
//         }

//         await Session.deleteMany({ userId: id });
//         await User.findByIdAndDelete(id);

//         return res.status(200).json({
//             message: "User deleted successfully",
//             success: true
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error deleting user",
//             success: false,
//             error: error.message
//         });
//     }
// };

// controllers/authController.js
// import User from "../models/userModel.js";
// import bcrypt from "bcryptjs";
// import Session from "../models/sessionModel.js";
// import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";
// import otpService from "../services/otpService.js";
// import twilio from 'twilio';
// import crypto from 'crypto'; // Add this
// import { validationResult } from 'express-validator'; // Add this
// import { sendResetPasswordEmail } from '../utils/emailService.js';
// import jwt from 'jsonwebtoken';

// // import { sendResetPasswordEmail } from '../utils/emailService.js';
// // Initialize Twilio client
// const twilioClient = twilio(
//     process.env.TWILIO_ACCOUNT_SID,
//     process.env.TWILIO_AUTH_TOKEN
// );
// const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// // ================= TEMPORARY STORAGE =================
// const verifiedUsersStore = new Map();
// const emailOTPStore = new Map();
// const phoneOTPStore = new Map();

// // Clean up expired data every hour
// setInterval(() => {
//     const now = Date.now();
//     for (const [email, data] of verifiedUsersStore.entries()) {
//         if (data.expiresAt < now) {
//             verifiedUsersStore.delete(email);
//         }
//     }
//     for (const [email, data] of emailOTPStore.entries()) {
//         if (data.expiresAt < now) {
//             emailOTPStore.delete(email);
//         }
//     }
//     for (const [email, data] of phoneOTPStore.entries()) {
//         if (data.expiresAt < now) {
//             phoneOTPStore.delete(email);
//         }
//     }
// }, 60 * 60 * 1000);

// // ================= STEP 1: SEND EMAIL OTP =================
// export const sendEmailOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         // Check if user already exists
//         const existingUser = await User.findOne({ email });
//         if (existingUser) {
//             return res.status(409).json({
//                 message: "User already exists with this email",
//                 success: false
//             });
//         }

//         // Generate OTP
//         const otp = otpService.generateOTP();

//         // Send OTP via email
//         try {
//             await otpService.sendEmailOTP(email, otp, "User");

//             // Store OTP temporarily
//             emailOTPStore.set(email, {
//                 otp,
//                 expiresAt: Date.now() + 10 * 60 * 1000
//             });

//             console.log(`✅ Email OTP sent to ${email}: ${otp}`);

//             return res.status(200).json({
//                 message: "Email OTP sent successfully",
//                 success: true,
//                 email: email
//             });
//         } catch (sendError) {
//             console.error("OTP sending error:", sendError);
//             return res.status(500).json({
//                 message: "Failed to send OTP. Please try again.",
//                 success: false
//             });
//         }
//     } catch (error) {
//         console.error("Send email OTP error:", error);
//         return res.status(500).json({
//             message: "Error sending OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 2: VERIFY EMAIL OTP =================
// export const verifyEmailOTP = async (req, res) => {
//     try {
//         const { email, otp } = req.body;

//         console.log("=== verifyEmailOTP called ===");
//         console.log("Email:", email);
//         console.log("OTP:", otp);

//         if (!email || !otp) {
//             return res.status(400).json({
//                 message: "Email and OTP are required",
//                 success: false
//             });
//         }

//         const storedData = emailOTPStore.get(email);

//         if (!storedData) {
//             return res.status(400).json({
//                 message: "No OTP found. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (Date.now() > storedData.expiresAt) {
//             emailOTPStore.delete(email);
//             return res.status(400).json({
//                 message: "OTP has expired. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (storedData.otp !== otp) {
//             return res.status(400).json({
//                 message: "Invalid OTP",
//                 success: false
//             });
//         }

//         // OTP verified - store email verification status
//         let userVerification = verifiedUsersStore.get(email);
//         if (!userVerification) {
//             userVerification = {
//                 isEmailVerified: true,
//                 isPhoneVerified: false,
//                 expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour to complete phone verification
//             };
//         } else {
//             userVerification.isEmailVerified = true;
//         }

//         verifiedUsersStore.set(email, userVerification);

//         console.log(`✅ Email verified for: ${email}`);
//         console.log("Current verified users:", Array.from(verifiedUsersStore.entries()));

//         // Clean up email OTP
//         emailOTPStore.delete(email);

//         return res.status(200).json({
//             message: "Email verified successfully. Please verify your phone number next.",
//             success: true,
//             email: email,
//             nextStep: "phone_verification"
//         });

//     } catch (error) {
//         console.error("Verify email OTP error:", error);
//         return res.status(500).json({
//             message: "Error verifying OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 3: SEND PHONE OTP =================
// export const sendPhoneOTP = async (req, res) => {
//     try {
//         const { phoneNumber, email } = req.body;

//         console.log("=== sendPhoneOTP called ===");
//         console.log("Phone number:", phoneNumber);
//         console.log("Email from request:", email);

//         // Validate phone number
//         if (!phoneNumber) {
//             return res.status(400).json({
//                 message: "Phone number is required",
//                 success: false
//             });
//         }

//         // If email is not provided, try to find it
//         let userEmail = email;
//         let userVerification = null;

//         if (userEmail) {
//             // Email provided, use it directly
//             userVerification = verifiedUsersStore.get(userEmail);
//             console.log("Found verification by email:", userVerification);
//         } else {
//             // Email not provided, try to find pending verification
//             console.log("No email provided, searching for pending verification...");
//             for (const [email, data] of verifiedUsersStore.entries()) {
//                 if (data.isEmailVerified && !data.isPhoneVerified) {
//                     userEmail = email;
//                     userVerification = data;
//                     console.log("Found pending verification for:", email);
//                     break;
//                 }
//             }
//         }

//         if (!userVerification || !userVerification.isEmailVerified) {
//             console.log("No verification found!");
//             return res.status(400).json({
//                 message: "Please verify your email first. Request email OTP before phone verification.",
//                 success: false,
//                 requiresEmailFirst: true
//             });
//         }

//         // Clean phone number (remove non-digits)
//         const cleanedPhone = phoneNumber.replace(/\D/g, '');

//         if (cleanedPhone.length !== 10) {
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Check if phone already exists
//         const existingUser = await User.findOne({ phoneNumber: cleanedPhone });
//         if (existingUser) {
//             return res.status(409).json({
//                 message: "Phone number already registered",
//                 success: false
//             });
//         }

//         // Format to E.164 format (Indian numbers +91)
//         const formattedPhone = `+91${cleanedPhone}`;

//         // Generate OTP
//         const otp = otpService.generateOTP();

//         // Log OTP for debugging
//         console.log(`=================================`);
//         console.log(`📱 Sending Phone OTP`);
//         console.log(`📧 Email: ${userEmail}`);
//         console.log(`📱 Phone: ${formattedPhone}`);
//         console.log(`🔢 OTP: ${otp}`);
//         console.log(`=================================`);

//         // Send SMS via Twilio
//         try {
//             const message = await twilioClient.messages.create({
//                 body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
//                 from: TWILIO_PHONE_NUMBER,
//                 to: formattedPhone
//             });

//             console.log(`✅ Phone OTP sent successfully! SID: ${message.sid}`);

//             // Update verification store with phone number
//             userVerification.phoneNumber = cleanedPhone;
//             userVerification.formattedPhone = formattedPhone;
//             verifiedUsersStore.set(userEmail, userVerification);

//             // Store phone OTP
//             phoneOTPStore.set(userEmail, {
//                 otp,
//                 phoneNumber: cleanedPhone,
//                 formattedPhone,
//                 expiresAt: Date.now() + 10 * 60 * 1000
//             });

//             return res.status(200).json({
//                 message: "Phone OTP sent successfully via SMS",
//                 success: true,
//                 phoneNumber: cleanedPhone,
//                 email: userEmail
//             });
//         } catch (sendError) {
//             console.error("Phone OTP sending error:", sendError);

//             // Handle Twilio errors
//             if (sendError.code === 21211) {
//                 return res.status(400).json({
//                     message: "Invalid phone number format. Please check your phone number.",
//                     success: false,
//                     error: sendError.message
//                 });
//             } else if (sendError.message && sendError.message.includes("unverified")) {
//                 return res.status(400).json({
//                     message: "This phone number is not verified in your Twilio trial account. Please verify your phone number in Twilio console or upgrade your account.",
//                     success: false,
//                     error: sendError.message,
//                     twilioTrialMode: true
//                 });
//             }

//             return res.status(500).json({
//                 message: "Failed to send phone OTP. Please try again.",
//                 success: false,
//                 error: sendError.message
//             });
//         }
//     } catch (error) {
//         console.error("Send phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error sending phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 4: VERIFY PHONE OTP =================
// export const verifyPhoneOTP = async (req, res) => {
//     try {
//         const { phoneNumber, otp, email } = req.body; // Add email parameter

//         console.log("=== verifyPhoneOTP called ===");
//         console.log("Phone number:", phoneNumber);
//         console.log("Email:", email);
//         console.log("OTP:", otp);

//         if (!phoneNumber || !otp) {
//             return res.status(400).json({
//                 message: "Phone number and OTP are required",
//                 success: false
//             });
//         }

//         // Clean phone number
//         const cleanedPhone = phoneNumber.replace(/\D/g, '');

//         // Find which email has this phone number or use provided email
//         let foundEmail = email;
//         let storedData = null;

//         if (foundEmail) {
//             // If email provided, get OTP directly
//             storedData = phoneOTPStore.get(foundEmail);
//             if (storedData && storedData.phoneNumber !== cleanedPhone) {
//                 storedData = null;
//             }
//         }

//         // If not found by email, search all entries
//         if (!storedData) {
//             for (const [email, data] of phoneOTPStore.entries()) {
//                 if (data.phoneNumber === cleanedPhone && Date.now() <= data.expiresAt) {
//                     foundEmail = email;
//                     storedData = data;
//                     break;
//                 }
//             }
//         }

//         if (!storedData) {
//             return res.status(400).json({
//                 message: "No OTP found. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (Date.now() > storedData.expiresAt) {
//             phoneOTPStore.delete(foundEmail);
//             return res.status(400).json({
//                 message: "OTP has expired. Please request a new OTP.",
//                 success: false
//             });
//         }

//         if (storedData.otp !== otp) {
//             return res.status(400).json({
//                 message: "Invalid OTP",
//                 success: false
//             });
//         }

//         // Update verification status
//         const userVerification = verifiedUsersStore.get(foundEmail);
//         if (userVerification) {
//             userVerification.isPhoneVerified = true;
//             userVerification.phoneNumber = cleanedPhone;
//             userVerification.formattedPhone = storedData.formattedPhone;
//             verifiedUsersStore.set(foundEmail, userVerification);
//             console.log(`✅ Phone verified for: ${foundEmail}`);
//         } else {
//             console.log(`❌ No verification found for: ${foundEmail}`);
//             return res.status(400).json({
//                 message: "Verification session expired. Please start over.",
//                 success: false
//             });
//         }

//         // Clean up phone OTP
//         phoneOTPStore.delete(foundEmail);

//         return res.status(200).json({
//             message: "Phone verified successfully. You can now complete your registration.",
//             success: true,
//             email: foundEmail,
//             nextStep: "complete_registration"
//         });

//     } catch (error) {
//         console.error("Verify phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error verifying phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= STEP 5: COMPLETE REGISTRATION =================
// // controllers/authController.js - Update completeRegistration function

// export const completeRegistration = async (req, res) => {
//     try {
//         console.log("=== completeRegistration called ===");

//         const {
//             fullName,
//             email,
//             password,
//             age,
//             gender,
//             qualification,
//             specialization,
//             experience,
//             location,
//             consultationMode,
//             languages,
//             aboutMe
//         } = req.body;

//         // VALIDATE REQUIRED FIELDS
//         if (!fullName || !email || !password) {
//             return res.status(400).json({
//                 message: "Full name, email, and password are required",
//                 success: false,
//                 required: ["fullName", "email", "password"]
//             });
//         }

//         if (password.length < 6) {
//             return res.status(400).json({
//                 message: "Password must be at least 6 characters",
//                 success: false
//             });
//         }

//         // Check if user is verified
//         const userVerification = verifiedUsersStore.get(email);

//         if (!userVerification) {
//             return res.status(400).json({
//                 message: "No verification found. Please verify your email and phone first.",
//                 success: false,
//                 requiresVerification: true
//             });
//         }

//         if (!userVerification.isEmailVerified) {
//             return res.status(400).json({
//                 message: "Email not verified. Please verify your email first.",
//                 success: false,
//                 requiresEmailVerification: true
//             });
//         }

//         if (!userVerification.isPhoneVerified) {
//             return res.status(400).json({
//                 message: "Phone number not verified. Please verify your phone number first.",
//                 success: false,
//                 requiresPhoneVerification: true
//             });
//         }

//         // Check if user already exists
//         const existingUser = await User.findOne({
//             $or: [{ email }, { phoneNumber: userVerification.phoneNumber }]
//         });

//         if (existingUser) {
//             verifiedUsersStore.delete(email);
//             return res.status(409).json({
//                 message: "User already exists with this email or phone number",
//                 success: false
//             });
//         }

//         // AUTO-DETECT ROLE
//         const hasQualification = qualification && qualification.toString().trim() !== "";
//         const hasSpecialization = specialization && specialization.toString().trim() !== "";
//         const hasExperience = experience && experience.toString().trim() !== "";
//         const hasLocation = location && location.toString().trim() !== "";

//         const hasCounsellorFields = hasQualification && hasSpecialization && hasExperience && hasLocation;
//         const role = hasCounsellorFields ? "counsellor" : "user";

//         // Hash password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Prepare user data
//         const userData = {
//             fullName,
//             email,
//             phoneNumber: userVerification.phoneNumber,
//             password: hashedPassword,
//             age: age || null,
//             gender: gender || "male",
//             role,
//             profileCompleted: true,
//             isEmailVerified: true,
//             isActive: true
//         };

//         // Add counsellor-specific fields
//         if (role === "counsellor") {
//             userData.qualification = qualification.toString().trim();
//             userData.specialization = typeof specialization === 'string'
//                 ? specialization.split(',').map(s => s.trim()).filter(s => s !== "")
//                 : specialization || [];
//             userData.experience = Number(experience);
//             userData.location = location.toString().trim();
//             userData.consultationMode = typeof consultationMode === 'string'
//                 ? consultationMode.split(',').map(m => m.trim()).filter(m => m !== "")
//                 : consultationMode || ["online"];
//             userData.languages = typeof languages === 'string'
//                 ? languages.split(',').map(l => l.trim()).filter(l => l !== "")
//                 : languages || [];
//             userData.aboutMe = aboutMe || "";

//             if (req.file) {
//                 userData.profilePhoto = saveLocalFile(req.file);
//             }
//         }

//         // Create user
//         const newUser = await User.create(userData);
//         console.log(`✅ User created successfully with role: ${newUser.role}`);

//         // Clean up verification data
//         verifiedUsersStore.delete(email);
//         emailOTPStore.delete(email);
//         phoneOTPStore.delete(email);

//         // 🔥 LIFETIME TOKEN: Generate tokens
//         const accessToken = generateAccessToken(newUser._id);
//         const refreshToken = generateRefreshToken(newUser._id); // NO EXPIRY

//         // 🔥 Create session with NO expiry date
//         await Session.create({
//             userId: newUser._id,
//             refreshToken,
//             isActive: true,
//             createdAt: new Date()
//             // NO expiresAt field - token lives forever
//         });

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000 // 15 minutes
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days (but effectively lifetime)
//         });

//         return res.status(201).json({
//             message: "Registration completed successfully!",
//             success: true,
//             user: newUser.toJSON(),
//             accessToken,
//             refreshToken,
//             role: newUser.role
//         });

//     } catch (error) {
//         console.error("Complete registration error:", error);
//         if (req.file) {
//             deleteLocalFile(saveLocalFile(req.file));
//         }
//         return res.status(500).json({
//             message: "Error completing registration",
//             success: false,
//             error: error.message
//         });
//     }
// };
// // export const completeRegistration = async (req, res) => {
// //     try {
// //         console.log("=== completeRegistration called ===");

// //         const {
// //             fullName,
// //             email,
// //             password,
// //             age,
// //             gender,
// //             // Counsellor fields
// //             qualification,
// //             specialization,
// //             experience,
// //             location,
// //             consultationMode,
// //             languages,
// //             aboutMe
// //         } = req.body;

// //         console.log("Email:", email);
// //         console.log("Full Name:", fullName);
// //         console.log("Qualification:", qualification);
// //         console.log("Specialization:", specialization);
// //         console.log("Experience:", experience);
// //         console.log("Location:", location);

// //         // VALIDATE REQUIRED FIELDS
// //         if (!fullName || !email || !password) {
// //             return res.status(400).json({
// //                 message: "Full name, email, and password are required",
// //                 success: false,
// //                 required: ["fullName", "email", "password"]
// //             });
// //         }

// //         if (password.length < 6) {
// //             return res.status(400).json({
// //                 message: "Password must be at least 6 characters",
// //                 success: false
// //             });
// //         }

// //         // Check if user is verified
// //         const userVerification = verifiedUsersStore.get(email);

// //         console.log("User verification found:", userVerification);

// //         if (!userVerification) {
// //             return res.status(400).json({
// //                 message: "No verification found. Please verify your email and phone first.",
// //                 success: false,
// //                 requiresVerification: true,
// //                 steps: {
// //                     emailVerified: false,
// //                     phoneVerified: false
// //                 }
// //             });
// //         }

// //         if (!userVerification.isEmailVerified) {
// //             return res.status(400).json({
// //                 message: "Email not verified. Please verify your email first.",
// //                 success: false,
// //                 requiresEmailVerification: true
// //             });
// //         }

// //         if (!userVerification.isPhoneVerified) {
// //             return res.status(400).json({
// //                 message: "Phone number not verified. Please verify your phone number first.",
// //                 success: false,
// //                 requiresPhoneVerification: true
// //             });
// //         }

// //         // Check if phone number exists in verification
// //         if (!userVerification.phoneNumber) {
// //             return res.status(400).json({
// //                 message: "Phone number not found. Please verify your phone number again.",
// //                 success: false
// //             });
// //         }

// //         // Check if user already exists
// //         const existingUser = await User.findOne({
// //             $or: [{ email }, { phoneNumber: userVerification.phoneNumber }]
// //         });

// //         if (existingUser) {
// //             verifiedUsersStore.delete(email);
// //             return res.status(409).json({
// //                 message: "User already exists with this email or phone number",
// //                 success: false
// //             });
// //         }

// //         // AUTO-DETECT ROLE - Check if fields are provided and not empty
// //         const hasQualification = qualification && qualification.toString().trim() !== "";
// //         const hasSpecialization = specialization && specialization.toString().trim() !== "";
// //         const hasExperience = experience && experience.toString().trim() !== "";
// //         const hasLocation = location && location.toString().trim() !== "";

// //         const hasCounsellorFields = hasQualification && hasSpecialization && hasExperience && hasLocation;
// //         const role = hasCounsellorFields ? "counsellor" : "user";

// //         console.log("Role detected:", role);
// //         console.log("Has counsellor fields:", hasCounsellorFields);

// //         // Validate counsellor required fields if role is counsellor
// //         if (role === "counsellor") {
// //             const missingFields = [];
// //             if (!hasQualification) missingFields.push("qualification");
// //             if (!hasSpecialization) missingFields.push("specialization");
// //             if (!hasExperience) missingFields.push("experience");
// //             if (!hasLocation) missingFields.push("location");

// //             if (missingFields.length > 0) {
// //                 return res.status(400).json({
// //                     message: `Counsellor requires: ${missingFields.join(", ")}`,
// //                     success: false,
// //                     required: missingFields
// //                 });
// //             }
// //         }

// //         // Hash password
// //         const hashedPassword = await bcrypt.hash(password, 10);

// //         // Prepare user data
// //         const userData = {
// //             fullName,
// //             email,
// //             phoneNumber: userVerification.phoneNumber,
// //             password: hashedPassword,
// //             age: age || null,
// //             gender: gender || "male",
// //             role,
// //             profileCompleted: true,
// //             isEmailVerified: true,
// //             isActive: true
// //         };

// //         // Add counsellor-specific fields if role is counsellor
// //         if (role === "counsellor") {
// //             userData.qualification = qualification.toString().trim();
// //             userData.specialization = typeof specialization === 'string'
// //                 ? specialization.split(',').map(s => s.trim()).filter(s => s !== "")
// //                 : specialization || [];
// //             userData.experience = Number(experience);
// //             userData.location = location.toString().trim();
// //             userData.consultationMode = typeof consultationMode === 'string'
// //                 ? consultationMode.split(',').map(m => m.trim()).filter(m => m !== "")
// //                 : consultationMode || ["online"];
// //             userData.languages = typeof languages === 'string'
// //                 ? languages.split(',').map(l => l.trim()).filter(l => l !== "")
// //                 : languages || [];
// //             userData.aboutMe = aboutMe || "";

// //             // Handle profile photo if uploaded
// //             if (req.file) {
// //                 userData.profilePhoto = saveLocalFile(req.file);
// //             }
// //         } else {
// //             // For users, allow optional fields
// //             if (specialization && specialization.toString().trim() !== "") {
// //                 userData.specialization = typeof specialization === 'string'
// //                     ? specialization.split(',').map(s => s.trim()).filter(s => s !== "")
// //                     : specialization;
// //             }
// //             if (languages && languages.toString().trim() !== "") {
// //                 userData.languages = typeof languages === 'string'
// //                     ? languages.split(',').map(l => l.trim()).filter(l => l !== "")
// //                     : languages || [];
// //             }
// //             if (consultationMode && consultationMode.toString().trim() !== "") {
// //                 userData.consultationMode = typeof consultationMode === 'string'
// //                     ? consultationMode.split(',').map(m => m.trim()).filter(m => m !== "")
// //                     : consultationMode || ["online"];
// //             }
// //         }

// //         // Create user
// //         const newUser = await User.create(userData);
// //         console.log(`✅ User created successfully with role: ${newUser.role}`);

// //         // Clean up verification data
// //         verifiedUsersStore.delete(email);

// //         // Clean up any remaining OTPs
// //         emailOTPStore.delete(email);
// //         phoneOTPStore.delete(email);

// //         // Auto-login after registration
// //         const accessToken = generateAccessToken(newUser._id);
// //         const refreshToken = generateRefreshToken(newUser._id);

// //         await Session.create({
// //             userId: newUser._id,
// //             refreshToken,
// //             isActive: true
// //         });

// //         // Set cookies
// //         res.cookie("accessToken", accessToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 15 * 60 * 1000
// //         });
// //         res.cookie("refreshToken", refreshToken, {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict",
// //             maxAge: 7 * 24 * 60 * 60 * 1000
// //         });

// //         return res.status(201).json({
// //             message: "Registration completed successfully!",
// //             success: true,
// //             user: newUser.toJSON(),
// //             accessToken,
// //             refreshToken,
// //             role: newUser.role
// //         });

// //     } catch (error) {
// //         console.error("Complete registration error:", error);
// //         if (req.file) {
// //             deleteLocalFile(saveLocalFile(req.file));
// //         }
// //         return res.status(500).json({
// //             message: "Error completing registration",
// //             success: false,
// //             error: error.message,
// //             stack: process.env.NODE_ENV === "development" ? error.stack : undefined
// //         });
// //     }
// // };

// // ================= RESEND OTP ENDPOINTS =================
// export const resendEmailOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const userVerification = verifiedUsersStore.get(email);
//         if (!userVerification) {
//             return res.status(404).json({
//                 message: "No pending verification found",
//                 success: false
//             });
//         }

//         const otp = otpService.generateOTP();

//         await otpService.sendEmailOTP(email, otp, "User");

//         emailOTPStore.set(email, {
//             otp,
//             expiresAt: Date.now() + 10 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Email OTP resent successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Resend email OTP error:", error);
//         return res.status(500).json({
//             message: "Error resending OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// export const resendPhoneOTP = async (req, res) => {
//     try {
//         const { email } = req.body;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const userVerification = verifiedUsersStore.get(email);
//         if (!userVerification || !userVerification.phoneNumber) {
//             return res.status(404).json({
//                 message: "No phone number found for verification",
//                 success: false
//             });
//         }

//         const otp = otpService.generateOTP();

//         let formattedPhone = userVerification.phoneNumber;
//         if (!formattedPhone.startsWith('+')) {
//             formattedPhone = `+91${formattedPhone}`;
//         }

//         await twilioClient.messages.create({
//             body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
//             from: TWILIO_PHONE_NUMBER,
//             to: formattedPhone
//         });

//         phoneOTPStore.set(email, {
//             otp,
//             phoneNumber: userVerification.phoneNumber,
//             formattedPhone,
//             expiresAt: Date.now() + 10 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Phone OTP resent successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Resend phone OTP error:", error);
//         return res.status(500).json({
//             message: "Error resending phone OTP",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= CHECK REGISTRATION STATUS =================
// export const checkRegistrationStatus = async (req, res) => {
//     try {
//         const { email } = req.params;

//         if (!email) {
//             return res.status(400).json({
//                 message: "Email is required",
//                 success: false
//             });
//         }

//         const userVerification = verifiedUsersStore.get(email);

//         if (!userVerification) {
//             return res.status(404).json({
//                 message: "No active registration session found",
//                 success: false,
//                 exists: false
//             });
//         }

//         const timeRemaining = Math.max(0, Math.floor((userVerification.expiresAt - Date.now()) / 1000));

//         return res.status(200).json({
//             success: true,
//             exists: true,
//             email: email,
//             isEmailVerified: userVerification.isEmailVerified,
//             isPhoneVerified: userVerification.isPhoneVerified,
//             hasPhoneNumber: !!userVerification.phoneNumber,
//             expiresIn: timeRemaining,
//             expiresAt: userVerification.expiresAt
//         });

//     } catch (error) {
//         console.error("Check status error:", error);
//         return res.status(500).json({
//             message: "Error checking registration status",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= DEPRECATED FUNCTIONS =================
// export const registerUserOnly = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use the new registration flow",
//         success: false,
//         instructions: {
//             step1: "POST /api/auth/send-email-otp with email",
//             step2: "POST /api/auth/verify-email-otp with email and otp",
//             step3: "POST /api/auth/send-phone-otp with phoneNumber and email",
//             step4: "POST /api/auth/verify-phone-otp with phoneNumber and otp",
//             step5: "POST /api/auth/complete-registration with full details"
//         }
//     });
// };

// export const registerCounsellor = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use the new registration flow",
//         success: false,
//         instructions: {
//             step1: "POST /api/auth/send-email-otp with email",
//             step2: "POST /api/auth/verify-email-otp with email and otp",
//             step3: "POST /api/auth/send-phone-otp with phoneNumber and email",
//             step4: "POST /api/auth/verify-phone-otp with phoneNumber and otp",
//             step5: "POST /api/auth/complete-registration with full details including counsellor fields"
//         }
//     });
// };

// export const resendOTPS = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use specific resend endpoints: /api/auth/resend-email-otp or /api/auth/resend-phone-otp",
//         success: false
//     });
// };

// export const checkVerificationStatus = async (req, res) => {
//     return res.status(400).json({
//         message: "Please use GET /api/auth/registration-status/:email",
//         success: false
//     });
// };

// // ================= LOGIN USER =================
// // controllers/authController.js - Update loginUser function

// export const loginUser = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({
//                 message: "Email and password are required",
//                 success: false
//             });
//         }

//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         if (!user.isActive) {
//             return res.status(401).json({
//                 message: "Account is deactivated. Please contact support.",
//                 success: false
//             });
//         }

//         const match = await bcrypt.compare(password, user.password);

//         if (!match) {
//             return res.status(401).json({
//                 message: "Invalid password",
//                 success: false
//             });
//         }

//         // 🔥 REMOVE the active session check - allow multiple logins
//         // Just create new session instead of blocking

//         const accessToken = generateAccessToken(user._id);
//         const refreshToken = generateRefreshToken(user._id); // NO EXPIRY

//         // 🔥 Create session with NO expiry
//         await Session.create({
//             userId: user._id,
//             refreshToken,
//             isActive: true,
//             createdAt: new Date()
//             // NO expiresAt field
//         });

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000 // 15 minutes
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
//         });

//         return res.status(200).json({
//             message: "Login successful",
//             success: true,
//             accessToken,
//             refreshToken,
//             user: user.toJSON(),
//             role: user.role
//         });

//     } catch (error) {
//         console.log("Login error:", error);
//         return res.status(500).json({
//             message: "Error in login",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // export const loginUser = async (req, res) => {
// //     try {
// //         const { email, password } = req.body;

// //         if (!email || !password) {
// //             return res.status(400).json({
// //                 message: "Email and password are required",
// //                 success: false
// //             });
// //         }

// //         const user = await User.findOne({ email });

// //         if (!user) {
// //             return res.status(404).json({
// //                 message: "User not found",
// //                 success: false
// //             });
// //         }

// //         if (!user.isActive) {
// //             return res.status(401).json({
// //                 message: "Account is deactivated. Please contact support.",
// //                 success: false
// //             });
// //         }

// //         const match = await bcrypt.compare(password, user.password);

// //         if (!match) {
// //             return res.status(401).json({
// //                 message: "Invalid password",
// //                 success: false
// //             });
// //         }

// //         const activeSession = await Session.findOne({
// //             userId: user._id,
// //             isActive: true
// //         });

// //         if (activeSession) {
// //             return res.status(400).json({
// //                 message: "User already logged in. Please use OTP login",
// //                 success: false
// //             });
// //         }
// //            const accessToken = generateAccessToken(user._id);
// //     const refreshToken = generateRefreshToken(user._id);

// //     // Create session
// //     await Session.create({
// //       userId: user._id,
// //       refreshToken,
// //       isActive: true,
// //       createdAt: new Date(),
// //       expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
// //     });

// //     // Set cookies
// //     res.cookie("accessToken", accessToken, {
// //       httpOnly: true,
// //       secure: process.env.NODE_ENV === "production",
// //       sameSite: "strict",
// //       maxAge: 1 * 24 * 60 * 60 * 1000 // 15 minutes
// //     });

// //     res.cookie("refreshToken", refreshToken, {
// //       httpOnly: true,
// //       secure: process.env.NODE_ENV === "production",
// //       sameSite: "strict",
// //       maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
// //     });

// //         // const accessToken = generateAccessToken(user._id);
// //         // const refreshToken = generateRefreshToken(user._id);

// //         // await Session.create({
// //         //     userId: user._id,
// //         //     refreshToken,
// //         //     isActive: true
// //         // });

// //         // res.cookie("accessToken", accessToken, {
// //         //     httpOnly: true,
// //         //     secure: process.env.NODE_ENV === "production",
// //         //     sameSite: "strict",
// //         //     maxAge: 15 * 60 * 1000
// //         // });
// //         // res.cookie("refreshToken", refreshToken, {
// //         //     httpOnly: true,
// //         //     secure: process.env.NODE_ENV === "production",
// //         //     sameSite: "strict",
// //         //     maxAge: 7 * 24 * 60 * 60 * 1000
// //         // });

// //         return res.status(200).json({
// //             message: "Login successful",
// //             success: true,
// //             accessToken,
// //             refreshToken,
// //             user: user.toJSON(),
// //             role: user.role
// //         });

// //     } catch (error) {
// //         console.log("Login error:", error);
// //         return res.status(500).json({
// //             message: "Error in login",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };

// // ================= GET ALL COUNSELLORS =================
// export const getAllCounsellors = async (req, res) => {
//     try {
//         const { specialization, location, consultationMode, minExperience } = req.query;

//         let filter = {
//             role: "counsellor",
//             isActive: true,
//             profileCompleted: true
//         };

//         if (specialization) {
//             filter.specialization = { $in: [specialization] };
//         }

//         if (location) {
//             filter.location = { $regex: location, $options: 'i' };
//         }

//         if (consultationMode) {
//             filter.consultationMode = { $in: [consultationMode] };
//         }

//         if (minExperience) {
//             filter.experience = { $gte: Number(minExperience) };
//         }

//         const counsellors = await User.find(filter)
//             .select("-password")
//             .sort({ createdAt: -1 });

//         return res.status(200).json({
//             message: "Counsellors fetched successfully",
//             success: true,
//             counsellors,
//             count: counsellors.length
//         });

//     } catch (error) {
//         console.log("Get counsellors error:", error);
//         return res.status(500).json({
//             message: "Error in fetching counsellors",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET SINGLE COUNSELLOR =================
// export const getCounsellorById = async (req, res) => {
//     try {
//         const { counsellorId } = req.params;

//         if (!counsellorId) {
//             return res.status(400).json({
//                 message: "Counsellor ID is required",
//                 success: false
//             });
//         }

//         const counsellor = await User.findOne({
//             _id: counsellorId,
//             role: "counsellor",
//             isActive: true
//         }).select("-password");

//         if (!counsellor) {
//             return res.status(404).json({
//                 message: "Counsellor not found",
//                 success: false
//             });
//         }

//         return res.status(200).json({
//             message: "Counsellor fetched successfully",
//             success: true,
//             counsellor: counsellor.toJSON()
//         });

//     } catch (error) {
//         console.log("Get counsellor error:", error);
//         return res.status(500).json({
//             message: "Error in fetching counsellor",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET CURRENT USER PROFILE =================
// export const getMyProfile = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;

//         if (!userId) {
//             return res.status(401).json({
//                 message: "Authentication required",
//                 success: false
//             });
//         }

//         const user = await User.findById(userId).select("-password");

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         return res.status(200).json({
//             message: "Profile fetched successfully",
//             success: true,
//             user: user.toJSON()
//         });

//     } catch (error) {
//         console.log("Get profile error:", error);
//         return res.status(500).json({
//             message: "Error in fetching profile",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= UPDATE USER =================
// export const updateUser = async (req, res) => {
//     try {
//         if (!req.userId && !req.user) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(401).json({
//                 message: "Authentication required",
//                 success: false
//             });
//         }

//         const userId = req.user?._id || req.userId;
//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         let allowedUpdates = [
//             'fullName',
//             'anonymous',
//             'phoneNumber',
//             'age',
//             'gender',
//         ];

//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push(
//                 'qualification',
//                 'specialization',
//                 'experience',
//                 'location',
//                 'consultationMode',
//                 'languages',
//                 'aboutMe'
//             );
//         }

//         const updates = {};
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") {
//                 updates[field] = req.body[field];
//             }
//         });

//         // Handle profile photo - ONLY for counsellors
//         if (req.file) {
//             if (currentUser.role !== "counsellor") {
//                 deleteLocalFile(saveLocalFile(req.file));
//                 return res.status(403).json({
//                     message: "Only counsellors can upload profile photos",
//                     success: false
//                 });
//             }

//             if (currentUser.profilePhoto) {
//                 deleteLocalFile(currentUser.profilePhoto);
//             }
//             const newPhotoUrl = saveLocalFile(req.file);
//             updates.profilePhoto = newPhotoUrl;
//         }

//         if (Object.keys(updates).length === 0 && !req.file) {
//             return res.status(400).json({
//                 message: "No valid fields to update",
//                 success: false
//             });
//         }

//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             if (req.file) {
//                 deleteLocalFile(saveLocalFile(req.file));
//             }
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Convert arrays
//         if (updates.specialization && typeof updates.specialization === 'string') {
//             updates.specialization = updates.specialization.split(',').map(s => s.trim());
//         }
//         if (updates.consultationMode && typeof updates.consultationMode === 'string') {
//             updates.consultationMode = updates.consultationMode.split(',').map(m => m.trim());
//         }
//         if (updates.languages && typeof updates.languages === 'string') {
//             updates.languages = updates.languages.split(',').map(l => l.trim());
//         }
//         if (updates.experience) {
//             updates.experience = Number(updates.experience);
//         }

//         const updatedUser = await User.findByIdAndUpdate(
//             userId,
//             updates,
//             { new: true, runValidators: true }
//         ).select("-password");

//         return res.status(200).json({
//             message: "Profile updated successfully",
//             success: true,
//             user: updatedUser.toJSON()
//         });

//     } catch (error) {
//         console.error("Update error:", error);
//         if (req.file) {
//             deleteLocalFile(saveLocalFile(req.file));
//         }
//         return res.status(500).json({
//             message: "Error in updating profile",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= LOGOUT =================
// // export const logout = async (req, res) => {
// //     try {
// //         const userId = req.userId || req.user?._id;

// //         if (!userId) {
// //             return res.status(401).json({
// //                 message: "User not authenticated",
// //                 success: false
// //             });
// //         }

// //         const refreshToken = req.cookies.refreshToken;

// //         if (refreshToken) {
// //             await Session.updateOne(
// //                 { userId, refreshToken, isActive: true },
// //                 { isActive: false }
// //             );
// //         } else {
// //             await Session.updateMany(
// //                 { userId, isActive: true },
// //                 { isActive: false }
// //             );
// //         }

// //         res.clearCookie("accessToken", {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict"
// //         });
// //         res.clearCookie("refreshToken", {
// //             httpOnly: true,
// //             secure: process.env.NODE_ENV === "production",
// //             sameSite: "strict"
// //         });

// //         return res.status(200).json({
// //             message: "Logged out successfully",
// //             success: true
// //         });

// //     } catch (error) {
// //         console.error("Logout error:", error);
// //         return res.status(500).json({
// //             message: "Error in logout",
// //             success: false,
// //             error: error.message
// //         });
// //     }
// // };
// //add timing token for logout
// export const logout = async (req, res) => {
//     try {
//         // Get userId from request (set by auth middleware)
//         let userId = req.userId || req.user?._id;
//         const refreshToken = req.cookies?.refreshToken;

//         console.log("🔓 Logout - UserId from request:", userId);
//         console.log("🔓 Logout - Refresh token present:", !!refreshToken);

//         // If still no userId but we have refresh token, try to decode it
//         if (!userId && refreshToken) {
//             try {
//                 const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
//                 userId = decoded.userId;
//                 console.log("✅ Got userId from refresh token in logout function:", userId);
//             } catch (error) {
//                 console.log("⚠️ Could not decode refresh token:", error.message);
//             }
//         }

//         // Invalidate session if we have userId
//         if (userId) {
//             if (refreshToken) {
//                 // Try to invalidate specific session
//                 const result = await Session.updateOne(
//                     { userId, refreshToken, isActive: true },
//                     { isActive: false, logoutAt: new Date() }
//                 );

//                 if (result.modifiedCount === 0) {
//                     // If no specific session found, invalidate all active sessions
//                     const allResult = await Session.updateMany(
//                         { userId, isActive: true },
//                         { isActive: false, logoutAt: new Date() }
//                     );
//                     console.log(`✅ All sessions invalidated for user: ${userId} (${allResult.modifiedCount} sessions)`);
//                 } else {
//                     console.log(`✅ Specific session invalidated for user: ${userId}`);
//                 }
//             } else {
//                 // No refresh token, invalidate all active sessions
//                 const result = await Session.updateMany(
//                     { userId, isActive: true },
//                     { isActive: false, logoutAt: new Date() }
//                 );
//                 console.log(`✅ All sessions invalidated for user: ${userId} (${result.modifiedCount} sessions)`);
//             }
//         } else {
//             console.log("⚠️ No userId found, skipping session invalidation");
//         }

//         // Always clear cookies
//         const cookieOptions = {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             path: "/"
//         };

//         res.clearCookie("accessToken", cookieOptions);
//         res.clearCookie("refreshToken", cookieOptions);

//         console.log("✅ Cookies cleared successfully");

//         return res.status(200).json({
//             message: "Logged out successfully",
//             success: true
//         });

//     } catch (error) {
//         console.error("Logout error:", error);

//         // Even on error, try to clear cookies
//         try {
//             res.clearCookie("accessToken", { path: "/" });
//             res.clearCookie("refreshToken", { path: "/" });
//         } catch (cookieError) {
//             console.error("Error clearing cookies:", cookieError);
//         }

//         return res.status(500).json({
//             message: "Error in logout",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET ALL USERS =================
// export const getAlluser = async (req, res) => {
//     try {
//         const users = await User.find().select("-password");
//         return res.status(200).json({
//             message: "Got all users",
//             success: true,
//             users,
//             count: users.length
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error in getting all users",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= GET SINGLE USER =================
// export const getUser = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const user = await User.findById(userId).select("-password");

//         if (!user) {
//             return res.status(404).json({
//                 success: false,
//                 message: "User not found"
//             });
//         }

//         return res.status(200).json({
//             message: "User data fetched successfully",
//             success: true,
//             user: user.toJSON()
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error in getting user data",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= DELETE USER =================
// export const deleteUser = async (req, res) => {
//     try {
//         const { id } = req.body;
//         const user = await User.findById(id);

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         if (user.profilePhoto) {
//             deleteLocalFile(user.profilePhoto);
//         }

//         await Session.deleteMany({ userId: id });
//         await User.findByIdAndDelete(id);

//         return res.status(200).json({
//             message: "User deleted successfully",
//             success: true
//         });
//     } catch (error) {
//         return res.status(500).json({
//             message: "Error deleting user",
//             success: false,
//             error: error.message
//         });
//     }
// };

// // ================= FORGOT PASSWORD =================
// // In your forgotPassword function
// export const forgotPassword = async (req, res) => {
//     try {
//         const errors = validationResult(req);
//         if (!errors.isEmpty()) {
//             return res.status(400).json({
//                 success: false,
//                 errors: errors.array(),
//             });
//         }

//         const { email } = req.body;
//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({
//                 success: false,
//                 message: "No account found with this email",
//             });
//         }

//         // Generate reset token
//         const resetToken = crypto.randomBytes(32).toString("hex");

//         // Hash token and save to database
//         user.resetPasswordToken = crypto
//             .createHash("sha256")
//             .update(resetToken)
//             .digest("hex");

//         user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

//         await user.save();

//         // FIX: Create proper URL for mobile
//         // Get the origin (domain) from the request
//         const origin = req.headers.origin || req.headers.referer || `${req.protocol}://${req.get("host")}`;

//         // For mobile app, you might want to use a deep link
//         // Option 1: Web URL (works in mobile browser)
//         const resetUrl = `${origin}/reset-password/${resetToken}`;

//         // Option 2: If you have a mobile app, use deep linking
//         // const resetUrl = `yourapp://reset-password?token=${resetToken}`;

//         console.log("Reset URL:", resetUrl); // Log to verify URL

//         try {
//             await sendResetPasswordEmail(user.email, resetUrl, user.fullName);
//         } catch (emailError) {
//             console.error("Email sending failed:", emailError);
//             user.resetPasswordToken = undefined;
//             user.resetPasswordExpire = undefined;
//             await user.save();

//             return res.status(500).json({
//                 success: false,
//                 message: "Error sending reset email. Please try again.",
//             });
//         }

//         res.status(200).json({
//             success: true,
//             message: "Password reset instructions sent to your email",
//         });
//     } catch (error) {
//         console.error("Forgot password error:", error);
//         res.status(500).json({
//             success: false,
//             message: "Error processing request",
//             error: process.env.NODE_ENV === "development" ? error.message : undefined,
//         });
//     }
// };
// // export const forgotPassword = async (req, res) => {
// //     try {
// //         const errors = validationResult(req);
// //         if (!errors.isEmpty()) {
// //             return res.status(400).json({
// //                 success: false,
// //                 errors: errors.array(),
// //             });
// //         }

// //         const { email } = req.body;

// //         // Fix: Use User model instead of Counsellor
// //         const user = await User.findOne({ email });

// //         if (!user) {
// //             return res.status(404).json({
// //                 success: false,
// //                 message: "No account found with this email",
// //             });
// //         }

// //         // Generate reset token
// //         const resetToken = crypto.randomBytes(32).toString("hex");

// //         // Hash token and save to database
// //         user.resetPasswordToken = crypto
// //             .createHash("sha256")
// //             .update(resetToken)
// //             .digest("hex");

// //         user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

// //         await user.save();

// //         // Send email with reset token
// //         const resetUrl = `${req.protocol}://${req.get("host")}/reset-password/${resetToken}`;

// //         try {
// //             // Fix: Pass correct parameters (email, resetUrl, userName)
// //             await sendResetPasswordEmail(user.email, resetUrl, user.fullName);
// //         } catch (emailError) {
// //             console.error("Email sending failed:", emailError);
// //             // Clear reset token if email fails
// //             user.resetPasswordToken = undefined;
// //             user.resetPasswordExpire = undefined;
// //             await user.save();

// //             return res.status(500).json({
// //                 success: false,
// //                 message: "Error sending reset email. Please try again.",
// //             });
// //         }

// //         res.status(200).json({
// //             success: true,
// //             message: "Password reset instructions sent to your email",
// //         });
// //     } catch (error) {
// //         console.error("Forgot password error:", error);
// //         res.status(500).json({
// //             success: false,
// //             message: "Error processing request",
// //             error: process.env.NODE_ENV === "development" ? error.message : undefined,
// //         });
// //     }
// // };

// // ================= RESET PASSWORD =================
// export const resetPassword = async (req, res) => {
//     try {
//         const { token } = req.params;
//         const { password, confirmPassword } = req.body;

//         // Check if passwords match
//         if (password !== confirmPassword) {
//             return res.status(400).json({
//                 success: false,
//                 message: "Passwords do not match",
//             });
//         }

//         // Validate password strength
//         if (password.length < 6) { // Changed from 8 to 6 to match your registration requirement
//             return res.status(400).json({
//                 success: false,
//                 message: "Password must be at least 6 characters long",
//             });
//         }

//         // Hash the token from URL
//         const resetPasswordToken = crypto
//             .createHash("sha256")
//             .update(token)
//             .digest("hex");

//         // Fix: Use User model instead of Counsellor
//         const user = await User.findOne({
//             resetPasswordToken,
//             resetPasswordExpire: { $gt: Date.now() },
//         });

//         if (!user) {
//             return res.status(400).json({
//                 success: false,
//                 message: "Invalid or expired reset token",
//             });
//         }

//         // Check if new password is same as old password
//         const isSamePassword = await bcrypt.compare(password, user.password);
//         if (isSamePassword) {
//             return res.status(400).json({
//                 success: false,
//                 message: "New password cannot be the same as old password",
//             });
//         }

//         // Update password
//         const hashedPassword = await bcrypt.hash(password, 10);
//         user.password = hashedPassword;
//         user.resetPasswordToken = undefined;
//         user.resetPasswordExpire = undefined;

//         await user.save();

//         // Fix: Use Session model instead of SessionCounselor
//         await Session.updateMany(
//             { userId: user._id, isActive: true },
//             { isActive: false, logoutAt: new Date() }
//         );

//         res.status(200).json({
//             success: true,
//             message: "Password reset successful. Please login with your new password.",
//         });
//     } catch (error) {
//         console.error("Reset password error:", error);
//         res.status(500).json({
//             success: false,
//             message: "Error resetting password",
//             error: process.env.NODE_ENV === "development" ? error.message : undefined,
//         });
//     }
// };

// // controllers/authController.js
// // Add this function after your login function

// // export const refreshAccessToken = async (req, res) => {
// //   try {
// //     const refreshToken = req.cookies?.refreshToken;

// //     if (!refreshToken) {
// //       return res.status(401).json({
// //         success: false,
// //         message: "No refresh token provided"
// //       });
// //     }

// //     // Verify refresh token
// //     let decoded;
// //     try {
// //       decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
// //     } catch (error) {
// //       return res.status(401).json({
// //         success: false,
// //         message: "Invalid or expired refresh token"
// //       });
// //     }

// //     // Check if session exists
// //     const session = await Session.findOne({
// //       userId: decoded.userId,
// //       refreshToken: refreshToken,
// //       isActive: true
// //     });

// //     if (!session) {
// //       return res.status(401).json({
// //         success: false,
// //         message: "Session not found or expired"
// //       });
// //     }

// //     // Check if user exists
// //     const user = await User.findById(decoded.userId);
// //     if (!user || !user.isActive) {
// //       return res.status(401).json({
// //         success: false,
// //         message: "User not found or deactivated"
// //       });
// //     }

// //     // Generate new access token
// //     const newAccessToken = generateAccessToken(user._id);

// //     // Set new access token in cookie
// //     res.cookie("accessToken", newAccessToken, {
// //       httpOnly: true,
// //       secure: process.env.NODE_ENV === "production",
// //       sameSite: "strict",
// //       maxAge: 15 * 60 * 1000 // 15 minutes
// //     });

// //     return res.status(200).json({
// //       success: true,
// //       message: "Token refreshed successfully",
// //       accessToken: newAccessToken
// //     });

// //   } catch (error) {
// //     console.error("Refresh token error:", error);
// //     return res.status(500).json({
// //       success: false,
// //       message: "Error refreshing token",
// //       error: error.message
// //     });
// //   }
// // };
// // controllers/authController.js - Update refreshAccessToken function

// export const refreshAccessToken = async (req, res) => {
//     try {
//         const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

//         if (!refreshToken) {
//             return res.status(401).json({
//                 success: false,
//                 message: "No refresh token provided"
//             });
//         }

//         // Verify refresh token
//         let decoded;
//         try {
//             decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
//         } catch (error) {
//             return res.status(401).json({
//                 success: false,
//                 message: "Invalid or expired refresh token"
//             });
//         }

//         // Check if session exists and is active
//         const session = await Session.findOne({
//             userId: decoded.userId,
//             refreshToken: refreshToken,
//             isActive: true
//         });

//         if (!session) {
//             return res.status(401).json({
//                 success: false,
//                 message: "Session not found. Please login again."
//             });
//         }

//         // Check if user exists
//         const user = await User.findById(decoded.userId);
//         if (!user || !user.isActive) {
//             return res.status(401).json({
//                 success: false,
//                 message: "User not found or deactivated"
//             });
//         }

//         // Generate new access token (15 minutes)
//         const newAccessToken = generateAccessToken(user._id);

//         // Set new access token in cookie
//         res.cookie("accessToken", newAccessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000 // 15 minutes
//         });

//         return res.status(200).json({
//             success: true,
//             message: "Token refreshed successfully",
//             accessToken: newAccessToken,
//             refreshToken: refreshToken // Return same refresh token
//         });

//     } catch (error) {
//         console.error("Refresh token error:", error);
//         return res.status(500).json({
//             success: false,
//             message: "Error refreshing token",
//             error: error.message
//         });
//     }
// };

// // controllers/authController.js - Add these new functions

// // Logout from all devices
// export const logoutAllDevices = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;

//         if (!userId) {
//             return res.status(401).json({
//                 success: false,
//                 message: "User not authenticated"
//             });
//         }

//         // 🔥 Revoke ALL active sessions for this user
//         const result = await Session.updateMany(
//             { userId, isActive: true },
//             { isActive: false, logoutAt: new Date() }
//         );

//         // Clear cookies
//         const cookieOptions = {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             path: "/"
//         };

//         res.clearCookie("accessToken", cookieOptions);
//         res.clearCookie("refreshToken", cookieOptions);

//         return res.status(200).json({
//             success: true,
//             message: `Logged out from all devices. ${result.modifiedCount} sessions terminated.`
//         });

//     } catch (error) {
//         console.error("Logout all devices error:", error);
//         return res.status(500).json({
//             success: false,
//             message: "Error logging out from all devices",
//             error: error.message
//         });
//     }
// };

// // Get all active sessions for current user
// export const getMySessions = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;

//         if (!userId) {
//             return res.status(401).json({
//                 success: false,
//                 message: "User not authenticated"
//             });
//         }

//         // Get all active sessions
//         const sessions = await Session.find({
//             userId,
//             isActive: true
//         }).select("-refreshToken").sort({ createdAt: -1 });

//         return res.status(200).json({
//             success: true,
//             sessions,
//             count: sessions.length
//         });

//     } catch (error) {
//         console.error("Get sessions error:", error);
//         return res.status(500).json({
//             success: false,
//             message: "Error fetching sessions",
//             error: error.message
//         });
//     }
// };

// // Refresh token handler (alias for refreshAccessToken)
// export const refreshAccessTokenHandler = async (req, res) => {
//     return refreshAccessToken(req, res);
// };

// controllers/authController.js
import mongoose from "mongoose";
import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import { formatCertifications } from "../utils/certificationFormatter.js";
import Session from "../models/sessionModel.js";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
// import { saveLocalFile, deleteLocalFile } from "../utils/uploadHelper.js";
import otpService from "../services/otpService.js";
import twilio from "twilio";
import crypto from "crypto";
import { validationResult } from "express-validator";
import { sendResetPasswordEmail } from "../utils/emailService.js";
import cloudinary from "../config/cloudinary.js";
import {
  uploadToCloudinary,
  deleteFromCloudinary,
} from "../utils/uploadHelper.js";
// import User from "../models/userModel.js";
import jwt from "jsonwebtoken";

// Initialize Twilio client
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN,
);
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// ================= TEMPORARY STORAGE =================
const verifiedUsersStore = new Map();
const emailOTPStore = new Map();
const phoneOTPStore = new Map();

// Clean up expired data every hour
setInterval(
  () => {
    const now = Date.now();
    for (const [email, data] of verifiedUsersStore.entries()) {
      if (data.expiresAt < now) verifiedUsersStore.delete(email);
    }
    for (const [email, data] of emailOTPStore.entries()) {
      if (data.expiresAt < now) emailOTPStore.delete(email);
    }
    for (const [email, data] of phoneOTPStore.entries()) {
      if (data.expiresAt < now) phoneOTPStore.delete(email);
    }
  },
  60 * 60 * 1000,
);


export const updateUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    console.log("=== UPDATE USER REQUEST ===");
    // console.log("User ID:", userId);
    console.log(
      "Files received:",
      req.files ? JSON.stringify(Object.keys(req.files)) : "No files",
    );
    // console.log("Body keys:", Object.keys(req.body));

    // Log all files with their paths
    if (req.files) {
      Object.keys(req.files).forEach((field) => {
        req.files[field].forEach((file, idx) => {
          console.log(`File ${field}[${idx}]:`, {
            originalname: file.originalname,
            path: file.path,
            filename: file.filename,
            fieldname: file.fieldname,
          });
        });
      });
    }

    // Find existing user
    const currentUser = await User.findById(userId);
    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
        success: false,
      });
    }

    // Prepare updates object
    const updates = {};

    // 1. Handle Profile Photo Upload
    if (
      req.files &&
      req.files["profilePhoto"] &&
      req.files["profilePhoto"][0]
    ) {
      const profileFile = req.files["profilePhoto"][0];
      // console.log(
      //   "Processing profile photo:",
      //   profileFile.originalname,
      //   "URL:",
      //   profileFile.path,
      // );

      // Delete old photo if exists
      if (currentUser.profilePhoto && currentUser.profilePhoto.publicId) {
        try {
          await cloudinary.uploader.destroy(currentUser.profilePhoto.publicId);
          console.log("Deleted old profile photo");
        } catch (err) {
          console.error("Error deleting old photo:", err);
        }
      }

      updates.profilePhoto = {
        url: profileFile.path,
        publicId: profileFile.filename,
        format: profileFile.format || null,
        bytes: profileFile.bytes || null,
      };
    }

    // 2. Handle Certifications - FIXED: Properly handle document URLs and DELETION
    let processedCertifications = [];

    // Check for certifications to delete
    let certificationsToDelete = [];
    if (req.body.deleteCertificationIds) {
      try {
        certificationsToDelete =
          typeof req.body.deleteCertificationIds === "string"
            ? JSON.parse(req.body.deleteCertificationIds)
            : req.body.deleteCertificationIds;
        console.log("Certifications to delete:", certificationsToDelete);
      } catch (e) {
        console.error("Error parsing deleteCertificationIds:", e);
      }
    }

    // Check for certification files in different formats
    const certificationFiles = [];

    // Check for nested certification files (certifications[0][document] format)
    if (req.files) {
      Object.keys(req.files).forEach((field) => {
        if (field.includes("certifications") && field.includes("document")) {
          // Extract index from field name like "certifications[0][document]"
          const match = field.match(/certifications\[(\d+)\]\[document\]/);
          if (match) {
            const index = parseInt(match[1]);
            certificationFiles[index] = req.files[field][0];
            console.log(
              `Found nested certification file at index ${index}:`,
              req.files[field][0].originalname,
            );
          }
        } else if (field === "certificationDocuments") {
          // Handle flat certificationDocuments array
          req.files[field].forEach((file, idx) => {
            certificationFiles[idx] = file;
            // console.log(
            //   `Found certification file at index ${idx}:`,
            //   file.originalname,
            // );
          });
        }
      });
    }

    // console.log(`Total certification files found: ${certificationFiles.length}`);

    // First, delete the certifications that are marked for deletion
    if (certificationsToDelete.length > 0 && currentUser.certifications) {
      // Find certifications to delete and remove their files from Cloudinary
      const certsToRemove = currentUser.certifications.filter((cert) =>
        certificationsToDelete.includes(cert._id.toString()),
      );

      // Delete files from Cloudinary
      for (const cert of certsToRemove) {
        if (cert.documentPublicId) {
          try {
            await cloudinary.uploader.destroy(cert.documentPublicId);
            // console.log(`Deleted certification file: ${cert.documentPublicId}`);
          } catch (err) {
            // console.error(
            //   `Error deleting certification file ${cert.documentPublicId}:`,
            //   err,
            // );
          }
        }
      }

      // Keep only certifications that are NOT marked for deletion
      const remainingCerts = currentUser.certifications.filter(
        (cert) => !certificationsToDelete.includes(cert._id.toString()),
      );

      // console.log(
      //   `Deleted ${certsToRemove.length} certifications, ${remainingCerts.length} remaining`,
      // );
      processedCertifications = [...remainingCerts];
    }

    // Parse certifications from request body (new/updated certifications)
    if (req.body.certifications) {
      try {
        let certificationsData = req.body.certifications;

        // Parse if it's a JSON string
        if (typeof certificationsData === "string") {
          try {
            certificationsData = JSON.parse(certificationsData);
            // console.log('Parsed certifications from JSON string');
          } catch (e) {
            console.log("Failed to parse as JSON, checking nested format");
          }
        }

        // Handle nested format (certifications[0][name], etc.)
        const hasNestedFormat = Object.keys(req.body).some((key) =>
          key.startsWith("certifications["),
        );

        if (hasNestedFormat) {
          // console.log("Processing nested certifications format");
          const certMap = new Map();

          Object.keys(req.body).forEach((key) => {
            const match = key.match(/certifications\[(\d+)\]\[(\w+)\]/);
            if (match) {
              const index = parseInt(match[1]);
              const field = match[2];
              const value = req.body[key];

              if (!certMap.has(index)) {
                certMap.set(index, {});
              }
              certMap.get(index)[field] = value;
            }
          });

          // Convert map to array with file URLs
          const newCertifications = [];
          certMap.forEach((cert, index) => {
            // Skip if this certification is marked as deleted
            if (cert._id && certificationsToDelete.includes(cert._id)) {
              // console.log(
              //   `Skipping deleted certification with ID: ${cert._id}`,
              // );
              return;
            }

            const certFile = certificationFiles[index];
            const certification = {
              name: cert.name || "",
              issuedBy: cert.issuedBy || "",
              issueDate: cert.issueDate || null,
              expiryDate: cert.expiryDate || null,
              _id: cert._id || undefined,
            };

            if (certFile && certFile.path) {
              console.log(
                `Adding document for certification ${index}:`,
                certFile.originalname,
                "URL:",
                certFile.path,
              );
              certification.documentName = certFile.originalname;
              certification.documentUrl = certFile.path;
              certification.documentPublicId = certFile.filename;
            } else if (
              cert.documentUrl &&
              cert.documentUrl !== "null" &&
              cert.documentUrl !== ""
            ) {
              // Keep existing document
              certification.documentName = cert.documentName || "";
              certification.documentUrl = cert.documentUrl;
              certification.documentPublicId = cert.documentPublicId || null;
              // console.log(
              //   `Keeping existing document for certification ${index}:`,
              //   certification.documentUrl,
              // );
            }

            newCertifications.push(certification);
          });

          // Merge with existing certifications that weren't deleted
          // Filter out any certifications that might be duplicates
          const existingCerts = processedCertifications.filter(
            (existing) =>
              !newCertifications.some(
                (newCert) => newCert._id && newCert._id === existing._id,
              ),
          );

          processedCertifications = [...existingCerts, ...newCertifications];
        }
        // Handle array format
        else if (Array.isArray(certificationsData)) {
          // console.log("Processing array format certifications");
          const newCertifications = certificationsData
            .map((cert, index) => {
              // Skip if this certification is marked as deleted
              if (cert._id && certificationsToDelete.includes(cert._id)) {
                // console.log(
                //   `Skipping deleted certification with ID: ${cert._id}`,
                // );
                return null;
              }

              const certFile = certificationFiles[index];

              if (certFile && certFile.path) {
                // console.log(
                //   `Adding document for certification ${index}:`,
                //   certFile.originalname,
                //   "URL:",
                //   certFile.path,
                // );
                return {
                  ...cert,
                  documentName: certFile.originalname,
                  documentUrl: certFile.path,
                  documentPublicId: certFile.filename,
                };
              }

              // Keep existing document if no new file
              if (
                cert.documentUrl &&
                cert.documentUrl !== "null" &&
                cert.documentUrl !== ""
              ) {
                // console.log(
                //   `Keeping existing document for certification ${index}:`,
                //   cert.documentUrl,
                // );
                return cert;
              }

              // Return certification without document
              return {
                ...cert,
                documentName: cert.documentName || "",
                documentUrl: null,
                documentPublicId: null,
              };
            })
            .filter((cert) => cert !== null); // Remove null entries (deleted certs)

          // Merge with existing certifications that weren't deleted
          const existingCerts = processedCertifications.filter(
            (existing) =>
              !newCertifications.some(
                (newCert) => newCert._id && newCert._id === existing._id,
              ),
          );

          processedCertifications = [...existingCerts, ...newCertifications];
        }
        // Handle object with arrays format
        else if (
          certificationsData.name &&
          Array.isArray(certificationsData.name)
        ) {
          // console.log("Processing object with arrays format");
          let fileIndex = 0;
          const newCertifications = [];

          for (let i = 0; i < certificationsData.name.length; i++) {
            if (
              certificationsData.name[i] &&
              certificationsData.name[i].trim()
            ) {
              // Skip if this certification is marked as deleted
              if (
                certificationsData._id?.[i] &&
                certificationsToDelete.includes(certificationsData._id[i])
              ) {
                // console.log(
                //   `Skipping deleted certification with ID: ${certificationsData._id[i]}`,
                // );
                continue;
              }

              const certFile = certificationFiles[fileIndex];

              const certification = {
                name: certificationsData.name[i],
                issuedBy: certificationsData.issuedBy?.[i] || "",
                issueDate: certificationsData.issueDate?.[i] || null,
                expiryDate: certificationsData.expiryDate?.[i] || null,
                _id: certificationsData._id?.[i] || undefined,
              };

              if (certFile && certFile.path) {
                // console.log(
                //   `Adding document for certification ${i}:`,
                //   certFile.originalname,
                // );
                certification.documentName = certFile.originalname;
                certification.documentUrl = certFile.path;
                certification.documentPublicId = certFile.filename;
                fileIndex++;
              } else if (
                certificationsData.documentUrl?.[i] &&
                certificationsData.documentUrl[i] !== "null" &&
                certificationsData.documentUrl[i] !== ""
              ) {
                // Keep existing document
                certification.documentName =
                  certificationsData.documentName?.[i] || "";
                certification.documentUrl = certificationsData.documentUrl[i];
                certification.documentPublicId =
                  certificationsData.documentPublicId?.[i] || null;
              } else {
                certification.documentName = "";
                certification.documentUrl = null;
                certification.documentPublicId = null;
              }

              newCertifications.push(certification);
            }
          }

          // Merge with existing certifications that weren't deleted
          const existingCerts = processedCertifications.filter(
            (existing) =>
              !newCertifications.some(
                (newCert) => newCert._id && newCert._id === existing._id,
              ),
          );

          processedCertifications = [...existingCerts, ...newCertifications];
        }

        // console.log(
        //   `Processed ${processedCertifications.length} certifications total after deletion and updates`,
        // );

        // Apply certifications update
        updates.certifications = processedCertifications;
        // console.log(
        //   `Added ${processedCertifications.length} certifications to update`,
        // );
      } catch (error) {
        console.error("Error processing certifications:", error);
      }
    } else if (
      req.body.certifications === null ||
      req.body.certifications === ""
    ) {
      updates.certifications = [];
    } else if (certificationsToDelete.length > 0 && !req.body.certifications) {
      // If only deletions happened (no new/updated certifications)
      updates.certifications = processedCertifications;
    }

    // Log final certifications before update
    if (updates.certifications) {
      console.log("Final certifications to save:");
      updates.certifications.forEach((cert, idx) => {
        console.log(`  Cert ${idx}:`, {
          name: cert.name,
          documentUrl: cert.documentUrl,
          documentName: cert.documentName,
          _id: cert._id,
        });
      });
    }

    // 3. Handle basic user fields
    const basicFields = [
      "fullName",
      "phoneNumber",
      "age",
      "gender",
      "dateOfBirth",
      "bloodGroup",
      "isActive",
      "isVerified",
      "profileCompleted",
      "email",
    ];

    basicFields.forEach((field) => {
      if (req.body[field] !== undefined && req.body[field] !== "") {
        updates[field] = req.body[field];
      }
    });

    // 4. Handle nested objects
    if (req.body.address) {
      try {
        updates.address =
          typeof req.body.address === "string"
            ? JSON.parse(req.body.address)
            : req.body.address;
      } catch (e) {
        updates.address = req.body.address;
      }
    }

    if (req.body.emergencyContact) {
      try {
        updates.emergencyContact =
          typeof req.body.emergencyContact === "string"
            ? JSON.parse(req.body.emergencyContact)
            : req.body.emergencyContact;
      } catch (e) {
        updates.emergencyContact = req.body.emergencyContact;
      }
    }

    // 5. Handle medicalInfo field (NEW)
    if (req.body.medicalInfo) {
      try {
        updates.medicalInfo =
          typeof req.body.medicalInfo === "string"
            ? JSON.parse(req.body.medicalInfo)
            : req.body.medicalInfo;
      } catch (e) {
        updates.medicalInfo = req.body.medicalInfo;
      }
    }

    // 6. Handle insuranceInfo field (NEW)
    if (req.body.insuranceInfo) {
      try {
        updates.insuranceInfo =
          typeof req.body.insuranceInfo === "string"
            ? JSON.parse(req.body.insuranceInfo)
            : req.body.insuranceInfo;
      } catch (e) {
        updates.insuranceInfo = req.body.insuranceInfo;
      }
    }

    // 7. Handle counsellor-specific fields
    if (currentUser.role === "counsellor") {
      const counsellorFields = [
        "qualification",
        "specialization",
        "experience",
        "location",
        "consultationMode",
        "languages",
        "aboutMe",
        "education",
        "rating",
        "totalSessions",
        "activeClients",
      ];

      counsellorFields.forEach((field) => {
        if (req.body[field] !== undefined && req.body[field] !== "") {
          // Parse JSON strings for array fields
          if (
            ["specialization", "languages", "consultationMode"].includes(
              field,
            ) &&
            typeof req.body[field] === "string"
          ) {
            try {
              updates[field] = JSON.parse(req.body[field]);
            } catch (e) {
              updates[field] = req.body[field].split(",").map((s) => s.trim());
            }
          } else {
            updates[field] = req.body[field];
          }
        }
      });
    }

    // 8. Validate phone number
    if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
      return res.status(400).json({
        message: "Phone number must be 10 digits",
        success: false,
      });
    }

    // 9. Update user
    // console.log("Applying updates...");

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updates },
      { new: true, runValidators: true },
    ).select("-password -emailOTP -phoneOTP");

    if (!updatedUser) {
      return res.status(404).json({
        message: "User not found after update",
        success: false,
      });
    }

    // 10. Format response with all fields matching frontend structure
    const formattedUser = {
      _id: updatedUser._id,
      fullName: updatedUser.fullName,
      email: updatedUser.email,
      phoneNumber: updatedUser.phoneNumber,
      age: updatedUser.age,
      gender: updatedUser.gender,
      role: updatedUser.role,
      profilePhoto: updatedUser.profilePhoto,
      isActive: updatedUser.isActive,
      profileCompleted: updatedUser.profileCompleted,
      createdAt: updatedUser.createdAt,
      updatedAt: updatedUser.updatedAt,
      dateOfBirth: updatedUser.dateOfBirth
        ? new Date(updatedUser.dateOfBirth).toISOString().split("T")[0]
        : null,
      bloodGroup: updatedUser.bloodGroup,
      address: updatedUser.address,
      emergencyContact: updatedUser.emergencyContact,
      medicalInfo: updatedUser.medicalInfo,
      insuranceInfo: updatedUser.insuranceInfo,
    };

    // Add counsellor fields if applicable
    if (updatedUser.role === "counsellor") {
      Object.assign(formattedUser, {
        qualification: updatedUser.qualification,
        specialization: updatedUser.specialization,
        experience: updatedUser.experience,
        location: updatedUser.location,
        consultationMode: updatedUser.consultationMode,
        languages: updatedUser.languages,
        aboutMe: updatedUser.aboutMe,
        education: updatedUser.education,
        certifications: updatedUser.certifications,
        rating: updatedUser.rating,
        totalSessions: updatedUser.totalSessions,
        activeClients: updatedUser.activeClients,
        uniqueCode: updatedUser.uniqueCode,
      });
    }

    // console.log(
    //   "Update successful! Certifications saved:",
    //   formattedUser.certifications?.length,
    // );

    return res.status(200).json({
      message: "User updated successfully",
      success: true,
      user: formattedUser,
    });
  } catch (error) {
    console.error("Update user error:", error);

    // Rollback: Delete any uploaded files if error occurred
    if (req.files && req.files["profilePhoto"]) {
      try {
        await cloudinary.uploader.destroy(
          req.files["profilePhoto"][0].filename,
        );
        console.log("Rollback: Deleted profile photo");
      } catch (e) {}
    }
    if (req.files) {
      Object.keys(req.files).forEach((field) => {
        if (
          field.includes("certifications") ||
          field === "certificationDocuments"
        ) {
          req.files[field].forEach(async (file) => {
            try {
              await cloudinary.uploader.destroy(file.filename);
              // console.log(
              //   `Rollback: Deleted certification file ${file.filename}`,
              // );
            } catch (e) {}
          });
        }
      });
    }

    return res.status(500).json({
      message: "Error updating user",
      success: false,
      error: error.message,
    });
  }
};



export const sendEmailOTP = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ message: "Email is required", success: false });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(409)
        .json({
          message: "User already exists with this email",
          success: false,
        });
    }

    const otp = otpService.generateOTP();

    try {
      await otpService.sendEmailOTP(email, otp, "User");
      emailOTPStore.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

      return res.status(200).json({
        message: "Email OTP sent successfully",
        success: true,
        email: email,
      });
    } catch (sendError) {
      console.error("OTP sending error:", sendError);
      return res
        .status(500)
        .json({
          message: "Failed to send OTP. Please try again.",
          success: false,
        });
    }
  } catch (error) {
    console.error("Send email OTP error:", error);
    return res
      .status(500)
      .json({
        message: "Error sending OTP",
        success: false,
        error: error.message,
      });
  }
};

// ================= STEP 2: VERIFY EMAIL OTP =================
export const verifyEmailOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res
        .status(400)
        .json({ message: "Email and OTP are required", success: false });
    }

    const storedData = emailOTPStore.get(email);

    if (!storedData) {
      return res
        .status(400)
        .json({
          message: "No OTP found. Please request a new OTP.",
          success: false,
        });
    }

    if (Date.now() > storedData.expiresAt) {
      emailOTPStore.delete(email);
      return res
        .status(400)
        .json({
          message: "OTP has expired. Please request a new OTP.",
          success: false,
        });
    }

    if (storedData.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP", success: false });
    }

    let userVerification = verifiedUsersStore.get(email);
    if (!userVerification) {
      userVerification = {
        isEmailVerified: true,
        isPhoneVerified: false,
        expiresAt: Date.now() + 60 * 60 * 1000,
      };
    } else {
      userVerification.isEmailVerified = true;
    }

    verifiedUsersStore.set(email, userVerification);
    emailOTPStore.delete(email);

    return res.status(200).json({
      message:
        "Email verified successfully. Please verify your phone number next.",
      success: true,
      email: email,
      nextStep: "phone_verification",
    });
  } catch (error) {
    console.error("Verify email OTP error:", error);
    return res
      .status(500)
      .json({
        message: "Error verifying OTP",
        success: false,
        error: error.message,
      });
  }
};

// ================= STEP 3: SEND PHONE OTP =================
export const sendPhoneOTP = async (req, res) => {
  try {
    const { phoneNumber, email } = req.body;

    if (!phoneNumber) {
      return res
        .status(400)
        .json({ message: "Phone number is required", success: false });
    }

    let userEmail = email;
    let userVerification = null;

    if (userEmail) {
      userVerification = verifiedUsersStore.get(userEmail);
    } else {
      for (const [email, data] of verifiedUsersStore.entries()) {
        if (data.isEmailVerified && !data.isPhoneVerified) {
          userEmail = email;
          userVerification = data;
          break;
        }
      }
    }

    if (!userVerification || !userVerification.isEmailVerified) {
      return res.status(400).json({
        message: "Please verify your email first.",
        success: false,
        requiresEmailFirst: true,
      });
    }

    const cleanedPhone = phoneNumber.replace(/\D/g, "");

    if (cleanedPhone.length !== 10) {
      return res
        .status(400)
        .json({ message: "Phone number must be 10 digits", success: false });
    }

    const existingUser = await User.findOne({ phoneNumber: cleanedPhone });
    if (existingUser) {
      return res
        .status(409)
        .json({ message: "Phone number already registered", success: false });
    }

    const formattedPhone = `+91${cleanedPhone}`;
    const otp = otpService.generateOTP();

    console.log(`📱 Sending Phone OTP to ${formattedPhone}: ${otp}`);

    try {
      const message = await twilioClient.messages.create({
        body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
        from: TWILIO_PHONE_NUMBER,
        to: formattedPhone,
      });

      userVerification.phoneNumber = cleanedPhone;
      userVerification.formattedPhone = formattedPhone;
      verifiedUsersStore.set(userEmail, userVerification);

      phoneOTPStore.set(userEmail, {
        otp,
        phoneNumber: cleanedPhone,
        formattedPhone,
        expiresAt: Date.now() + 10 * 60 * 1000,
      });

      return res.status(200).json({
        message: "Phone OTP sent successfully",
        success: true,
        phoneNumber: cleanedPhone,
        email: userEmail,
      });
    } catch (sendError) {
      // console.error("Phone OTP sending error:", sendError);
      return res
        .status(500)
        .json({ message: "Failed to send phone OTP", success: false });
    }
  } catch (error) {
    console.error("Send phone OTP error:", error);
    return res
      .status(500)
      .json({
        message: "Error sending phone OTP",
        success: false,
        error: error.message,
      });
  }
};

// ================= STEP 4: VERIFY PHONE OTP =================
// export const verifyPhoneOTP = async (req, res) => {
//     try {
//         const { phoneNumber, otp, email } = req.body;

//         if (!phoneNumber || !otp) {
//             return res.status(400).json({ message: "Phone number and OTP are required", success: false });
//         }

//         const cleanedPhone = phoneNumber.replace(/\D/g, '');
//         let foundEmail = email;
//         let storedData = null;

//         if (foundEmail) {
//             storedData = phoneOTPStore.get(foundEmail);
//             if (storedData && storedData.phoneNumber !== cleanedPhone) storedData = null;
//         }

//         if (!storedData) {
//             for (const [email, data] of phoneOTPStore.entries()) {
//                 if (data.phoneNumber === cleanedPhone && Date.now() <= data.expiresAt) {
//                     foundEmail = email;
//                     storedData = data;
//                     break;
//                 }
//             }
//         }

//         if (!storedData) {
//             return res.status(400).json({ message: "No OTP found. Please request a new OTP.", success: false });
//         }

//         if (Date.now() > storedData.expiresAt) {
//             phoneOTPStore.delete(foundEmail);
//             return res.status(400).json({ message: "OTP has expired. Please request a new OTP.", success: false });
//         }

//         if (storedData.otp !== otp) {
//             return res.status(400).json({ message: "Invalid OTP", success: false });
//         }

//         const userVerification = verifiedUsersStore.get(foundEmail);
//         if (userVerification) {
//             userVerification.isPhoneVerified = true;
//             userVerification.phoneNumber = cleanedPhone;
//             userVerification.formattedPhone = storedData.formattedPhone;
//             verifiedUsersStore.set(foundEmail, userVerification);
//         }

//         phoneOTPStore.delete(foundEmail);

//         return res.status(200).json({
//             message: "Phone verified successfully. You can now complete your registration.",
//             success: true,
//             email: foundEmail,
//             nextStep: "complete_registration"
//         });

//     } catch (error) {
//         console.error("Verify phone OTP error:", error);
//         return res.status(500).json({ message: "Error verifying phone OTP", success: false, error: error.message });
//     }
// };

// ================= STEP 4: VERIFY PHONE OTP =================
export const verifyPhoneOTP = async (req, res) => {
  try {
    const { phoneNumber, otp, email } = req.body;

    if (!phoneNumber || !otp) {
      return res
        .status(400)
        .json({ message: "Phone number and OTP are required", success: false });
    }

    const cleanedPhone = phoneNumber.replace(/\D/g, "");
    let foundEmail = email;
    let storedData = null;

    if (foundEmail) {
      storedData = phoneOTPStore.get(foundEmail);
      if (storedData && storedData.phoneNumber !== cleanedPhone)
        storedData = null;
    }

    if (!storedData) {
      for (const [email, data] of phoneOTPStore.entries()) {
        if (data.phoneNumber === cleanedPhone && Date.now() <= data.expiresAt) {
          foundEmail = email;
          storedData = data;
          break;
        }
      }
    }

    if (!storedData) {
      return res
        .status(400)
        .json({
          message: "No OTP found. Please request a new OTP.",
          success: false,
        });
    }

    if (Date.now() > storedData.expiresAt) {
      phoneOTPStore.delete(foundEmail);
      return res
        .status(400)
        .json({
          message: "OTP has expired. Please request a new OTP.",
          success: false,
        });
    }

    if (storedData.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP", success: false });
    }

    const userVerification = verifiedUsersStore.get(foundEmail);
    if (userVerification) {
      userVerification.isPhoneVerified = true;
      userVerification.phoneNumber = cleanedPhone;
      userVerification.formattedPhone = storedData.formattedPhone;
      verifiedUsersStore.set(foundEmail, userVerification);

      // DEBUG: Log the verification status
      console.log(`✅ Phone verified for ${foundEmail}`);
      console.log(`Verification data:`, {
        isEmailVerified: userVerification.isEmailVerified,
        isPhoneVerified: userVerification.isPhoneVerified,
        expiresAt: new Date(userVerification.expiresAt),
      });
    } else {
      // If no verification entry exists, create one
      verifiedUsersStore.set(foundEmail, {
        isEmailVerified: false, // This should have been set in email verification
        isPhoneVerified: true,
        phoneNumber: cleanedPhone,
        formattedPhone: storedData.formattedPhone,
        expiresAt: Date.now() + 60 * 60 * 1000,
      });
      console.log(
        `⚠️ Created new verification entry for ${foundEmail} (email verification missing)`,
      );
    }

    phoneOTPStore.delete(foundEmail);

    return res.status(200).json({
      message:
        "Phone verified successfully. You can now complete your registration.",
      success: true,
      email: foundEmail,
      nextStep: "complete_registration",
    });
  } catch (error) {
    console.error("Verify phone OTP error:", error);
    return res
      .status(500)
      .json({
        message: "Error verifying phone OTP",
        success: false,
        error: error.message,
      });
  }
};
// controllers/authController.js

// ================= STEP 5: COMPLETE REGISTRATION =================
export const completeRegistration = async (req, res) => {
  try {
    const {
      fullName,
      anonymous,
      email,
      password,
      age,
      gender,
      qualification,
      specialization,
      experience,
      location,
      consultationMode,
      languages,
      aboutMe,
      // NEW: Patient profile fields (optional)
      dateOfBirth,
      bloodGroup,
      address,
      emergencyContact,
      medicalInfo,
      insuranceInfo,
    } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({
        message: "Full name, email, and password are required",
        success: false,
      });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({
          message: "Password must be at least 6 characters",
          success: false,
        });
    }

    // DEBUG: Check what's in verifiedUsersStore
    console.log(`🔍 Checking verification for email: ${email}`);
    // console.log(`All verified users:`, Array.from(verifiedUsersStore.keys()));

    const userVerification = verifiedUsersStore.get(email);

    // DEBUG: Log verification status
    if (userVerification) {
      console.log(`Verification data for ${email}:`, {
        isEmailVerified: userVerification.isEmailVerified,
        isPhoneVerified: userVerification.isPhoneVerified,
        expiresAt: new Date(userVerification.expiresAt),
        now: new Date(),
        isExpired: Date.now() > userVerification.expiresAt,
      });
    } else {
      console.log(`❌ No verification data found for ${email}`);
    }

    // Check if verification exists and is complete
    if (!userVerification) {
      return res.status(400).json({
        message:
          "Please verify your email and phone first. No verification session found.",
        success: false,
      });
    }

    // Check if verification has expired
    if (Date.now() > userVerification.expiresAt) {
      verifiedUsersStore.delete(email);
      return res.status(400).json({
        message:
          "Verification session has expired. Please restart the registration process.",
        success: false,
      });
    }

    // Check both verifications
    if (
      !userVerification.isEmailVerified ||
      !userVerification.isPhoneVerified
    ) {
      const missing = [];
      if (!userVerification.isEmailVerified) missing.push("email");
      if (!userVerification.isPhoneVerified) missing.push("phone");

      return res.status(400).json({
        message: `Please verify your ${missing.join(" and ")} first`,
        success: false,
        missingVerifications: missing,
        status: {
          isEmailVerified: userVerification.isEmailVerified,
          isPhoneVerified: userVerification.isPhoneVerified,
        },
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { phoneNumber: userVerification.phoneNumber }],
    });

    if (existingUser) {
      verifiedUsersStore.delete(email);
      return res.status(409).json({
        message: "User already exists with this email or phone number",
        success: false,
      });
    }

    // Auto-detect role based on counsellor fields
    const hasCounsellorFields =
      qualification && specialization && experience && location;
    const role = hasCounsellorFields ? "counsellor" : "user";

    const hashedPassword = await bcrypt.hash(password, 10);

    // Base user data (common for both roles)
    const userData = {
      fullName,
      anonymous,
      email,
      password: hashedPassword,
      phoneNumber: userVerification.phoneNumber,
      age: age || null,
      gender: gender || "male",
      role,
      profileCompleted: true,
      isEmailVerified: true,
      isActive: true,
      // NEW: Add patient profile fields (will be null/empty for counsellors initially)
      dateOfBirth: dateOfBirth || null,
      bloodGroup: bloodGroup || null,
      address: address || {
        line1: "",
        line2: "",
        city: "",
        state: "",
        pincode: "",
        country: "India",
      },
      emergencyContact: emergencyContact || {
        name: "",
        relation: "",
        phone: "",
      },
      medicalInfo: medicalInfo || {
        height: "",
        weight: "",
        allergies: [],
        chronicConditions: [],
        currentMedications: [],
      },
      insuranceInfo: insuranceInfo || {
        provider: "",
        policyNumber: "",
        groupNumber: "",
        coverageAmount: "",
        validityDate: null,
        nominee: "",
        relationship: "",
        insuranceType: "",
      },
    };

    // Handle profile photo upload to Cloudinary (for counsellors only)
    let profilePhotoData = null;
    if (role === "counsellor" && req.file) {
      try {
        // Validate file buffer exists
        if (!req.file.buffer) {
          return res.status(400).json({
            message: "Invalid file data",
            success: false,
          });
        }

        // Upload to Cloudinary
        console.log("Uploading profile photo to Cloudinary...");
        profilePhotoData = await uploadToCloudinary(req.file.buffer, {
          folder: "profile-photos",
          transformation: [{ width: 500, height: 500, crop: "limit" }],
        });

        userData.profilePhoto = profilePhotoData;
        console.log(
          "Profile photo uploaded successfully:",
          profilePhotoData.url,
        );
      } catch (uploadError) {
        console.error("Cloudinary upload error:", uploadError);
        return res.status(500).json({
          message: "Failed to upload profile photo",
          success: false,
          error: uploadError.message,
        });
      }
    }

    // Add counsellor-specific fields ONLY if role is counsellor
    if (role === "counsellor") {
      userData.qualification = qualification;
      userData.specialization =
        typeof specialization === "string"
          ? specialization.split(",").map((s) => s.trim())
          : specialization;
      userData.experience = Number(experience);
      userData.location = location;
      userData.consultationMode =
        typeof consultationMode === "string"
          ? consultationMode.split(",").map((m) => m.trim())
          : consultationMode || ["online"];
      userData.languages =
        typeof languages === "string"
          ? languages.split(",").map((l) => l.trim())
          : languages || [];
      userData.aboutMe = aboutMe || "";
    }

    const newUser = await User.create(userData);

    // Clean up verification data
    verifiedUsersStore.delete(email);
    emailOTPStore.delete(email);
    phoneOTPStore.delete(email);

    // Generate tokens
    const accessToken = generateAccessToken(newUser._id);
    const refreshToken = generateRefreshToken(newUser._id);

    // Create session
    await Session.create({
      userId: newUser._id,
      refreshToken,
      isActive: true,
      createdAt: new Date(),
    });

    // Set cookies
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.status(201).json({
      message: "Registration completed successfully!",
      success: true,
      user: newUser.toJSON(),
      accessToken,
      refreshToken,
      role: newUser.role,
    });
  } catch (error) {
    console.error("Complete registration error:", error);

    // Rollback: Delete uploaded photo from Cloudinary if registration fails
    if (req.file && profilePhotoData && profilePhotoData.publicId) {
      try {
        await deleteFromCloudinary(profilePhotoData.publicId);
        console.log(
          `Rollback: Deleted uploaded photo ${profilePhotoData.publicId}`,
        );
      } catch (deleteError) {
        console.error("Error rolling back photo upload:", deleteError);
      }
    }

    return res.status(500).json({
      message: "Error completing registration",
      success: false,
      error: error.message,
    });
  }
};
// controllers/authController.js - FIXED loginUser
// export const loginUser = async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     if (!email || !password) {
//       return res
//         .status(400)
//         .json({ message: "Email and password are required", success: false });
//     }

//     const user = await User.findOne({ email });

//     if (!user) {
//       return res
//         .status(404)
//         .json({ message: "User not found", success: false });
//     }

//     if (!user.isActive) {
//       return res
//         .status(401)
//         .json({ message: "Account is deactivated", success: false });
//     }

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) {
//       return res
//         .status(401)
//         .json({ message: "Invalid password", success: false });
//     }

//     // Force logout all previous sessions
//     await Session.updateMany(
//       { userId: user._id, isActive: true },
//       { isActive: false, logoutAt: new Date() },
//     );

//     // ✅ STEP 1: Create session FIRST
// // ✅ STEP 1: Create empty session FIRST (without validation issue)
// const newSession = new Session({
//   userId: user._id,
//   isActive: true,
//   createdAt: new Date(),
// });

// // ✅ STEP 2: Generate tokens WITH sessionId
// const refreshToken = generateRefreshToken(user._id, newSession._id);
// const accessToken = generateAccessToken(user._id, newSession._id);

//    console.log("========== TOKEN DEBUG INFO ==========");
//     console.log("Access token payload:", jwt.decode(accessToken));
//     console.log("Refresh token payload:", jwt.decode(refreshToken));
//     console.log("Session ID:", newSession._id.toString());
//     console.log("======================================");

// // ✅ STEP 3: assign refreshToken BEFORE save
// newSession.refreshToken = refreshToken;

// // ✅ STEP 4: now save (no validation error)
// await newSession.save();
//     // // Generate refresh token (NO EXPIRY)
//     // const refreshToken = generateRefreshToken(user._id);

//     // // FIRST create session
//     // const newSession = await Session.create({
//     //   userId: user._id,
//     //   refreshToken,
//     //   isActive: true,
//     //   createdAt: new Date(),
//     // });

//     // console.log(`✅ Created new session: ${newSession._id}`);

//     // // THEN create access token WITH sessionId
//     // const accessToken = generateAccessToken(user._id, newSession._id);

//     // Set cookies
//     res.cookie("accessToken", accessToken, {
//       httpOnly: true,
//      secure: false,
// sameSite: "lax",
//     });

//     // res.cookie("refreshToken", refreshToken, {
//     //   httpOnly: true,
//     //   secure: process.env.NODE_ENV === "production",
//     //   sameSite: "none",
//     //   maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
//     // });
  
//     const cookieOptions = {
//   httpOnly: true,
//  secure: false,
// sameSite: "lax",
// };

// res.cookie("refreshToken", refreshToken, cookieOptions);
//     return res.status(200).json({
//       message: "Login successful",
//       success: true,
//       accessToken,
//       refreshToken,
//       user: user.toJSON(),
//       role: user.role,
//     });


//   } catch (error) {
//     console.log("Login error:", error);
//     return res
//       .status(500)
//       .json({
//         message: "Error in login",
//         success: false,
//         error: error.message,
//       });
//   }
// };

// ================= LOGIN USER (Prevent multiple logins - returns error if already logged in) =================
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required", success: false });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ message: "User not found", success: false });
    }

    if (!user.isActive) {
      return res
        .status(401)
        .json({ message: "Account is deactivated", success: false });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res
        .status(401)
        .json({ message: "Invalid password", success: false });
    }

    // Check if there's an existing active session for this user
    const existingActiveSession = await Session.findOne({
      userId: user._id,
      isActive: true
    });

    // If user already has an active session, return error
    if (existingActiveSession) {
      return res.status(409).json({
        message: "User is already logged in. Please logout from existing session first.",
        success: false,
        existingSessionId: existingActiveSession._id,
        loggedInAt: existingActiveSession.createdAt
      });
    }

    // Create new session
    const newSession = new Session({
      userId: user._id,
      isActive: true,
      createdAt: new Date(),
    });

    // Generate tokens WITH sessionId
    const refreshToken = generateRefreshToken(user._id, newSession._id);
    const accessToken = generateAccessToken(user._id, newSession._id);

    console.log("========== TOKEN DEBUG INFO ==========");
    console.log("Access token payload:", jwt.decode(accessToken));
    console.log("Refresh token payload:", jwt.decode(refreshToken));
    console.log("Session ID:", newSession._id.toString());
    console.log("======================================");

    // Assign refreshToken and save session
    newSession.refreshToken = refreshToken;
    await newSession.save();

    console.log(`✅ Created new session for user ${user._id}: ${newSession._id}`);

    // Set cookies
    const cookieOptions = {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    };

    res.cookie("accessToken", accessToken, cookieOptions);
    res.cookie("refreshToken", refreshToken, cookieOptions);

    return res.status(200).json({
      message: "Login successful",
      success: true,
      accessToken,
      refreshToken,
      user: user.toJSON(),
      role: user.role,
    });

  } catch (error) {
    console.error("Login error:", error);
    return res
      .status(500)
      .json({
        message: "Error in login",
        success: false,
        error: error.message,
      });
  }
};









// export const loginUser = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({ message: "Email and password are required", success: false });
//         }

//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({ message: "User not found", success: false });
//         }

//         if (!user.isActive) {
//             return res.status(401).json({ message: "Account is deactivated", success: false });
//         }

//         const match = await bcrypt.compare(password, user.password);
//         if (!match) {
//             return res.status(401).json({ message: "Invalid password", success: false });
//         }

//         // 🔥 Force logout all previous sessions (optional)
//         await Session.updateMany(
//             { userId: user._id, isActive: true },
//             { isActive: false, logoutAt: new Date() }
//         );

//         // ✅ 1. Create session FIRST
//         const session = await Session.create({
//             userId: user._id,
//             isActive: true,
//             userAgent: req.headers["user-agent"],
//             ipAddress: req.ip
//         });

//         // ✅ 2. Generate tokens (IMPORTANT FIX)
//         const accessToken = generateAccessToken(user._id, session._id);
//         const refreshToken = generateRefreshToken(user._id, session._id); // 🔥 FIXED

//         // ✅ 3. Save refresh token in DB
//         session.refreshToken = refreshToken;
//         await session.save();

//         console.log(`✅ Session created: ${session._id}`);

//         // ✅ 4. Cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 7 * 24 * 60 * 60 * 1000 // 🔥 change to 7 days (not 1 year)
//         });

//         return res.status(200).json({
//             message: "Login successful",
//             success: true,
//             accessToken,
//             user: user.toJSON(),
//             role: user.role
//         });

//     } catch (error) {
//         console.log("Login error:", error);
//         return res.status(500).json({ message: "Error in login", success: false });
//     }
// };

// export const completeRegistration = async (req, res) => {
//     try {
//         const {
//             fullName, email, password, age, gender,
//             qualification, specialization, experience, location,
//             consultationMode, languages, aboutMe,
//             // NEW: Patient profile fields (optional)
//             dateOfBirth, bloodGroup,
//             address, emergencyContact,
//             medicalInfo, insuranceInfo
//         } = req.body;

//         if (!fullName || !email || !password) {
//             return res.status(400).json({
//                 message: "Full name, email, and password are required",
//                 success: false
//             });
//         }

//         if (password.length < 6) {
//             return res.status(400).json({ message: "Password must be at least 6 characters", success: false });
//         }

//         const userVerification = verifiedUsersStore.get(email);

//         if (!userVerification || !userVerification.isEmailVerified || !userVerification.isPhoneVerified) {
//             return res.status(400).json({
//                 message: "Please verify your email and phone first",
//                 success: false
//             });
//         }

//         const existingUser = await User.findOne({
//             $or: [{ email }, { phoneNumber: userVerification.phoneNumber }]
//         });

//         if (existingUser) {
//             verifiedUsersStore.delete(email);
//             return res.status(409).json({ message: "User already exists", success: false });
//         }

//         // Auto-detect role based on counsellor fields
//         const hasCounsellorFields = qualification && specialization && experience && location;
//         const role = hasCounsellorFields ? "counsellor" : "user";

//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Base user data (common for both roles)
//         const userData = {
//             fullName,
//             email,
//             password: hashedPassword,
//             phoneNumber: userVerification.phoneNumber,
//             age: age || null,
//             gender: gender || "male",
//             role,
//             profileCompleted: true,
//             isEmailVerified: true,
//             isActive: true,
//             // NEW: Add patient profile fields (will be null/empty for counsellors initially)
//             dateOfBirth: dateOfBirth || null,
//             bloodGroup: bloodGroup || null,
//             address: address || {
//                 line1: "",
//                 line2: "",
//                 city: "",
//                 state: "",
//                 pincode: "",
//                 country: "India"
//             },
//             emergencyContact: emergencyContact || {
//                 name: "",
//                 relation: "",
//                 phone: ""
//             },
//             medicalInfo: medicalInfo || {
//                 height: "",
//                 weight: "",
//                 allergies: [],
//                 chronicConditions: [],
//                 currentMedications: []
//             },
//             insuranceInfo: insuranceInfo || {
//                 provider: "",
//                 policyNumber: "",
//                 groupNumber: "",
//                 coverageAmount: "",
//                 validityDate: null,
//                 nominee: "",
//                 relationship: "",
//                 insuranceType: ""
//             }
//         };

//         // Add counsellor-specific fields ONLY if role is counsellor
//         if (role === "counsellor") {
//             userData.qualification = qualification;
//             userData.specialization = typeof specialization === 'string'
//                 ? specialization.split(',').map(s => s.trim())
//                 : specialization;
//             userData.experience = Number(experience);
//             userData.location = location;
//             userData.consultationMode = typeof consultationMode === 'string'
//                 ? consultationMode.split(',').map(m => m.trim())
//                 : consultationMode || ["online"];
//             userData.languages = typeof languages === 'string'
//                 ? languages.split(',').map(l => l.trim())
//                 : languages || [];
//             userData.aboutMe = aboutMe || "";

//             if (req.file) {
//                 userData.profilePhoto = saveLocalFile(req.file);
//             }
//         }

//         const newUser = await User.create(userData);

//         // Clean up verification data
//         verifiedUsersStore.delete(email);
//         emailOTPStore.delete(email);
//         phoneOTPStore.delete(email);

//         // Generate tokens
//         const accessToken = generateAccessToken(newUser._id);
//         const refreshToken = generateRefreshToken(newUser._id);

//         // Create session
//         await Session.create({
//             userId: newUser._id,
//             refreshToken,
//             isActive: true,
//             createdAt: new Date()
//         });

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000 // 15 minutes
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
//         });

//         return res.status(201).json({
//             message: "Registration completed successfully!",
//             success: true,
//             user: newUser.toJSON(),
//             accessToken,
//             refreshToken,
//             role: newUser.role
//         });

//     } catch (error) {
//         console.error("Complete registration error:", error);
//         if (req.file) deleteLocalFile(saveLocalFile(req.file));
//         return res.status(500).json({
//             message: "Error completing registration",
//             success: false,
//             error: error.message
//         });
//     }
// };

// ================= LOGIN USER (Force logout previous sessions) =================
// export const loginUser = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({ message: "Email and password are required", success: false });
//         }

//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({ message: "User not found", success: false });
//         }

//         if (!user.isActive) {
//             return res.status(401).json({ message: "Account is deactivated", success: false });
//         }

//         const match = await bcrypt.compare(password, user.password);
//         if (!match) {
//             return res.status(401).json({ message: "Invalid password", success: false });
//         }

//         // Force logout all previous sessions
//         await Session.updateMany(
//             { userId: user._id, isActive: true },
//             { isActive: false, logoutAt: new Date() }
//         );

//         // Generate tokens - REFRESH TOKEN HAS NO EXPIRY
//         const accessToken = generateAccessToken(user._id);
//         const refreshToken = generateRefreshToken(user._id);

//         // Create new session with NO expiry date
//         await Session.create({
//             userId: user._id,
//             refreshToken,
//             isActive: true,
//             createdAt: new Date()
//         });

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 365 * 24 * 60 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Login successful. Previous sessions have been logged out.",
//             success: true,
//             accessToken,
//             refreshToken,
//             user: user.toJSON(),
//             role: user.role
//         });

//     } catch (error) {
//         console.log("Login error:", error);
//         return res.status(500).json({ message: "Error in login", success: false, error: error.message });
//     }
// };
// ================= LOGIN USER (Force logout previous sessions) =================
// export const loginUser = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({ message: "Email and password are required", success: false });
//         }

//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({ message: "User not found", success: false });
//         }

//         if (!user.isActive) {
//             return res.status(401).json({ message: "Account is deactivated", success: false });
//         }

//         const match = await bcrypt.compare(password, user.password);
//         if (!match) {
//             return res.status(401).json({ message: "Invalid password", success: false });
//         }

//         // DEBUG: Check existing sessions before logout
//         const existingSessionsBefore = await Session.find({
//             userId: user._id,
//             isActive: true
//         });
//         console.log(`📊 Existing active sessions BEFORE logout: ${existingSessionsBefore.length}`);
//         existingSessionsBefore.forEach(session => {
//             console.log(`   - Session ID: ${session._id}, Created: ${session.createdAt}`);
//         });

//         // Force logout all previous sessions
//         const result = await Session.updateMany(
//             { userId: user._id, isActive: true },
//             { isActive: false, logoutAt: new Date() }
//         );

//         console.log(`✅ Logged out ${result.modifiedCount} previous sessions`);

//         // DEBUG: Verify sessions are logged out
//         const existingSessionsAfter = await Session.find({
//             userId: user._id,
//             isActive: true
//         });
//         console.log(`📊 Active sessions AFTER logout: ${existingSessionsAfter.length}`);

//         // Generate tokens - REFRESH TOKEN HAS NO EXPIRY
//         // const accessToken = generateAccessToken(user._id);
//         // const refreshToken = generateRefreshToken(user._id);

//         // // Create new session with NO expiry date
//         // const newSession = await Session.create({
//         //     userId: user._id,
//         //     refreshToken,
//         //     isActive: true,
//         //     createdAt: new Date()
//         // });
// const refreshToken = generateRefreshToken(user._id);

// // 🔥 FIRST create session
// const newSession = await Session.create({
//     userId: user._id,
//     refreshToken,
//     isActive: true,
//     createdAt: new Date()
// });

// // 🔥 THEN create accessToken with sessionId
// const accessToken = generateAccessToken(user._id, newSession._id);
//         console.log(`✅ Created new session: ${newSession._id}`);

//         // Set cookies
//         res.cookie("accessToken", accessToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 365 * 24 * 60 * 60 * 1000
//         });

//         return res.status(200).json({
//             message: "Login successful. Previous sessions have been logged out.",
//             success: true,
//             accessToken,
//             refreshToken,
//             user: user.toJSON(),
//             role: user.role,
//             sessionsLoggedOut: result.modifiedCount
//         });

//     } catch (error) {
//         console.log("Login error:", error);
//         return res.status(500).json({ message: "Error in login", success: false, error: error.message });
//     }
// };

// ================= REFRESH ACCESS TOKEN =================
export const refreshAccessToken = async (req, res) => {
  try {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    
    if (!incomingRefreshToken) {
      return res.status(401).json({ message: "No refresh token" });
    }

    let decoded;
    try {
      decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Find session using sessionId from refresh token
    const session = await Session.findById(decoded.sessionId);
    
    if (!session || !session.isActive) {
      return res.status(401).json({ message: "Session expired" });
    }
    
    if (session.refreshToken !== incomingRefreshToken) {
      return res.status(401).json({ message: "Token mismatch" });
    }
    
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({ message: "User not found" });
    }
    
    // ✅ FIXED: Pass sessionId to generateAccessToken
    const newAccessToken = generateAccessToken(user._id, session._id);
    const newRefreshToken = generateRefreshToken(user._id, session._id);
    
    // Update session with new refresh token
    session.refreshToken = newRefreshToken;
    await session.save();
    
    // Set cookies (for browser clients)
    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: '/'
    });
    
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: '/'
    });
    
    // Return both tokens for Postman/frontend
    return res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken  // Also return this
    });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

// export const refreshAccessToken = async (req, res) => {
//     try {
//         const incomingRefreshToken =
//             req.cookies?.refreshToken || req.body?.refreshToken;

//         if (!incomingRefreshToken) {
//             return res.status(401).json({ message: "No refresh token" });
//         }

//         let decoded;
//         try {
//             decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_SECRET);
//         } catch (err) {
//             return res.status(401).json({ message: "Invalid refresh token" });
//         }

//         // 🔥 find session using sessionId (NOT only userId)
//         const session = await Session.findById(decoded.sessionId);

//         if (!session || !session.isActive) {
//             return res.status(401).json({ message: "Session expired" });
//         }

//         // 🔥 match refresh token
//         if (session.refreshToken !== incomingRefreshToken) {
//             return res.status(401).json({ message: "Token mismatch" });
//         }

//         const user = await User.findById(decoded.userId);

//         // ✅ NEW TOKENS (rotation)
//         const newAccessToken = generateAccessToken(user._id);
//         const newRefreshToken = generateRefreshToken(user._id, session._id);

//         // 🔥 update DB with new refresh token
//         session.refreshToken = newRefreshToken;
//         await session.save();

//         // 🍪 send cookies
//         res.cookie("accessToken", newAccessToken, {
//             httpOnly: true,
//             sameSite: "strict",
//             maxAge: 15 * 60 * 1000
//         });

//         res.cookie("refreshToken", newRefreshToken, {
//             httpOnly: true,
//             sameSite: "strict",
//             maxAge: 7 * 24 * 60 * 60 * 1000
//         });

//         return res.json({
//             success: true,
//             accessToken: newAccessToken
//         });

//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ message: "Server error" });
//     }
// };

// ================= LOGOUT ================= real
// export const logout = async (req, res) => {
//     try {
//         const refreshToken = req.cookies?.refreshToken;

//         if (refreshToken) {
//             await Session.updateOne(
//                 { refreshToken, isActive: true },
//                 { isActive: false, logoutAt: new Date() }
//             );
//         }

//         res.clearCookie("accessToken", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict" });
//         res.clearCookie("refreshToken", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict" });

//         return res.status(200).json({ message: "Logged out successfully", success: true });

//     } catch (error) {
//         console.error("Logout error:", error);
//         return res.status(500).json({ message: "Error in logout", success: false });
//     }
// };

// ================= LOGOUT (FIXED - Properly invalidates session) =================
export const logout = async (req, res) => {
  try {
    // Get userId from request (set by auth middleware)
    let userId = req.userId || req.user?._id;
    const refreshToken = req.cookies?.refreshToken;

    console.log("🔓 Logout - UserId from request:", userId);
    console.log("🔓 Logout - Refresh token present:", !!refreshToken);

    // If no userId but we have refresh token, try to decode it
    if (!userId && refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        userId = decoded.userId;
        console.log("✅ Got userId from refresh token in logout function:", userId);
      } catch (error) {
        console.log("⚠️ Could not decode refresh token:", error.message);
      }
    }

    // Invalidate session(s)
    if (userId) {
      if (refreshToken) {
        // Invalidate the specific session with this refresh token
        const result = await Session.updateOne(
          { userId, refreshToken, isActive: true },
          { isActive: false, logoutAt: new Date() }
        );
        
        if (result.modifiedCount === 0) {
          // If no specific session found, invalidate all active sessions for this user
          const allResult = await Session.updateMany(
            { userId, isActive: true },
            { isActive: false, logoutAt: new Date() }
          );
          console.log(`✅ All ${allResult.modifiedCount} sessions invalidated for user: ${userId}`);
        } else {
          console.log(`✅ Specific session invalidated for user: ${userId}`);
        }
      } else {
        // No refresh token provided, invalidate ALL active sessions
        const result = await Session.updateMany(
          { userId, isActive: true },
          { isActive: false, logoutAt: new Date() }
        );
        console.log(`✅ All ${result.modifiedCount} sessions invalidated for user: ${userId}`);
      }
    } else {
      console.log("⚠️ No userId found, skipping session invalidation");
    }

    // Clear cookies regardless
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/"
    };

    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    console.log("✅ Cookies cleared successfully");

    return res.status(200).json({
      message: "Logged out successfully",
      success: true
    });

  } catch (error) {
    console.error("Logout error:", error);

    // Even on error, try to clear cookies
    try {
      res.clearCookie("accessToken", { path: "/" });
      res.clearCookie("refreshToken", { path: "/" });
    } catch (cookieError) {
      console.error("Error clearing cookies:", cookieError);
    }

    return res.status(500).json({
      message: "Error in logout",
      success: false,
      error: error.message
    });
  }
};


// ================= LOGOUT =================

// ================= LOGOUT FROM ALL DEVICES =================
export const logoutAllDevices = async (req, res) => {
  try {
    const userId = req.userId || req.user?._id;

    if (!userId) {
      return res
        .status(401)
        .json({ success: false, message: "User not authenticated" });
    }

    await Session.updateMany(
      { userId, isActive: true },
      { isActive: false, logoutAt: new Date() },
    );

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res
      .status(200)
      .json({ message: "Logged out from all devices", success: true });
  } catch (error) {
    console.error("Logout all error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Error logging out" });
  }
};

// ================= GET ALL SESSIONS =================
export const getMySessions = async (req, res) => {
  try {
    const userId = req.userId || req.user?._id;

    if (!userId) {
      return res
        .status(401)
        .json({ success: false, message: "User not authenticated" });
    }

    const sessions = await Session.find({ userId, isActive: true })
      .select("-refreshToken")
      .sort({ createdAt: -1 });

    return res
      .status(200)
      .json({ success: true, sessions, count: sessions.length });
  } catch (error) {
    console.error("Get sessions error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Error fetching sessions" });
  }
};

// ================= GET ALL COUNSELLORS =================
export const getAllCounsellors = async (req, res) => {
  try {
    const { specialization, location, consultationMode, minExperience } =
      req.query;
    let filter = { role: "counsellor", isActive: true, profileCompleted: true };

    if (specialization) filter.specialization = { $in: [specialization] };
    if (location) filter.location = { $regex: location, $options: "i" };
    if (consultationMode) filter.consultationMode = { $in: [consultationMode] };
    if (minExperience) filter.experience = { $gte: Number(minExperience) };

    const counsellors = await User.find(filter)
      .select("-password")
      .sort({ createdAt: -1 });

    return res
      .status(200)
      .json({
        message: "Counsellors fetched successfully",
        success: true,
        counsellors,
        count: counsellors.length,
      });
  } catch (error) {
    console.log("Get counsellors error:", error);
    return res
      .status(500)
      .json({ message: "Error fetching counsellors", success: false });
  }
};

// ================= GET SINGLE COUNSELLOR =================
export const getCounsellorById = async (req, res) => {
  try {
    const { counsellorId } = req.params;
    const counsellor = await User.findOne({
      _id: counsellorId,
      role: "counsellor",
      isActive: true,
    }).select("-password");

    if (!counsellor) {
      return res
        .status(404)
        .json({ message: "Counsellor not found", success: false });
    }

    return res
      .status(200)
      .json({
        message: "Counsellor fetched successfully",
        success: true,
        counsellor: counsellor.toJSON(),
      });
  } catch (error) {
    console.log("Get counsellor error:", error);
    return res
      .status(500)
      .json({ message: "Error fetching counsellor", success: false });
  }
};

// ================= GET MY PROFILE =================

// controllers/profileController.js

// ================= GET COMPLETE PROFILE =================
export const getMyProfile = async (req, res) => {
  try {
    const userId = req.userId || req.user?._id;
    const user = await User.findById(userId).select(
      "-password -emailOTP -phoneOTP",
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found",
        success: false,
      });
    }

    // Format the response with all fields including new patient profile fields
    const formattedProfile = {
      // Basic Info
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      age: user.age,
      gender: user.gender,
      role: user.role,
      profilePhoto: user.profilePhoto,
      isActive: user.isActive,
      profileCompleted: user.profileCompleted,

      // New Patient Profile Fields
      dateOfBirth: user.dateOfBirth
        ? new Date(user.dateOfBirth).toISOString().split("T")[0]
        : null,
      bloodGroup: user.bloodGroup || null,

      address: user.address || {
        line1: "",
        line2: "",
        city: "",
        state: "",
        pincode: "",
        country: "India",
      },

      emergencyContact: user.emergencyContact || {
        name: "",
        relation: "",
        phone: "",
      },

      medicalInfo: user.medicalInfo || {
        height: "",
        weight: "",
        allergies: [],
        chronicConditions: [],
        currentMedications: [],
      },

      insuranceInfo: user.insuranceInfo || {
        provider: "",
        policyNumber: "",
        groupNumber: "",
        coverageAmount: "",
        validityDate: null,
        nominee: "",
        relationship: "",
        insuranceType: "",
      },
    };

    // Add counsellor-specific fields if user is counsellor
    if (user.role === "counsellor") {
      formattedProfile.qualification = user.qualification;
      formattedProfile.specialization = user.specialization;
      formattedProfile.experience = user.experience;
      formattedProfile.location = user.location;
      formattedProfile.consultationMode = user.consultationMode;
      formattedProfile.languages = user.languages;
      formattedProfile.aboutMe = user.aboutMe;
    }

    return res.status(200).json({
      message: "Profile fetched successfully",
      success: true,
      user: formattedProfile,
    });
  } catch (error) {
    console.log("Get profile error:", error);
    return res.status(500).json({
      message: "Error fetching profile",
      success: false,
    });
  }
};
// controllers/profileController.js
// export const getMyProfile = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;
//         const user = await User.findById(userId).select("-password -emailOTP -phoneOTP");

//         if (!user) {
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         // Common fields for BOTH users and counsellors
//         const formattedProfile = {
//             // Basic Info
//             _id: user._id,
//             fullName: user.fullName,
//             email: user.email,
//             phoneNumber: user.phoneNumber,
//             age: user.age,
//             gender: user.gender,
//             role: user.role,
//             profilePhoto: user.profilePhoto,
//             isActive: user.isActive,
//             profileCompleted: user.profileCompleted,

//             // Patient Profile Fields (available for BOTH users and counsellors)
//             dateOfBirth: user.dateOfBirth ? new Date(user.dateOfBirth).toISOString().split('T')[0] : null,
//             bloodGroup: user.bloodGroup || null,

//             address: user.address || {
//                 line1: "",
//                 line2: "",
//                 city: "",
//                 state: "",
//                 pincode: "",
//                 country: "India"
//             },

//             emergencyContact: user.emergencyContact || {
//                 name: "",
//                 relation: "",
//                 phone: ""
//             },

//             medicalInfo: user.medicalInfo || {
//                 height: "",
//                 weight: "",
//                 allergies: [],
//                 chronicConditions: [],
//                 currentMedications: []
//             },

//             insuranceInfo: user.insuranceInfo || {
//                 provider: "",
//                 policyNumber: "",
//                 groupNumber: "",
//                 coverageAmount: "",
//                 validityDate: null,
//                 nominee: "",
//                 relationship: "",
//                 insuranceType: ""
//             }
//         };

//         // Add counsellor-specific fields ONLY if user is counsellor
//         if (user.role === "counsellor") {
//             formattedProfile.qualification = user.qualification || "";
//             formattedProfile.specialization = user.specialization || [];
//             formattedProfile.experience = user.experience || 0;
//             formattedProfile.location = user.location || "";
//             formattedProfile.consultationMode = user.consultationMode || ["online"];
//             formattedProfile.languages = user.languages || [];
//             formattedProfile.aboutMe = user.aboutMe || "";
//             formattedProfile.education = user.education || "";
//             formattedProfile.certifications = user.certifications || [];
//             formattedProfile.rating = user.rating || 0;
//             formattedProfile.totalSessions = user.totalSessions || 0;
//             formattedProfile.activeClients = user.activeClients || 0;
//             formattedProfile.uniqueCode = user.uniqueCode || `CNS-${user._id.toString().substr(-6).toUpperCase()}`;
//         }

//         return res.status(200).json({
//             message: "Profile fetched successfully",
//             success: true,
//             user: formattedProfile
//         });

//     } catch (error) {
//         console.log("Get profile error:", error);
//         return res.status(500).json({
//             message: "Error fetching profile",
//             success: false,
//             error: error.message
//         });
//     }
// };
// controllers/profileController.js
// controllers/profileController.js

// ================= UPDATE USER BY ID (Admin Only) =================

// ================= UPDATE USER BY ID (Admin Only) =================
// export const updateUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         // Format certifications from form data (arrays) to array of objects
//         const formattedCertifications = formatCertifications(req.body);

//         // Base allowed updates for ALL users
//         let allowedUpdates = [
//             'fullName', 'anonymous', 'phoneNumber', 'age', 'gender', 'role',
//             // Patient profile fields
//             'dateOfBirth', 'bloodGroup',
//             'address', 'emergencyContact', 'medicalInfo', 'insuranceInfo',
//             // Account status
//             'isActive', 'isVerified', 'profileCompleted'
//         ];

//         // Add counsellor-specific fields ONLY if user is counsellor
//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push(
//                 'qualification', 'specialization', 'experience',
//                 'location', 'consultationMode', 'languages', 'aboutMe',
//                 'education', 'rating', 'totalSessions', 'activeClients'
//             );
//         }

//         // Prepare updates object
//         const updates = {};

//         // Process each allowed field
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") {
//                 updates[field] = req.body[field];
//             }
//         });

//         // Add formatted certifications
//         if (formattedCertifications && formattedCertifications.length > 0) {
//             updates.certifications = formattedCertifications;
//         } else if (req.body.certifications === null || req.body.certifications === "") {
//             // If certifications is explicitly set to empty, clear them
//             updates.certifications = [];
//         }

//         // Handle nested objects (address, emergencyContact, medicalInfo, insuranceInfo)
//         if (req.body.address && typeof req.body.address === 'object' && !Array.isArray(req.body.address)) {
//             updates.address = {
//                 line1: req.body.address.line1 || currentUser.address?.line1 || "",
//                 line2: req.body.address.line2 || currentUser.address?.line2 || "",
//                 city: req.body.address.city || currentUser.address?.city || "",
//                 state: req.body.address.state || currentUser.address?.state || "",
//                 pincode: req.body.address.pincode || currentUser.address?.pincode || "",
//                 country: req.body.address.country || currentUser.address?.country || "India"
//             };
//         }

//         if (req.body.emergencyContact && typeof req.body.emergencyContact === 'object' && !Array.isArray(req.body.emergencyContact)) {
//             updates.emergencyContact = {
//                 name: req.body.emergencyContact.name || currentUser.emergencyContact?.name || "",
//                 relation: req.body.emergencyContact.relation || currentUser.emergencyContact?.relation || "",
//                 phone: req.body.emergencyContact.phone || currentUser.emergencyContact?.phone || ""
//             };
//         }

//         if (req.body.medicalInfo && typeof req.body.medicalInfo === 'object' && !Array.isArray(req.body.medicalInfo)) {
//             updates.medicalInfo = {
//                 height: req.body.medicalInfo.height || currentUser.medicalInfo?.height || "",
//                 weight: req.body.medicalInfo.weight || currentUser.medicalInfo?.weight || "",
//                 allergies: Array.isArray(req.body.medicalInfo.allergies) ? req.body.medicalInfo.allergies :
//                            (req.body.medicalInfo.allergies ? [req.body.medicalInfo.allergies] : []),
//                 chronicConditions: Array.isArray(req.body.medicalInfo.chronicConditions) ? req.body.medicalInfo.chronicConditions :
//                                    (req.body.medicalInfo.chronicConditions ? [req.body.medicalInfo.chronicConditions] : []),
//                 currentMedications: Array.isArray(req.body.medicalInfo.currentMedications) ? req.body.medicalInfo.currentMedications :
//                                     (req.body.medicalInfo.currentMedications ? [req.body.medicalInfo.currentMedications] : [])
//             };
//         }

//         if (req.body.insuranceInfo && typeof req.body.insuranceInfo === 'object' && !Array.isArray(req.body.insuranceInfo)) {
//             updates.insuranceInfo = {
//                 provider: req.body.insuranceInfo.provider || currentUser.insuranceInfo?.provider || "",
//                 policyNumber: req.body.insuranceInfo.policyNumber || currentUser.insuranceInfo?.policyNumber || "",
//                 groupNumber: req.body.insuranceInfo.groupNumber || currentUser.insuranceInfo?.groupNumber || "",
//                 coverageAmount: req.body.insuranceInfo.coverageAmount || currentUser.insuranceInfo?.coverageAmount || "",
//                 validityDate: req.body.insuranceInfo.validityDate || currentUser.insuranceInfo?.validityDate || null,
//                 nominee: req.body.insuranceInfo.nominee || currentUser.insuranceInfo?.nominee || "",
//                 relationship: req.body.insuranceInfo.relationship || currentUser.insuranceInfo?.relationship || "",
//                 insuranceType: req.body.insuranceInfo.insuranceType || currentUser.insuranceInfo?.insuranceType || ""
//             };
//         }

//         // Handle counsellor-specific array fields (convert from string to array if needed)
//         if (currentUser.role === "counsellor") {
//             // Handle specialization
//             if (req.body.specialization) {
//                 if (typeof req.body.specialization === 'string') {
//                     // Check if it's a JSON string
//                     try {
//                         const parsed = JSON.parse(req.body.specialization);
//                         updates.specialization = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         // Treat as comma-separated string
//                         updates.specialization = req.body.specialization.split(',').map(s => s.trim()).filter(s => s);
//                     }
//                 } else if (Array.isArray(req.body.specialization)) {
//                     updates.specialization = req.body.specialization;
//                 }
//             }

//             // Handle languages
//             if (req.body.languages) {
//                 if (typeof req.body.languages === 'string') {
//                     try {
//                         const parsed = JSON.parse(req.body.languages);
//                         updates.languages = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         updates.languages = req.body.languages.split(',').map(l => l.trim()).filter(l => l);
//                     }
//                 } else if (Array.isArray(req.body.languages)) {
//                     updates.languages = req.body.languages;
//                 }
//             }

//             // Handle consultationMode
//             if (req.body.consultationMode) {
//                 if (typeof req.body.consultationMode === 'string') {
//                     try {
//                         const parsed = JSON.parse(req.body.consultationMode);
//                         updates.consultationMode = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         updates.consultationMode = req.body.consultationMode.split(',').map(m => m.trim()).filter(m => m);
//                     }
//                 } else if (Array.isArray(req.body.consultationMode)) {
//                     updates.consultationMode = req.body.consultationMode;
//                 }
//             }
//         }

//         // Handle profile photo upload
//         if (req.file) {
//             if (currentUser.profilePhoto) deleteLocalFile(currentUser.profilePhoto);
//             updates.profilePhoto = saveLocalFile(req.file);
//         }

//         // Validate phone number if being updated
//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Update the user
//         const updatedUser = await User.findByIdAndUpdate(
//             userId,
//             updates,
//             { new: true, runValidators: true }
//         ).select("-password -emailOTP -phoneOTP");

//         if (!updatedUser) {
//             return res.status(404).json({
//                 message: "User not found after update",
//                 success: false
//             });
//         }

//         // Format response with all fields
//         const formattedUser = {
//             _id: updatedUser._id,
//             fullName: updatedUser.fullName,
//             email: updatedUser.email,
//             phoneNumber: updatedUser.phoneNumber,
//             age: updatedUser.age,
//             gender: updatedUser.gender,
//             role: updatedUser.role,
//             profilePhoto: updatedUser.profilePhoto,
//             isActive: updatedUser.isActive,
//             profileCompleted: updatedUser.profileCompleted,
//             createdAt: updatedUser.createdAt,
//             updatedAt: updatedUser.updatedAt,

//             // Patient profile fields
//             dateOfBirth: updatedUser.dateOfBirth ? new Date(updatedUser.dateOfBirth).toISOString().split('T')[0] : null,
//             bloodGroup: updatedUser.bloodGroup,
//             address: updatedUser.address,
//             emergencyContact: updatedUser.emergencyContact,
//             medicalInfo: updatedUser.medicalInfo,
//             insuranceInfo: updatedUser.insuranceInfo
//         };

//         // Add counsellor fields if role is counsellor
//         if (updatedUser.role === "counsellor") {
//             formattedUser.qualification = updatedUser.qualification;
//             formattedUser.specialization = updatedUser.specialization;
//             formattedUser.experience = updatedUser.experience;
//             formattedUser.location = updatedUser.location;
//             formattedUser.consultationMode = updatedUser.consultationMode;
//             formattedUser.languages = updatedUser.languages;
//             formattedUser.aboutMe = updatedUser.aboutMe;
//             formattedUser.education = updatedUser.education;
//             formattedUser.certifications = updatedUser.certifications;
//             formattedUser.rating = updatedUser.rating;
//             formattedUser.totalSessions = updatedUser.totalSessions;
//             formattedUser.activeClients = updatedUser.activeClients;
//             formattedUser.uniqueCode = updatedUser.uniqueCode;
//         }

//         return res.status(200).json({
//             message: "User updated successfully",
//             success: true,
//             user: formattedUser
//         });

//     } catch (error) {
//         console.error("Update user by ID error:", error);
//         if (req.file) deleteLocalFile(saveLocalFile(req.file));
//         return res.status(500).json({
//             message: "Error updating user",
//             success: false,
//             error: error.message
//         });
//     }
// };

// controllers/authController.js
// export const updateUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             // If file was uploaded to Cloudinary and user doesn't exist, delete it
//             if (req.file && req.file.filename) {
//                 await cloudinary.uploader.destroy(req.file.filename);
//             }
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         // Format certifications from form data (arrays) to array of objects
//         const formattedCertifications = formatCertifications(req.body);

//         // Base allowed updates for ALL users
//         let allowedUpdates = [
//             'fullName', 'anonymous', 'phoneNumber', 'age', 'gender', 'role',
//             // Patient profile fields
//             'dateOfBirth', 'bloodGroup',
//             'address', 'emergencyContact', 'medicalInfo', 'insuranceInfo',
//             // Account status
//             'isActive', 'isVerified', 'profileCompleted'
//         ];

//         // Add counsellor-specific fields ONLY if user is counsellor
//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push(
//                 'qualification', 'specialization', 'experience',
//                 'location', 'consultationMode', 'languages', 'aboutMe',
//                 'education', 'rating', 'totalSessions', 'activeClients'
//             );
//         }

//         // Prepare updates object
//         const updates = {};

//         // Process each allowed field
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") {
//                 updates[field] = req.body[field];
//             }
//         });

//         // Add formatted certifications
//         if (formattedCertifications && formattedCertifications.length > 0) {
//             updates.certifications = formattedCertifications;
//         } else if (req.body.certifications === null || req.body.certifications === "") {
//             updates.certifications = [];
//         }

//         // Handle nested objects (address, emergencyContact, medicalInfo, insuranceInfo)
//         if (req.body.address && typeof req.body.address === 'object' && !Array.isArray(req.body.address)) {
//             updates.address = {
//                 line1: req.body.address.line1 || currentUser.address?.line1 || "",
//                 line2: req.body.address.line2 || currentUser.address?.line2 || "",
//                 city: req.body.address.city || currentUser.address?.city || "",
//                 state: req.body.address.state || currentUser.address?.state || "",
//                 pincode: req.body.address.pincode || currentUser.address?.pincode || "",
//                 country: req.body.address.country || currentUser.address?.country || "India"
//             };
//         }

//         if (req.body.emergencyContact && typeof req.body.emergencyContact === 'object' && !Array.isArray(req.body.emergencyContact)) {
//             updates.emergencyContact = {
//                 name: req.body.emergencyContact.name || currentUser.emergencyContact?.name || "",
//                 relation: req.body.emergencyContact.relation || currentUser.emergencyContact?.relation || "",
//                 phone: req.body.emergencyContact.phone || currentUser.emergencyContact?.phone || ""
//             };
//         }

//         if (req.body.medicalInfo && typeof req.body.medicalInfo === 'object' && !Array.isArray(req.body.medicalInfo)) {
//             updates.medicalInfo = {
//                 height: req.body.medicalInfo.height || currentUser.medicalInfo?.height || "",
//                 weight: req.body.medicalInfo.weight || currentUser.medicalInfo?.weight || "",
//                 allergies: Array.isArray(req.body.medicalInfo.allergies) ? req.body.medicalInfo.allergies :
//                            (req.body.medicalInfo.allergies ? [req.body.medicalInfo.allergies] : []),
//                 chronicConditions: Array.isArray(req.body.medicalInfo.chronicConditions) ? req.body.medicalInfo.chronicConditions :
//                                    (req.body.medicalInfo.chronicConditions ? [req.body.medicalInfo.chronicConditions] : []),
//                 currentMedications: Array.isArray(req.body.medicalInfo.currentMedications) ? req.body.medicalInfo.currentMedications :
//                                     (req.body.medicalInfo.currentMedications ? [req.body.medicalInfo.currentMedications] : [])
//             };
//         }

//         if (req.body.insuranceInfo && typeof req.body.insuranceInfo === 'object' && !Array.isArray(req.body.insuranceInfo)) {
//             updates.insuranceInfo = {
//                 provider: req.body.insuranceInfo.provider || currentUser.insuranceInfo?.provider || "",
//                 policyNumber: req.body.insuranceInfo.policyNumber || currentUser.insuranceInfo?.policyNumber || "",
//                 groupNumber: req.body.insuranceInfo.groupNumber || currentUser.insuranceInfo?.groupNumber || "",
//                 coverageAmount: req.body.insuranceInfo.coverageAmount || currentUser.insuranceInfo?.coverageAmount || "",
//                 validityDate: req.body.insuranceInfo.validityDate || currentUser.insuranceInfo?.validityDate || null,
//                 nominee: req.body.insuranceInfo.nominee || currentUser.insuranceInfo?.nominee || "",
//                 relationship: req.body.insuranceInfo.relationship || currentUser.insuranceInfo?.relationship || "",
//                 insuranceType: req.body.insuranceInfo.insuranceType || currentUser.insuranceInfo?.insuranceType || ""
//             };
//         }

//         // Handle counsellor-specific array fields (convert from string to array if needed)
//         if (currentUser.role === "counsellor") {
//             // Handle specialization
//             if (req.body.specialization) {
//                 if (typeof req.body.specialization === 'string') {
//                     try {
//                         const parsed = JSON.parse(req.body.specialization);
//                         updates.specialization = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         updates.specialization = req.body.specialization.split(',').map(s => s.trim()).filter(s => s);
//                     }
//                 } else if (Array.isArray(req.body.specialization)) {
//                     updates.specialization = req.body.specialization;
//                 }
//             }

//             // Handle languages
//             if (req.body.languages) {
//                 if (typeof req.body.languages === 'string') {
//                     try {
//                         const parsed = JSON.parse(req.body.languages);
//                         updates.languages = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         updates.languages = req.body.languages.split(',').map(l => l.trim()).filter(l => l);
//                     }
//                 } else if (Array.isArray(req.body.languages)) {
//                     updates.languages = req.body.languages;
//                 }
//             }

//             // Handle consultationMode
//             if (req.body.consultationMode) {
//                 if (typeof req.body.consultationMode === 'string') {
//                     try {
//                         const parsed = JSON.parse(req.body.consultationMode);
//                         updates.consultationMode = Array.isArray(parsed) ? parsed : [parsed];
//                     } catch (e) {
//                         updates.consultationMode = req.body.consultationMode.split(',').map(m => m.trim()).filter(m => m);
//                     }
//                 } else if (Array.isArray(req.body.consultationMode)) {
//                     updates.consultationMode = req.body.consultationMode;
//                 }
//             }
//         }

//         // Handle profile photo upload with Cloudinary
//         if (req.file) {
//             // req.file contains Cloudinary data when using multer-storage-cloudinary
//             // req.file.path = Cloudinary URL
//             // req.file.filename = Cloudinary public ID

//             // Delete old photo from Cloudinary if exists
//             if (currentUser.profilePhoto && currentUser.profilePhoto.publicId) {
//                 try {
//                     await cloudinary.uploader.destroy(currentUser.profilePhoto.publicId);
//                     console.log(`Deleted old profile photo: ${currentUser.profilePhoto.publicId}`);
//                 } catch (deleteError) {
//                     console.error("Error deleting old photo from Cloudinary:", deleteError);
//                     // Continue with update even if deletion fails
//                 }
//             }

//             // Save new Cloudinary photo info
//             updates.profilePhoto = {
//                 url: req.file.path,
//                 publicId: req.file.filename,
//                 format: req.file.format || null,
//                 bytes: req.file.bytes || null
//             };
//         }

//         // Validate phone number if being updated
//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             // If there was a new photo uploaded, delete it since update failed
//             if (req.file && req.file.filename) {
//                 await cloudinary.uploader.destroy(req.file.filename);
//             }
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Update the user
//         const updatedUser = await User.findByIdAndUpdate(
//             userId,
//             updates,
//             { new: true, runValidators: true }
//         ).select("-password -emailOTP -phoneOTP");

//         if (!updatedUser) {
//             // If user not found after update, delete any newly uploaded photo
//             if (req.file && req.file.filename) {
//                 await cloudinary.uploader.destroy(req.file.filename);
//             }
//             return res.status(404).json({
//                 message: "User not found after update",
//                 success: false
//             });
//         }

//         // Format response with all fields
//         const formattedUser = {
//             _id: updatedUser._id,
//             fullName: updatedUser.fullName,
//             email: updatedUser.email,
//             phoneNumber: updatedUser.phoneNumber,
//             age: updatedUser.age,
//             gender: updatedUser.gender,
//             role: updatedUser.role,
//             profilePhoto: updatedUser.profilePhoto,
//             isActive: updatedUser.isActive,
//             profileCompleted: updatedUser.profileCompleted,
//             createdAt: updatedUser.createdAt,
//             updatedAt: updatedUser.updatedAt,

//             // Patient profile fields
//             dateOfBirth: updatedUser.dateOfBirth ? new Date(updatedUser.dateOfBirth).toISOString().split('T')[0] : null,
//             bloodGroup: updatedUser.bloodGroup,
//             address: updatedUser.address,
//             emergencyContact: updatedUser.emergencyContact,
//             medicalInfo: updatedUser.medicalInfo,
//             insuranceInfo: updatedUser.insuranceInfo
//         };

//         // Add counsellor fields if role is counsellor
//         if (updatedUser.role === "counsellor") {
//             formattedUser.qualification = updatedUser.qualification;
//             formattedUser.specialization = updatedUser.specialization;
//             formattedUser.experience = updatedUser.experience;
//             formattedUser.location = updatedUser.location;
//             formattedUser.consultationMode = updatedUser.consultationMode;
//             formattedUser.languages = updatedUser.languages;
//             formattedUser.aboutMe = updatedUser.aboutMe;
//             formattedUser.education = updatedUser.education;
//             formattedUser.certifications = updatedUser.certifications;
//             formattedUser.rating = updatedUser.rating;
//             formattedUser.totalSessions = updatedUser.totalSessions;
//             formattedUser.activeClients = updatedUser.activeClients;
//             formattedUser.uniqueCode = updatedUser.uniqueCode;
//         }

//         return res.status(200).json({
//             message: "User updated successfully",
//             success: true,
//             user: formattedUser
//         });

//     } catch (error) {
//         console.error("Update user by ID error:", error);

//         // Rollback: If there was a new photo uploaded and an error occurred, delete it
//         if (req.file && req.file.filename) {
//             try {
//                 await cloudinary.uploader.destroy(req.file.filename);
//                 console.log(`Rollback: Deleted uploaded photo ${req.file.filename}`);
//             } catch (deleteError) {
//                 console.error("Error rolling back photo upload:", deleteError);
//             }
//         }

//         return res.status(500).json({
//             message: "Error updating user",
//             success: false,
//             error: error.message
//         });
//     }
// };

// ================= UPDATE USER (Enhanced with All Fields) =================
// export const updateUser = async (req, res) => {
//     try {
//         const userId = req.user?._id || req.userId;
//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(404).json({
//                 message: "User not found",
//                 success: false
//             });
//         }

//         // Base allowed updates for ALL users (both user and counsellor)
//         let allowedUpdates = [
//             'fullName', 'anonymous', 'phoneNumber', 'age', 'gender',
//             // New patient profile fields - available for both roles
//             'dateOfBirth', 'bloodGroup',
//             'address', 'emergencyContact', 'medicalInfo', 'insuranceInfo'
//         ];

//         // Add counsellor-specific fields ONLY if user is counsellor
//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push(
//                 'qualification', 'specialization', 'experience',
//                 'location', 'consultationMode', 'languages', 'aboutMe'
//             );
//         }

//         // Prepare updates object
//         const updates = {};

//         // Process each allowed field
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") {
//                 updates[field] = req.body[field];
//             }
//         });

//         // Handle nested objects specially (address, emergencyContact, medicalInfo, insuranceInfo)
//         // These come as objects from frontend, we need to merge them properly
//         if (req.body.address && typeof req.body.address === 'object') {
//             updates.address = {
//                 line1: req.body.address.line1 || currentUser.address?.line1 || "",
//                 line2: req.body.address.line2 || currentUser.address?.line2 || "",
//                 city: req.body.address.city || currentUser.address?.city || "",
//                 state: req.body.address.state || currentUser.address?.state || "",
//                 pincode: req.body.address.pincode || currentUser.address?.pincode || "",
//                 country: req.body.address.country || currentUser.address?.country || "India"
//             };
//         }

//         if (req.body.emergencyContact && typeof req.body.emergencyContact === 'object') {
//             updates.emergencyContact = {
//                 name: req.body.emergencyContact.name || currentUser.emergencyContact?.name || "",
//                 relation: req.body.emergencyContact.relation || currentUser.emergencyContact?.relation || "",
//                 phone: req.body.emergencyContact.phone || currentUser.emergencyContact?.phone || ""
//             };
//         }

//         if (req.body.medicalInfo && typeof req.body.medicalInfo === 'object') {
//             updates.medicalInfo = {
//                 height: req.body.medicalInfo.height || currentUser.medicalInfo?.height || "",
//                 weight: req.body.medicalInfo.weight || currentUser.medicalInfo?.weight || "",
//                 allergies: req.body.medicalInfo.allergies || currentUser.medicalInfo?.allergies || [],
//                 chronicConditions: req.body.medicalInfo.chronicConditions || currentUser.medicalInfo?.chronicConditions || [],
//                 currentMedications: req.body.medicalInfo.currentMedications || currentUser.medicalInfo?.currentMedications || []
//             };
//         }

//         if (req.body.insuranceInfo && typeof req.body.insuranceInfo === 'object') {
//             updates.insuranceInfo = {
//                 provider: req.body.insuranceInfo.provider || currentUser.insuranceInfo?.provider || "",
//                 policyNumber: req.body.insuranceInfo.policyNumber || currentUser.insuranceInfo?.policyNumber || "",
//                 groupNumber: req.body.insuranceInfo.groupNumber || currentUser.insuranceInfo?.groupNumber || "",
//                 coverageAmount: req.body.insuranceInfo.coverageAmount || currentUser.insuranceInfo?.coverageAmount || "",
//                 validityDate: req.body.insuranceInfo.validityDate || currentUser.insuranceInfo?.validityDate || null,
//                 nominee: req.body.insuranceInfo.nominee || currentUser.insuranceInfo?.nominee || "",
//                 relationship: req.body.insuranceInfo.relationship || currentUser.insuranceInfo?.relationship || "",
//                 insuranceType: req.body.insuranceInfo.insuranceType || currentUser.insuranceInfo?.insuranceType || ""
//             };
//         }

//         // Handle profile photo upload (only for counsellors as per your original logic)
//         if (req.file) {
//             if (currentUser.role !== "counsellor") {
//                 deleteLocalFile(saveLocalFile(req.file));
//                 return res.status(403).json({
//                     message: "Only counsellors can upload photos",
//                     success: false
//                 });
//             }
//             if (currentUser.profilePhoto) deleteLocalFile(currentUser.profilePhoto);
//             updates.profilePhoto = saveLocalFile(req.file);
//         }

//         // Validate phone number if being updated
//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(400).json({
//                 message: "Phone number must be 10 digits",
//                 success: false
//             });
//         }

//         // Update the user
//         const updatedUser = await User.findByIdAndUpdate(
//             userId,
//             updates,
//             { new: true, runValidators: true }
//         ).select("-password -emailOTP -phoneOTP");

//         // Format response with all fields
//         const formattedUser = {
//             _id: updatedUser._id,
//             fullName: updatedUser.fullName,
//             email: updatedUser.email,
//             phoneNumber: updatedUser.phoneNumber,
//             age: updatedUser.age,
//             gender: updatedUser.gender,
//             role: updatedUser.role,
//             profilePhoto: updatedUser.profilePhoto,
//             isActive: updatedUser.isActive,
//             profileCompleted: updatedUser.profileCompleted,

//             // New patient profile fields
//             dateOfBirth: updatedUser.dateOfBirth ? new Date(updatedUser.dateOfBirth).toISOString().split('T')[0] : null,
//             bloodGroup: updatedUser.bloodGroup,
//             address: updatedUser.address,
//             emergencyContact: updatedUser.emergencyContact,
//             medicalInfo: updatedUser.medicalInfo,
//             insuranceInfo: updatedUser.insuranceInfo
//         };

//         // Add counsellor fields if role is counsellor
//         if (updatedUser.role === "counsellor") {
//             formattedUser.qualification = updatedUser.qualification;
//             formattedUser.specialization = updatedUser.specialization;
//             formattedUser.experience = updatedUser.experience;
//             formattedUser.location = updatedUser.location;
//             formattedUser.consultationMode = updatedUser.consultationMode;
//             formattedUser.languages = updatedUser.languages;
//             formattedUser.aboutMe = updatedUser.aboutMe;
//         }

//         return res.status(200).json({
//             message: "Profile updated successfully",
//             success: true,
//             user: formattedUser
//         });

//     } catch (error) {
//         console.error("Update error:", error);
//         if (req.file) deleteLocalFile(saveLocalFile(req.file));
//         return res.status(500).json({
//             message: "Error updating profile",
//             success: false,
//             error: error.message
//         });
//     }
// };

// ================= UPLOAD PROFILE PHOTO =================
export const uploadProfilePhoto = async (req, res) => {
  try {
    const userId = req.user?._id || req.userId;
    const currentUser = await User.findById(userId);

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
        success: false,
      });
    }

    // Only counsellors can upload photos (as per your original logic)
    if (currentUser.role !== "counsellor") {
      if (req.file) deleteLocalFile(saveLocalFile(req.file));
      return res.status(403).json({
        message: "Only counsellors can upload photos",
        success: false,
      });
    }

    if (!req.file) {
      return res.status(400).json({
        message: "No file uploaded",
        success: false,
      });
    }

    // Delete old photo if exists
    if (currentUser.profilePhoto) {
      deleteLocalFile(currentUser.profilePhoto);
    }

    // Save new photo
    const photoPath = saveLocalFile(req.file);

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: { profilePhoto: photoPath } },
      { new: true },
    ).select("-password");

    return res.status(200).json({
      message: "Profile photo updated successfully",
      success: true,
      profilePhoto: photoPath,
      user: updatedUser.toJSON(),
    });
  } catch (error) {
    console.error("Photo upload error:", error);
    if (req.file) deleteLocalFile(saveLocalFile(req.file));
    return res.status(500).json({
      message: "Error uploading photo",
      success: false,
      error: error.message,
    });
  }
};
// export const getMyProfile = async (req, res) => {
//     try {
//         const userId = req.userId || req.user?._id;
//         const user = await User.findById(userId).select("-password");

//         if (!user) {
//             return res.status(404).json({ message: "User not found", success: false });
//         }

//         return res.status(200).json({ message: "Profile fetched successfully", success: true, user: user.toJSON() });
//     } catch (error) {
//         console.log("Get profile error:", error);
//         return res.status(500).json({ message: "Error fetching profile", success: false });
//     }
// };

// // ================= UPDATE USER =================
// export const updateUser = async (req, res) => {
//     try {
//         const userId = req.user?._id || req.userId;
//         const currentUser = await User.findById(userId);

//         if (!currentUser) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(404).json({ message: "User not found", success: false });
//         }

//         let allowedUpdates = ['fullName', 'anonymous', 'phoneNumber', 'age', 'gender'];

//         if (currentUser.role === "counsellor") {
//             allowedUpdates.push('qualification', 'specialization', 'experience', 'location', 'consultationMode', 'languages', 'aboutMe');
//         }

//         const updates = {};
//         allowedUpdates.forEach(field => {
//             if (req.body[field] !== undefined && req.body[field] !== "") updates[field] = req.body[field];
//         });

//         if (req.file) {
//             if (currentUser.role !== "counsellor") {
//                 deleteLocalFile(saveLocalFile(req.file));
//                 return res.status(403).json({ message: "Only counsellors can upload photos", success: false });
//             }
//             if (currentUser.profilePhoto) deleteLocalFile(currentUser.profilePhoto);
//             updates.profilePhoto = saveLocalFile(req.file);
//         }

//         if (updates.phoneNumber && updates.phoneNumber.length !== 10) {
//             if (req.file) deleteLocalFile(saveLocalFile(req.file));
//             return res.status(400).json({ message: "Phone number must be 10 digits", success: false });
//         }

//         const updatedUser = await User.findByIdAndUpdate(userId, updates, { new: true }).select("-password");

//         return res.status(200).json({ message: "Profile updated successfully", success: true, user: updatedUser.toJSON() });
//     } catch (error) {
//         console.error("Update error:", error);
//         if (req.file) deleteLocalFile(saveLocalFile(req.file));
//         return res.status(500).json({ message: "Error updating profile", success: false });
//     }
// };

// ================= FORGOT PASSWORD =================
export const forgotPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "No account found with this email" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
    await user.save();

    const resetUrl = `${req.protocol}://${req.get("host")}/reset-password/${resetToken}`;

    try {
      await sendResetPasswordEmail(user.email, resetUrl, user.fullName);
    } catch (emailError) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      return res
        .status(500)
        .json({ success: false, message: "Error sending reset email" });
    }

    res
      .status(200)
      .json({
        success: true,
        message: "Password reset instructions sent to your email",
      });
  } catch (error) {
    console.error("Forgot password error:", error);
    res
      .status(500)
      .json({ success: false, message: "Error processing request" });
  }
};

// ================= RESET PASSWORD =================
export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Passwords do not match" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Password must be at least 6 characters",
        });
    }

    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired reset token" });
    }

    const isSamePassword = await bcrypt.compare(password, user.password);
    if (isSamePassword) {
      return res
        .status(400)
        .json({
          success: false,
          message: "New password cannot be the same as old password",
        });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    await Session.updateMany(
      { userId: user._id, isActive: true },
      { isActive: false, logoutAt: new Date() },
    );

    res
      .status(200)
      .json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res
      .status(500)
      .json({ success: false, message: "Error resetting password" });
  }
};

// ================= HELPER FUNCTIONS =================
export const registerUserOnly = async (req, res) => {
  return res.status(400).json({
    message: "Please use the new registration flow",
    success: false,
    instructions: {
      step1: "POST /api/auth/send-email-otp",
      step2: "POST /api/auth/verify-email-otp",
      step3: "POST /api/auth/send-phone-otp",
      step4: "POST /api/auth/verify-phone-otp",
      step5: "POST /api/auth/complete-registration",
    },
  });
};

export const registerCounsellor = async (req, res) => {
  return res.status(400).json({
    message: "Please use the new registration flow",
    success: false,
    instructions: {
      step1: "POST /api/auth/send-email-otp",
      step2: "POST /api/auth/verify-email-otp",
      step3: "POST /api/auth/send-phone-otp",
      step4: "POST /api/auth/verify-phone-otp",
      step5: "POST /api/auth/complete-registration with counsellor fields",
    },
  });
};

export const getAlluser = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    return res
      .status(200)
      .json({
        message: "Got all users",
        success: true,
        users,
        count: users.length,
      });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Error getting users", success: false });
  }
};

export const getUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select("-password");
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    return res
      .status(200)
      .json({
        message: "User fetched successfully",
        success: true,
        user: user.toJSON(),
      });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Error fetching user", success: false });
  }
};

export const deleteUser = async (req, res) => {
  try {
    const { id } = req.body;
    const user = await User.findById(id);
    if (!user)
      return res
        .status(404)
        .json({ message: "User not found", success: false });
    if (user.profilePhoto) deleteLocalFile(user.profilePhoto);
    await Session.deleteMany({ userId: id });
    await User.findByIdAndDelete(id);
    return res
      .status(200)
      .json({ message: "User deleted successfully", success: true });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Error deleting user", success: false });
  }
};

export const checkRegistrationStatus = async (req, res) => {
  try {
    const { email } = req.params;
    const userVerification = verifiedUsersStore.get(email);

    if (!userVerification) {
      return res
        .status(404)
        .json({
          success: false,
          exists: false,
          message: "No active registration session",
        });
    }

    return res.status(200).json({
      success: true,
      exists: true,
      email: email,
      isEmailVerified: userVerification.isEmailVerified,
      isPhoneVerified: userVerification.isPhoneVerified,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Error checking status" });
  }
};

export const resendEmailOTP = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ message: "Email required", success: false });

    const userVerification = verifiedUsersStore.get(email);
    if (!userVerification)
      return res
        .status(404)
        .json({ message: "No pending verification", success: false });

    const otp = otpService.generateOTP();
    await otpService.sendEmailOTP(email, otp, "User");

    emailOTPStore.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

    return res
      .status(200)
      .json({ message: "Email OTP resent successfully", success: true });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Error resending OTP", success: false });
  }
};

export const resendPhoneOTP = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ message: "Email required", success: false });

    const userVerification = verifiedUsersStore.get(email);
    if (!userVerification || !userVerification.phoneNumber) {
      return res
        .status(404)
        .json({ message: "No phone number found", success: false });
    }

    const otp = otpService.generateOTP();
    const formattedPhone = `+91${userVerification.phoneNumber}`;

    await twilioClient.messages.create({
      body: `Your verification code is: ${otp}. This code will expire in 10 minutes.`,
      from: TWILIO_PHONE_NUMBER,
      to: formattedPhone,
    });

    phoneOTPStore.set(email, {
      otp,
      phoneNumber: userVerification.phoneNumber,
      formattedPhone,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    return res
      .status(200)
      .json({ message: "Phone OTP resent successfully", success: true });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Error resending phone OTP", success: false });
  }
};

// Aliases
export const refreshAccessTokenHandler = refreshAccessToken;
export const resendOTPS = resendEmailOTP;
export const checkVerificationStatus = checkRegistrationStatus;
