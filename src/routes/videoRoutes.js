// videoCallRoutes.js
import express from "express";
import { videoCallController } from "../controllers/videoCallController.js";

const router = express.Router();

// Call Request Management
router.post("/calls/initiate", videoCallController.initiateCall);
router.get("/calls/pending/:userId", videoCallController.getPendingRequests);
router.put("/calls/:callId/accept", videoCallController.acceptCall);
router.put("/calls/:callId/reject", videoCallController.rejectCall);
router.post("/calls/:callId/resend", videoCallController.resendCallRequest);

// Call Management
router.post("/calls/:callId/join", videoCallController.joinCall);
router.put("/calls/:callId/end", videoCallController.endCall);

// History & Status
router.get("/calls/history/:userId", videoCallController.getCallHistory);
router.get("/calls/active/:userId", videoCallController.getActiveCalls);
router.get("/calls/:callId/details", videoCallController.getCallDetails);

// User Status
router.put("/users/status", videoCallController.updateUserStatus);
router.get("/users/status/:userId", videoCallController.getUserStatus);

// Utility endpoints
router.get("/calls/pending/all", videoCallController.getAllPendingCalls);
router.get("/calls/all", videoCallController.getAllCalls);

export default router;
