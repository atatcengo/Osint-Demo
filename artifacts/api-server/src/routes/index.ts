import { Router, type IRouter } from "express";
import healthRouter from "./health";
import osintRouter from "./osint";

const router: IRouter = Router();

router.use(healthRouter);
router.use(osintRouter);

export default router;
