import { Router, type IRouter } from "express";
import healthRouter from "./health";
import osintRouter from "./osint";
import historyRouter from "./history";

const router: IRouter = Router();

router.use(healthRouter);
router.use(osintRouter);
router.use(historyRouter);

export default router;
