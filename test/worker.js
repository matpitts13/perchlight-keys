// The Worker under test, built around the tests' config.
import { makeWorker } from "../src/app.js";
import { TEST_CONFIG } from "./config.js";

export default makeWorker(TEST_CONFIG);
