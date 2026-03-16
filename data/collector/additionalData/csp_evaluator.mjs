import { CspEvaluator } from "csp_evaluator/dist/evaluator.js";
import { CspParser } from "csp_evaluator/dist/parser.js";

const csp = process.argv[2];
const parsed = new CspParser(csp).csp;
const evaluation = new CspEvaluator(parsed).evaluate();

console.log(JSON.stringify(evaluation));
