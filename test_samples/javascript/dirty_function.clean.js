/**
 * Dirty JavaScript - contains unused functions and dead code.
 * These functions should be removed by UnusedFunctionRule.
 */

function helperUnused() {
    return "this function is never called";
}

// This one IS used
function formatData(data) {
    return data.toString().trim();
}

// Never called anywhere
function deepThought() {
    return 42;
}

// Entry point - should be preserved
function main() {
    const value = processData("hello");
    console.log(formatData(value));
}

// IS used
function processData(input) {
    return input.toUpperCase();
}

// Exported - should be preserved
export function getConfig() {
    return { debug: false };
}

// Exported but NOT used in this file - should still be preserved
export function setConfig(cfg) {
    return cfg;
}

// Unused private function - should be removed
function internalHelper() {
    return Math.random();
}

main();
