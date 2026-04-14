/**
 * Clean JavaScript test file
 * This file contains NO issues - should produce 0 false positives.
 * Used to verify rules don't incorrectly flag clean code.
 */

// Used functions
function add(a, b) {
    return a + b;
}

function multiply(x, y) {
    return x * y;
}

// Exported function (should NOT be removed even if unused in this file)
export function calculate(a, b) {
    return add(a, b) * multiply(a, b);
}

// Entry point (should never be removed)
function main() {
    const result = calculate(3, 4);
    console.log('Result:', result);
}

// This file is clean - no issues expected
main();
