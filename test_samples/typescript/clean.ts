// Clean TypeScript test file - no issues expected

export function add(a: number, b: number): number {
    return a + b;
}

export function multiply(x: number, y: number): number {
    return x * y;
}

function main(): void {
    const result = calculate(3, 4);
    console.log('Result:', result);
}

function calculate(a: number, b: number): number {
    return add(a, b) * multiply(a, b);
}

main();
