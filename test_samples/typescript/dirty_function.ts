// Dirty TypeScript - contains unused functions

function helperUnused(): string {
    return "never called";
}

function formatData(data: string): string {
    return data.trim();
}

function main(): void {
    const val = processValue("hello");
    console.log(formatData(val));
}

function processValue(input: string): string {
    return input.toUpperCase();
}

function deepThought(): number {
    return 42;
}

export function getConfig(): object {
    return { debug: false };
}

export function setConfig(cfg: object): object {
    return cfg;
}

main();
