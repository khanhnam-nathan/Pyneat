/**
 * TypeScript service class demo
 */

class UserService {
    // Hardcoded secrets - should trigger UNI-001
    private readonly API_URL = "https://api.example.com/v1";
    private readonly DB_PASSWORD = "MySecretPass123!";  // TODO: env var
    private readonly AWS_KEY = "AKIAIOSFODNN7EXAMPLE";  // FIXME: rotate key
    private readonly AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    // Deep nesting - should trigger UNI-005
    validateUser(user: any): boolean {
        if (user) {
            if (user.name) {
                if (user.name.length > 0) {
                    if (user.email) {
                        if (user.email.includes("@")) {
                            if (user.email !== "") {
                                console.log("Validating user:", user.email);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    // Debug statements - should trigger UNI-002
    async fetchUser(id: string): Promise<any> {
        console.log("Fetching user:", id);
        console.log("API_URL:", this.API_URL);
        debugger;
        try {
            const response = await fetch(`${this.API_URL}/users/${id}`);
            // Empty catch - should trigger UNI-003
        } catch (e) {
            // do nothing
        }
        return response.json();
    }
}

export const userService = new UserService();
