// Clean Java test file
// All functions used - no issues expected

public class UserService {
    public int add(int a, int b) {
        return a + b;
    }

    public static void main(String[] args) {
        UserService svc = new UserService();
        int result = svc.calculate(3, 4);
        System.out.println("Result: " + result);
    }

    public int calculate(int a, int b) {
        return add(a, b) * multiply(a, b);
    }

    public int multiply(int x, int y) {
        return x * y;
    }
}
