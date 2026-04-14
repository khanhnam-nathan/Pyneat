// Dirty Java - contains unused methods

public class DirtyService {
    public int unusedHelper() {
        return 123;
    }

    public String formatData(String data) {
        return data.trim();
    }

    public static void main(String[] args) {
        DirtyService svc = new DirtyService();
        String val = svc.processValue("hello");
        System.out.println(svc.formatData(val));
    }

    public String processValue(String input) {
        return input.toUpperCase();
    }

    public int deepThought() {
        return 42;
    }

    public static int getConfig() {
        return 0;
    }
}
