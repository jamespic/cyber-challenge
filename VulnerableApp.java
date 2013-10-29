import java.sql.*;

public class VulnerableApp {
    private Connection conn;
    
    public static void main(String[] args) throws Exception {
        new VulnerableApp().doMain(args);
    }
    public void doMain(String[] args) throws Exception {
        Connection conn = getConnection();
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery("select count(*) from AppUsers where username = '" + args[0] + "' and userid = " + Integer.parseInt(args[1]));
            rs.next();
            System.out.println("selected " + rs.getInt(1) + " AppUsers");
        } catch(SQLException e) {
            System.out.println("Exeption thrown, possible SQL injection?");
            e.printStackTrace();
        }
        printAppUsers();
    }
    
    public Connection getConnection() throws Exception {
        if (conn == null) {
            Class.forName("org.hsqldb.jdbcDriver");
            conn = DriverManager.getConnection("jdbc:hsqldb:mem:mydb", "sa", "");
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("create table AppUsers(username varchar(40), userid int, password varchar(10));");
                stmt.executeUpdate("insert into AppUsers(username, userid, password) values('admin',0,'password');");
                conn.commit();
            } 
        }
        return conn;
    }
    
    public void printAppUsers() throws Exception {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("select username, userid, password from AppUsers");
        System.out.println(padRight("Username", 40) + " Userid " + padRight("Password", 10));
        int count = 0;
        while (rs.next()) {
            System.out.println(padRight(rs.getString(1), 40) + " " + padRight(rs.getString(2), 6) +" " + padRight(rs.getString(3), 10));
            count++;
        }
        if (count > 1) {
            System.out.println("System compromised! SQL Injection successful!");
        }
    }
    
    public static String padRight(String s, int n) {
        return String.format("%1$-" + n + "s", s);  
    }
}
