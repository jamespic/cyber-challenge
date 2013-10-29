import java.sql.*;

public class VulnerableApp {
    public static void main(String[] args) throws SQLException {
        new VulnerableApp().doMain(args);
    }
    public void doMain(String[] args) throws SQLException{
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        stmt.execute("select * from Users where user = '" + args[0] + "' and userid = " + Integer.parseInt(args[1]));
    }
    
    public Connection getConnection() {
        throw new UnsupportedOperationException();
    }
    
    public void safeExecute() throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        stmt.execute("select count(*) from Users");
    }
}
