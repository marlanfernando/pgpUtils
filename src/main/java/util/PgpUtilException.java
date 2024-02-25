package util;

public class PgpUtilException extends Exception{

    public PgpUtilException(String message) {
        super(message);
    }

    PgpUtilException(String message, Throwable t) {
        super(message, t);
    }

}
