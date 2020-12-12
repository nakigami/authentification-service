package com.glsid.soa.security;

public class JWTUtils {
    public static final String SECRET = "sec_12551_)=)àç$*ù^DffeEE20210ççç";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPRIRE_ACCESS_TOKEN = 2*60*1000;
    public static final long EXPRIRE_REFRESH_TOKEN = 15*60*1000;
}
