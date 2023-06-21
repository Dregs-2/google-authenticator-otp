package org.dregs.auth.otp;

public enum MacAlgorithm {

    HmacSHA1("HMAC-SHA-1"),
    HmacSHA256("HMAC-SHA-256"),
    HmacSHA512("HMAC-SHA-512"),
    ;

    MacAlgorithm(String as){
        this.as = as;
    }
    private String as;

    public String as(){
        return this.as;
    }

}
