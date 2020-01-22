package com.ibm.mobilefirstplatform.serversdk.java.push;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

/**
 * Klasse bietet statische Methoden zum Parsing von Zahlen.
 * 
 * @author David Garcia
 * @version 1.0, 11-01-12
 */
public class NumberParser {

    /** stat. Member: Zahleformatierer für Deutsche Beträge */
    static DecimalFormat germanDF;
    
    /**
     * stat. Konstruktor baut Zahlenformatierer
     */
    static{
        germanDF = new DecimalFormat( "0.00", DecimalFormatSymbols.getInstance( Locale.GERMANY ) );
    }
    
    /**
     * Double Wert zu String in deutscher Notation erzeugen
     * @param dbl Double Wert
     * @return Wert als String
     */
    public static String formatGermanDouble( double dbl ){
        return germanDF.format(dbl);
    }
    
    
    
    
    /**
     * Eine long-Zahl als String zu long parsen
     * @param longStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return long Zahl
     */
    public static long parseLong(String longStr, long defVal) {
        try {
            return Long.parseLong(longStr);
        } catch (Exception ex) {
            return defVal;
        }
    }

    /**
     * Eine byte-Zahl als String zu byte parsen
     * @param byteStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return byte Zahl
     */
    public static byte parseByte(String byteStr, byte defVal) {
        try {
            return Byte.parseByte(byteStr);
        } catch (Exception ex) {
            return defVal;
        }
    }

    /**
     * Eine integer-Zahl als String zu integer parsen
     * @param intStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return int Zahl
     */
    public static int parseInt(String intStr, int defVal) {
        try {
            return Integer.parseInt(intStr);
        } catch (Exception ex) {
            return defVal;
        }
    }

    /**
     * Eine hex-Zahl als String zu integer parsen
     * @param intStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return int Zahl
     */
    public static int parseIntHex(String intStr, int defVal) {
        try {
            return Integer.parseInt(intStr, 16);
        } catch (Exception ex) {
            return defVal;
        }
    }

    /**
     * Eine double-Zahl als String zu double parsen
     * @param dblStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return double Zahl
     */
    public static double parseDouble(String dblStr, double defVal) {
        try {
            return Double.parseDouble(dblStr);
        } catch (Exception ex) {
            return defVal;
        }
    }

    /**
     * Eine boolean-Angabe als String zu boolean parsen
     * @param boolStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @return boolean Wert
     */
    public static boolean parseBooleanStr(String boolStr, boolean defVal) {

        if (boolStr == null) {
            return defVal;
        }

        if (boolStr.toLowerCase().equals("true")) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Eine double-Zahl als String zu double parsen, auch für deutsche Notation geeignet
     * @param dblStr Zahlenwert
     * @param defVal Defaultrückgabewert, falls parsing nicht möglich
     * @param deutscheNotation Flag: Liegt eine deutsche Notation vor?
     * @return double Zahl
     */
    public static double parseDouble(String dblStr, double defVal, boolean deutscheNotation) {
        try {

            if (deutscheNotation) {
                dblStr = dblStr.replace(',', '.'); // DezSeparator wechseln
            }
            return Double.parseDouble(dblStr);
        } catch (Exception ex) {
            return defVal;
        }
    }
}
