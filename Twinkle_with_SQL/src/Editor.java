/*
Twinkle with SQL
Distributed under the MIT License
� Copyright Maxim Bortnikov 2021
For more information please visit
https://github.com/Northstrix/Twinkle
Credit:
Implementation of DES by David Simmons was taken from here https://github.com/simmons/desdemo

* Copyright 2011 David Simmons
* http://cafbit.com/
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.

*/
import java.awt.GraphicsEnvironment;
import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.BadLocationException;  
import javax.swing.text.Document;  
import javax.swing.text.SimpleAttributeSet;  
import javax.swing.text.StyleConstants;
import java.io.*;
import java.lang.*;
import java.awt.BorderLayout;  
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;

public class Editor {
    static JMenuBar mb, cm, rm;
    static JMenu m,m1,m2;
    static JMenuItem c, o, s, q, sk,ct,lr,sr,rr;
    static JTextPane pane;
    static JButton select, cancel, rmv, cncl;
    public static class Global {
        public static String X;
        public static int end;
        public static int s;
        public static String stf;
        public static String ck;
        public static int Forward_S_Box[][] = {  
        	    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},  
        	    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},  
        	    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},  
        	    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},  
        	    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},  
        	    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},  
        	    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},  
        	    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},  
        	    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},  
        	    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},  
        	    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},  
        	    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},  
        	    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},  
        	    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},  
        	    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},  
        	    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  
        	};
        
        public static int Inv_S_Box[][] = {  
        	    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},  
        	    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},  
        	    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},  
        	    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},  
        	    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},  
        	    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},  
        	    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},  
        	    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},  
        	    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},  
        	    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},  
        	    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},  
        	    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},  
        	    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},  
        	    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},  
        	    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},  
        	    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  
        	};
    }
    
    public static void cf() {
        
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
        StyleConstants.setFontFamily(attributeSet, Global.X);
        StyleConstants.setFontSize(attributeSet, Global.s);
    	pane.selectAll();
        pane.setCharacterAttributes(attributeSet, true);  
        
        Document doc = pane.getStyledDocument();  
        try {
			doc.insertString(doc.getLength(), "", attributeSet);
		} catch (BadLocationException e1) {
			e1.printStackTrace();
		} 
  
    }
    
    public static void disp_rec(String T) {
        
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
        StyleConstants.setFontFamily(attributeSet, Global.X);
        StyleConstants.setFontSize(attributeSet, Global.s); 
        pane.setCharacterAttributes(attributeSet, true);  
        
        Document doc = pane.getStyledDocument();  
        try {
			doc.insertString(doc.getLength(), T, attributeSet);
		} catch (BadLocationException e1) {
			e1.printStackTrace();
		} 
  
    }
    
    static int split(char ct[], int i){
    		int res = 0;
    	    if(ct[i] != 0 && ct[i+1] != 0)
    	    res = 16*getNum(ct[i])+getNum(ct[i+1]);
    	    if(ct[i] != 0 && ct[i+1] == 0)
    	    res = 16*getNum(ct[i]);
    	    if(ct[i] == 0 && ct[i+1] != 0)
    	    res = getNum(ct[i+1]);
    	    if(ct[i] == 0 && ct[i+1] == 0)
    	    res = 0;
    	    return res;
    	}
    
    static int getNum(char ch)
    {
        int num=0;
        if(ch>='0' && ch<='9')
        {
            num=ch-0x30;
        }
        else
        {
            switch(ch)
            {
                case 'A': case 'a': num=10; break;
                case 'B': case 'b': num=11; break;
                case 'C': case 'c': num=12; break;
                case 'D': case 'd': num=13; break;
                case 'E': case 'e': num=14; break;
                case 'F': case 'f': num=15; break;
                default: num=0;
            }
        }
        return num;
    }
    
    public static void cl(){
    	pane.selectAll();
        pane.replaceSelection("");
    }
    
    private static final byte[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    private static final byte[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    private static final byte[][] S = {{
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    }, {
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    }, {
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    }, {
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    }, {
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    }, {
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    }, {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    }, {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }};

    private static final byte[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private static final byte[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    private static final byte[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    private static final byte[] rotations = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    private static long IP(long src) {
        return permute(IP, 64, src);
    } // 64-bit output

    private static long FP(long src) {
        return permute(FP, 64, src);
    } // 64-bit output

    private static long E(int src) {
        return permute(E, 32, src & 0xFFFFFFFFL);
    } // 48-bit output

    private static int P(int src) {
        return (int) permute(P, 32, src & 0xFFFFFFFFL);
    } // 32-bit output

    private static long PC1(long src) {
        return permute(PC1, 64, src);
    } // 56-bit output

    private static long PC2(long src) {
        return permute(PC2, 56, src);
    } // 48-bit output

    private static long permute(byte[] table, int srcWidth, long src) {
        long dst = 0;
        for (int i = 0; i < table.length; i++) {
            int srcPos = srcWidth - table[i];
            dst = (dst << 1) | (src >> srcPos & 0x01);
        }
        return dst;
    }

    private static byte S(int boxNumber, byte src) {
        // The first aindex based on the following bit shuffle:
        // abcdef => afbcde
        src = (byte) (src & 0x20 | ((src & 0x01) << 4) | ((src & 0x1E) >> 1));
        return S[boxNumber - 1][src];
    }

    private static long getLongFromBytes(byte[] ba, int offset) {
        long l = 0;
        for (int i = 0; i < 8; i++) {
            byte value;
            if ((offset + i) < ba.length) {
                // and last bits determine which 16-value row to
                // reference, so we transform the 6-bit input into an
                // absolute
                value = ba[offset + i];
            } else {
                value = 0;
            }
            l = l << 8 | (value & 0xFFL);
        }
        return l;
    }

    private static void getBytesFromLong(byte[] ba, int offset, long l) {
        for (int i = 7; i > -1; i--) {
            if ((offset + i) < ba.length) {
                ba[offset + i] = (byte) (l & 0xFF);
                l = l >> 8;
            } else {
                break;
            }
        }
    }

    private static int feistel(int r, /* 48 bits */ long subkey) {
        // 1. expansion
        long e = E(r);
        // 2. key mixing
        long x = e ^ subkey;
        // 3. substitution
        int dst = 0;
        for (int i = 0; i < 8; i++) {
            dst >>>= 4;
            int s = S(8 - i, (byte) (x & 0x3F));
            dst |= s << 28;
            x >>= 6;
        }
        // 4. permutation
        return P(dst);
    }

    private static long[] createSubkeys(/* 64 bits */ long key) {
        long subkeys[] = new long[16];

        // perform the PC1 permutation
        key = PC1(key);

        // split into 28-bit left and right (c and d) pairs.
        int c = (int) (key >> 28);
        int d = (int) (key & 0x0FFFFFFF);

        // for each of the 16 needed subkeys, perform a bit
        // rotation on each 28-bit keystuff half, then join
        // the halves together and permute to generate the
        // subkey.
        for (int i = 0; i < 16; i++) {
            // rotate the 28-bit values
            if (rotations[i] == 1) {
                // rotate by 1 bit
                c = ((c << 1) & 0x0FFFFFFF) | (c >> 27);
                d = ((d << 1) & 0x0FFFFFFF) | (d >> 27);
            } else {
                // rotate by 2 bits
                c = ((c << 2) & 0x0FFFFFFF) | (c >> 26);
                d = ((d << 2) & 0x0FFFFFFF) | (d >> 26);
            }

            // join the two keystuff halves together.
            long cd = (c & 0xFFFFFFFFL) << 28 | (d & 0xFFFFFFFFL);

            // perform the PC2 permutation
            subkeys[i] = PC2(cd);
        }

        return subkeys; /* 48-bit values */
    }

    public static long encryptBlock(long m, /* 64 bits */ long key) {
        // generate the 16 subkeys
        long subkeys[] = createSubkeys(key);

        // perform the initial permutation
        long ip = IP(m);

        // split the 32-bit value into 16-bit left and right halves.
        int l = (int) (ip >> 32);
        int r = (int) (ip & 0xFFFFFFFFL);

        // perform 16 rounds
        for (int i = 0; i < 16; i++) {
            int previous_l = l;
            // the right half becomes the new left half.
            l = r;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (r & 0xFFFFFFFFL) << 32 | (l & 0xFFFFFFFFL);

        // apply the final permutation
        long fp = FP(rl);

        // return the ciphertext
        return fp;
    }

    public static void encryptBlock(
            byte[] message,
            int messageOffset,
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] key
    ) {
        long m = getLongFromBytes(message, messageOffset);
        long k = getLongFromBytes(key, 0);
        long c = encryptBlock(m, k);
        getBytesFromLong(ciphertext, ciphertextOffset, c);
    }

    public static byte[] encrypt(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.length];

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i = 0; i < message.length; i += 8) {
            encryptBlock(message, i, ciphertext, i, key);
        }

        return ciphertext;
    }

    public static byte[] encrypt(byte[] challenge, String password) {
        return encrypt(challenge, passwordToKey(password));
    }

    private static byte[] passwordToKey(String password) {
        byte[] pwbytes = password.getBytes();
        byte[] key = new byte[8];
        for (int i = 0; i < 8; i++) {
            if (i < pwbytes.length) {
                byte b = pwbytes[i];
                // flip the byte
                byte b2 = 0;
                for (int j = 0; j < 8; j++) {
                    b2 <<= 1;
                    b2 |= (b & 0x01);
                    b >>>= 1;
                }
                key[i] = b2;
            } else {
                key[i] = 0;
            }
        }
        return key;
    }

    private static int charToNibble(char c) {
        if (c >= '0' && c <= '9') {
            return (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            return (10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            return (10 + c - 'A');
        } else {
            return 0;
        }
    }

    private static byte[] parseBytes(String s) {
        s = s.replace(" ", "");
        byte[] ba = new byte[s.length() / 2];
        if (s.length() % 2 > 0) {
            s = s + '0';
        }
        for (int i = 0; i < s.length(); i += 2) {
            ba[i / 2] = (byte) (charToNibble(s.charAt(i)) << 4 | charToNibble(s.charAt(i + 1)));
        }
        return ba;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }
     
    private static long IV;

    public static long getIv() {
        return IV;
    }

    public static void setIv(long iv) {
        IV = iv;
    }

    public static byte[] encryptCBC(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.length];
        long k = getLongFromBytes(key, 0);
        long previousCipherBlock = IV;

        for (int i = 0; i < message.length; i += 8) {
            // get the message block to be encrypted (8bytes = 64bits)
            long messageBlock = getLongFromBytes(message, i);

            // XOR message block with previous cipherblock and encrypt
            // First previousCiphertext = Initial Vector (IV)
            long cipherBlock = encryptBlock(messageBlock ^ previousCipherBlock, k);

            // Store the cipherBlock in the correct position in ciphertext
            getBytesFromLong(ciphertext, i, cipherBlock);

            // Update previousCipherBlock
            previousCipherBlock = cipherBlock;
        }

        return ciphertext;
    }

    public static long decryptBlock(long c, /* 64 bits */ long key) {
        // generate the 16 subkeys
        long[] subkeys = createSubkeys(key);

        // perform the initial permutation
        long ip = IP(c);

        // split the 32-bit value into 16-bit left and right halves.
        int l = (int) (ip >> 32);
        int r = (int) (ip & 0xFFFFFFFFL);

        // perform 16 rounds
        // NOTE: reverse order of subkeys used!
        for (int i = 15; i > -1; i--) {
            int previous_l = l;
            // the right half becomes the new left half.
            l = r;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (r & 0xFFFFFFFFL) << 32 | (l & 0xFFFFFFFFL);

        // apply the final permutation
        long fp = FP(rl);

        // return the message
        return fp;
    }

    public static void decryptBlock(
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] message,
            int messageOffset,
            byte[] key
    ) {
        long c = getLongFromBytes(ciphertext, ciphertextOffset);
        long k = getLongFromBytes(key, 0);
        long m = decryptBlock(c, k);
        getBytesFromLong(message, messageOffset, m);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.length];

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i = 0; i < ciphertext.length; i += 8) {
            decryptBlock(ciphertext, i, message, i, key);
        }

        return message;
    }

    public static byte[] decryptCBC(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.length];
        long k = getLongFromBytes(key, 0);
        long previousCipherBlock = IV;

        for (int i = 0; i < ciphertext.length; i += 8) {
            // get the cipher block to be decrypted (8bytes = 64bits)
            long cipherBlock = getLongFromBytes(ciphertext, i);

            // Decrypt the cipher block and XOR with previousCipherBlock
            // First previousCiphertext = Initial Vector (IV)
            long messageBlock = decryptBlock(cipherBlock, k);
            messageBlock = messageBlock ^ previousCipherBlock;

            // Store the messageBlock in the correct position in message
            getBytesFromLong(message, i, messageBlock);

            // Update previousCipherBlock
            previousCipherBlock = cipherBlock;
        }

        return message;
    }
    
    public static void ctostr(char[] vrbls, int pos) {
    	String tf = "";
    	for (int i = 0; i < 8; i++) {
    	tf += vrbls[i+pos];
    	}
  	  SecureRandom number = new SecureRandom();
  	  for (int i = 0; i < 4; i++) {
  		  String r ="";
  		  r += number.nextInt(256);
  		  Integer inv =Integer.valueOf(r);  
  		  tf += String.format("%02x", inv);  
  		  }
  	  
  	  //System.out.println(tf);
	  String key = Global.ck;
  	  byte[] enc = encrypt(parseBytes(tf), parseBytes(key));
  	  for (int i = 0; i < 8; i++) {
  		  Global.stf += String.format("%02x", enc[i]);
  		  }
  	  
    }

	private static void dec_str(char[] tdec, int pos) {
    	String tf = "";
    	for (int i = 0; i < 16; i++) {
    	tf += tdec[i+pos];
    	}
    	//System.out.println(tf);
		String key = Global.ck;
    	byte[] dec_t = decrypt(parseBytes(tf), parseBytes(key));
    	String tsb = "";
        //System.out.println("\tDecrypted: " + hex(dec)); 
      	  for (int i = 0; i < 4; i++) {
      		  tsb += String.format("%02x", dec_t[i]);
      		  }
      	//System.out.println(tsb); 
      	String ir = "";
		char[] chtd = tsb.toCharArray();
		for(int i = 0; i < 8 ; i+=2){ 
			int fs = getNum(chtd[i]);
			int ss = getNum(chtd[i+1]);
      	  	Integer intObject = Integer.valueOf(Global.Inv_S_Box[fs][ss]);
      	  	String cv = "";
      	  	cv += (String.format("%02x", intObject));
      	  	//System.out.println(cv);
      	  	int rc = Integer.valueOf(cv, 16);
      	  	//System.out.println(rc);
      	  	char ctp = (char)rc;  
      	  	ir += ctp;
			}
		//System.out.println(ir);
		disp_rec(ir);
	}
	
	public static void create_table() {
	      Connection c = null;
	      Statement stmt = null;
	      
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
	         System.out.println("Opened database successfully");

	         stmt = c.createStatement();
	         String sql = "CREATE TABLE STUFF " +
                   " (NAME           TEXT    NOT NULL, " + 
                   " CONTENT         TEXT     NOT NULL)";
	         stmt.executeUpdate(sql);
	         stmt.close();
	         c.close();
	      } catch ( Exception e ) {
	         //System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	            JOptionPane.showMessageDialog(cancel, e.getClass().getName() + ": " + e.getMessage(),
                        "ERROR", JOptionPane.ERROR_MESSAGE);
	         System.exit(0);
	      }
	      JFrame ctf=new JFrame();  
	      JOptionPane.showMessageDialog(ctf,"Table created successfully!");  
	      //System.out.println("Table created successfully");
	      return;
	}
	
	public static void add_record(String name, String content) {
	      Connection c = null;
	      Statement stmt = null;
	      
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
	         c.setAutoCommit(false);
	         stmt = c.createStatement();
	         String sql = "INSERT INTO STUFF (NAME,CONTENT) " +
	                        "VALUES ('"+name+"', '"+content+"');"; 
	         stmt.executeUpdate(sql);
	         stmt.close();
	         c.commit();
	         c.close();
	      } catch ( Exception e ) {
	         System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	         System.exit(0);
	      }
	      JFrame ctf=new JFrame();  
	      JOptionPane.showMessageDialog(ctf,"Record saved successfully!");
	      return;
	}
	
	public static void load_rec() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM STUFF;" );
			  JFrame ch = new JFrame("Load record");
		      cm = new JMenuBar();
		      String rcrds[] = new String [1000];
			  JComboBox records = new JComboBox();
		      int n = 0;
		      while (rs.next()) {
		    	 rcrds[n] = (rs.getString("name"));
		    	 n++;
		      }
		      int m = 0;
		      while (rcrds[m] != null) {
		    	 m++;
		      }
		      for(int i = 0; i < m; i++) {
		    	  records.addItem(rcrds[i]);  
		      }
		      ch.setJMenuBar(cm);
			  cm.add(records);
			  select = new JButton("Select");  
		      cancel = new JButton("Cancel");   
		      cm.add(select);  
		      cm.add(cancel);  
			 
			  ch.setSize(400, 65);  
		      ch.setVisible(true); 
		      rs.close();
		      stmt.close();
		      c.close(); 
			    select.addActionListener(e ->
		        {
		        	select(rcrds[records.getSelectedIndex()]);
		        	ch.dispose();
	   	
		        });
			    cancel.addActionListener(e ->
		        {
		        	ch.dispose();
	   	
		        });
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void remove_rec() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM STUFF;" );
			  JFrame remrec = new JFrame("Delete record");
		      rm = new JMenuBar();
		      String rcrds[] = new String [1000];
			  JComboBox records = new JComboBox();
		      int n = 0;
		      while (rs.next()) {
		    	 rcrds[n] = (rs.getString("name"));
		    	 n++;
		      }
		      int m = 0;
		      while (rcrds[m] != null) {
		    	 m++;
		      }
		      for(int i = 0; i < m; i++) {
		    	  records.addItem(rcrds[i]);
		      }
		      remrec.setJMenuBar(rm);
			  rm.add(records);
			  rmv = new JButton("Delete");  
		      cncl = new JButton("Cancel");   
		      rm.add(rmv);  
		      rm.add(cncl);  
			 
		      remrec.setSize(400, 65);  
		      remrec.setVisible(true); 
		      rs.close();
		      stmt.close();
		      c.close(); 
			    rmv.addActionListener(e ->
		        {
		        	remove(rcrds[records.getSelectedIndex()]);
		        	remrec.dispose();
	   	
		        });
			    cncl.addActionListener(e ->
		        {
		        	remrec.dispose();
	   	
		        });
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}

	public static void remove(String name) {
	      Connection c = null;
	      Statement stmt = null;
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
	         c.setAutoCommit(false);

	         stmt = c.createStatement();
	         String sql = "DELETE from STUFF where NAME='"+name+"';";
	         stmt.executeUpdate(sql);
	         c.commit();

	      c.close();
	      } catch ( Exception e ) {
	         System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	         System.exit(0);
	      }
	      return;
	}
	
	public static void select(String name) {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:stuff.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT CONTENT FROM STUFF WHERE NAME = '"+name+"'" );
		      cl();
		      while (rs.next()) {
		         String  content = rs.getString("content");
		         //System.out.println( "CONTENT = " + content );
		         //System.out.println();
		         char[] tdec = content.toCharArray();
		         int td_len = tdec.length;
	             int crr = 0;
	             while(crr < td_len) {
	               	dec_str(tdec, crr);
	               	crr += 16;
	             }
		      }
		      rs.close();
		      stmt.close();
		      c.close();
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	  public static void main(String[] args){
		  String fonts[] = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();
		    String sizes[] = new String [92];
        	Global.s = 16;
		    for(int i = 0; i < 92; i++) {
		    	sizes[i] = String.valueOf(i+8);
		    }
		    
		    JFrame frame = new JFrame("Twinkle");
		    JComboBox fd = new JComboBox(fonts);
		    JComboBox ff = new JComboBox(sizes);
		    JButton sel = new JButton("Apply");
		    JLabel label0 = new JLabel("|  Font ");
		    JLabel label1 = new JLabel("  Font size ");
		    Global.X = fonts[2];
	        mb = new JMenuBar();
	        m = new JMenu("File");
	        m1 = new JMenu("Action");
	        o = new JMenuItem("Open");
	        s = new JMenuItem("Save");
	        c = new JMenuItem("Clear");
	        q = new JMenuItem("Quit");
	        sk = new JMenuItem("Select key");
	        m.add(o);
	        m.add(s);
	        m1.add(c);
	        m.add(sk);
	        m.add(q);
	        mb.add(m);
	        mb.add(m1);
	        m2 = new JMenu("Built-in storage");
	        ct = new JMenuItem("Create table");
	        lr = new JMenuItem("Load record");
	        sr = new JMenuItem("Save record");
	        rr = new JMenuItem("Delete record");
	        m2.add(ct);
	        m2.add(lr);
	        m2.add(sr);
	        m2.add(rr);
	        mb.add(m2);
	        frame.setJMenuBar(mb);  
		    mb.add(label0);  
		    mb.add(fd);
		    mb.add(label1);  
		    mb.add(ff);
		    mb.add(sel);
		    
		    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);  
	        Container cp = frame.getContentPane();  
	        pane = new JTextPane();  
	        
	        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
	        StyleConstants.setFontFamily(attributeSet, Global.X);
	        StyleConstants.setFontSize(attributeSet, 16); 
	        
	        // Set the attributes before adding text  
	        pane.setCharacterAttributes(attributeSet, true);
	        JScrollPane scrollPane = new JScrollPane(pane);  
	        cp.add(scrollPane, BorderLayout.CENTER);   
		    frame.setSize(700, 500);  
	        frame.setVisible(true);
	        
		    ct.addActionListener(e ->
	        {
	        	create_table();    	
	        });
		    
		    lr.addActionListener(e ->
	        {
	        	load_rec();
	        });
		    
		    sr.addActionListener(e ->
	        {
	        	   JFrame sf = new JFrame();
	        	   String name = JOptionPane.showInputDialog(sf,"Enter the name of the record");
	        	   if(name != null) {
	   	        	final JFrame iFRAME = new JFrame();
		        	iFRAME.setAlwaysOnTop(true);
		        	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		        	iFRAME.setLocationRelativeTo(null);
		        	iFRAME.requestFocus();

		        	JFileChooser jfc = new JFileChooser();
		        	jfc.setDialogTitle("Open a record");  
		        	int returnValue = jfc.showOpenDialog(iFRAME);
		        	iFRAME.dispose();
		        	if (returnValue == JFileChooser.APPROVE_OPTION) {
		        	    File selectedFile = jfc.getSelectedFile();
		        	    System.out.println(selectedFile.getAbsolutePath());
		        	    try {
		        	        String result = null;
		        	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
		        	        int nBytesToRead = reader.available();
		        	        if(nBytesToRead > 0) {
		        	            byte[] bytes = new byte[nBytesToRead];
		        	            reader.read(bytes);
		        	            result = new String(bytes);
		        	        }
		        	      add_record(name,result);

		                } catch (IOException r) {
		                    System.out.println("An error occurred.");
		                    r.printStackTrace();
		                  }
		        	}
	        	   }
	        		   
	        });
		    
		    rr.addActionListener(e ->
	        {
	        	remove_rec();  	
	        });

		    sel.addActionListener(e ->
	        {
	        	Global.X = fonts[fd.getSelectedIndex()];
	        	Global.s = Integer.parseInt(sizes[ff.getSelectedIndex()]);
	        	cf();      	
	        });
	        
	        c.addActionListener(e ->
	        {
	        	cl(); 
	        });
	        
	        q.addActionListener(e ->
	        {
	        	System.exit(0); 
	        });
	        
	        o.addActionListener(e ->
	        {
	        	final JFrame iFRAME = new JFrame();
	        	iFRAME.setAlwaysOnTop(true);
	        	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	        	iFRAME.setLocationRelativeTo(null);
	        	iFRAME.requestFocus();

	        	JFileChooser jfc = new JFileChooser();
	        	jfc.setDialogTitle("Open a record");  
	        	int returnValue = jfc.showOpenDialog(iFRAME);
	        	iFRAME.dispose();
	        	if (returnValue == JFileChooser.APPROVE_OPTION) {
	        	    File selectedFile = jfc.getSelectedFile();
	        	    cl();
	        	    System.out.println(selectedFile.getAbsolutePath());
	        	    try {
	        	        String result = null;
	        	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
	        	        int nBytesToRead = reader.available();
	        	        if(nBytesToRead > 0) {
	        	            byte[] bytes = new byte[nBytesToRead];
	        	            reader.read(bytes);
	        	            result = new String(bytes);
	        	        }
	            	    char[] tdec = result.toCharArray();
	            	    int td_len = tdec.length;
                        int crr = 0;
                       while(crr < td_len) {
                        	dec_str(tdec, crr);
                        	crr += 16;
                        }

	                } catch (IOException r) {
	                    System.out.println("An error occurred.");
	                    r.printStackTrace();
	                  }
	        	    SwingUtilities.updateComponentTreeUI(frame);
	        	}
	        });
	        
	        sk.addActionListener(e ->
	        {
	        	final JFrame iFRAME = new JFrame();
	        	iFRAME.setAlwaysOnTop(true);
	        	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	        	iFRAME.setLocationRelativeTo(null);
	        	iFRAME.requestFocus();

	        	JFileChooser jfc = new JFileChooser();
	        	int returnValue = jfc.showOpenDialog(iFRAME);
	        	iFRAME.dispose();
	        	if (returnValue == JFileChooser.APPROVE_OPTION) {
	        	    File selectedFile = jfc.getSelectedFile();
	        	    System.out.println(selectedFile.getAbsolutePath());
	        	    try {
	        	        String result = null;

	        	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
	        	        int nBytesToRead = reader.available();
	        	        if(nBytesToRead > 0) {
	        	            byte[] bytes = new byte[nBytesToRead];
	        	            reader.read(bytes);
	        	            result = new String(bytes);
	        	        }
	        	        //System.out.println(result);
	        	        Global.ck = result;
	                } catch (IOException r) {
	                    System.out.println("An error occurred.");
	                    r.printStackTrace();
	                  }
	        	    SwingUtilities.updateComponentTreeUI(frame);
	        	}
	        });
	        
	        s.addActionListener(e ->
	        {
	        	JFrame parentFrame = new JFrame();
	        	 
	        	JFileChooser fileChooser = new JFileChooser();
	        	fileChooser.setDialogTitle("Save a record");   
	        	 
	        	int userSelection = fileChooser.showSaveDialog(parentFrame);
	        	 
	        	if (userSelection == JFileChooser.APPROVE_OPTION) {
	        	    File fileToSave = fileChooser.getSelectedFile();
	        	    System.out.println("Save as file: " + fileToSave.getAbsolutePath());
	        	    Global.stf = "";
	            	try {
	            		String ir = "";
	            		String str = pane.getText();
	            		char[] ch = str.toCharArray();
	            		for(int i=0;i<ch.length;i++){ 
	            			if((int)ch[i] != 0) {
	            			int b = ((int)ch[i])/16;
	            			int s = ((int)ch[i])%16;
	  	            	  	Integer intObject = Integer.valueOf(Global.Forward_S_Box[b][s]);
	  	            	  	ir += (String.format("%02x", intObject));
	            			}
	            			else {
	      	            	  Integer c = Integer.valueOf(Global.Forward_S_Box[0][0]);
	    	            	  ir += (String.format("%02x", c));
	            			}

	            		}
	                    while(ir.length()%8 != 0){
	                        ir += "63";
	                        }
	                        //System.out.println(ir);
	                        //System.out.println("Length of a String is: " + ir.length());
	                        char[] iarr = new char[ir.length()];
	                        
	                        // Copy character by character into array
	                        for (int i = 0; i < ir.length(); i++) {
	                        	iarr[i] = ir.charAt(i);
	                        	//System.out.println(iarr[i]);
	                        }
	                  
	                        // Printing content of array
	                        /*for (char c : iarr) {
	                            System.out.println(c);
	                        }
	                        */
	                        int al = iarr.length;
	                        int curr = 0;
	                        while(curr < al) {
	                        	ctostr(iarr, curr);
	                        	curr += 8;
	                        }
	            		FileWriter myWriter = new FileWriter(fileToSave.getAbsolutePath());
	                    myWriter.write(Global.stf);
	                    myWriter.close();
	                    System.out.println("Successfully wrote to the file.");
	                  } catch (IOException q) {
	                    System.out.println("An error occurred.");
	                    q.printStackTrace();
	                  }
	        	}

	        });

	    }

}
