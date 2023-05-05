package com.code_intelligence.jazzer.android;

import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.io.InputStream;
import java.lang.Math;
import java.util.Arrays;

public class DexFileManager {
    public static byte[] toPrimitiveArray(ArrayList<Byte> list) {
        byte[] result = new byte[list.size()];

        for(int i = 0; i < list.size(); i++){
            result[i] = list.get(i).byteValue();
        }

        return result;
    }

    public static String[] toStringArray(ArrayList<String> list) {
        String[] result = new String[list.size()];

        for(int i = 0; i < list.size(); i++){
            result[i] = list.get(i).toString();
        }

        return result;
    }

    public static byte[] getBytecodeFromDex(String jarPath, String dexFile, long offset) throws IOException{
        try(JarFile jarFile = new JarFile(jarPath)){
            Enumeration<JarEntry> allEntries = jarFile.entries();
            while(allEntries.hasMoreElements()){
                JarEntry entry = allEntries.nextElement();
                if(entry.getName().equals(dexFile)){

                    // Read dex file
                    try(InputStream is = jarFile.getInputStream(entry)){
                        byte[] buf = new byte[2000000];
                        is.skip(offset);
                        int bytesRead = is.read(buf);

                        if(bytesRead < 0){
                            return new byte[]{};
                        }

                        return Arrays.copyOfRange(buf, 0, bytesRead);
                    }
                }
            }
        }

        throw new IOException("Could not find dex");
    }

    public static String[] getDexFilesForJar(String jarpath) throws IOException{
        ArrayList<String> dexFiles = new ArrayList<>();
        try (JarFile jarFile = new JarFile(jarpath)){
            Enumeration<JarEntry> allEntries = jarFile.entries();

            while(allEntries.hasMoreElements()){
                JarEntry entry = allEntries.nextElement();
                if(entry.getName().endsWith(".dex")){
                    dexFiles.add(entry.getName());
                }
            }

            String[] result = toStringArray(dexFiles);
            return result;
        }
    }
}