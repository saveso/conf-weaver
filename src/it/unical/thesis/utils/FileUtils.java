package it.unical.thesis.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


public final class FileUtils {

    private FileUtils() {}

 
    public static boolean writeToFile(String filePath, String content) {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(content);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }


    public static boolean deleteFile(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            return file.delete();
        }
        return false;
    }


    public static boolean deleteAllFiles(String... filePaths) {
        boolean allDeleted = true;
        for (String filePath : filePaths) {
            if (!deleteFile(filePath)) {
                allDeleted = false;
            }
        }
        return allDeleted;
    }
    
    
}