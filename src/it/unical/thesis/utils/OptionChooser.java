package it.unical.thesis.utils;

import java.util.Scanner;

public class OptionChooser {

    private final Scanner scanner;

    public OptionChooser() {
        this.scanner = new Scanner(System.in);
    }


    public int choose(int rangeMax) {
        if (rangeMax <= 0) {
            System.err.println("Error: Cannot choose from a range of zero or less.");
            return 0;
        }

        while (true) {
            System.out.println("Choose your option from 1 to " + rangeMax + " (or type 0 to skip):");
            String inputLine = scanner.nextLine();
            //scanner.nextInt();
            try {
                int chosen = Integer.parseInt(inputLine);

                if (chosen >= 0 && chosen <= rangeMax) {
                    return chosen;
                } else {
                    System.out.println("Invalid option! Please enter a number between 0 and " + rangeMax + ".");
                }

            } catch (NumberFormatException e) {
                System.out.println("Invalid input! Please enter a valid number.");
            }
        }
    }


    public void closeScanner() {
        scanner.close();
    }
    
    
}