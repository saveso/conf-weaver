package it.unical.thesis.utils;

import java.util.Scanner;

public class OptionChooser {
	
	private Scanner scanner;
	
	
	public OptionChooser()
	{
		this.scanner = new Scanner(System.in);
	}
	
	public int choose(int rangeMax)
	{
		if(rangeMax==0)
		{
			System.err.println("Error, rangeMax cannot be zero!");
			System.exit(1);
		}
		
		System.out.println("Choose your option from 1 to "+rangeMax);
		int chosen = scanner.nextInt();
		while(chosen<=0 || chosen>rangeMax)
		{
			System.out.println("Invalid option! Retry!");
			chosen = scanner.nextInt();
		}
		return chosen;
	}
	
	public void closeScanner()
	{
		scanner.close();
	}
	
}
