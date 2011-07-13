import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class AutokeySolver
{
	
	private String cipherText;
	private int minKeylength;
	private int maxKeylength;
	
	private HashMap<Integer, String> guessedKeys;
	
	/*****************************
	 * 
	 *	Default Constructor 
	 * 
	 *****************************/
	public AutokeySolver()
	{
		this.cipherText = null;
		this.minKeylength = 1;
		this.maxKeylength = 100;
	}
	
	/*****************************
	 * 
	 *	Alt Constructor - takes a filepath to a ciphertext file to load
	 * 
	 *****************************/
	public AutokeySolver(String cipherFilePath)
	{
		this.loadCipherTextFile(cipherFilePath);
		
		this.minKeylength = 1;
		this.maxKeylength = 100;
	}
	
	/*****************************
	 * 
	 *	Sets the minimum key length to test for.
	 * 
	 *****************************/
	public void setMinKeylength(int length)
	{
		this.minKeylength = length;
	}
	
	/*****************************
	 * 
	 *	Sets the maximum key length to test for.
	 * 
	 *****************************/
	public void setMaxKeylength(int length)
	{
		this.maxKeylength = length;
	}
	
	/*****************************
	 * 
	 *	Performs and prints analysis of the cipher
	 * 
	 *****************************/
	public void analyze()
	{
		this.guessedKeys = new HashMap<Integer, String>();
		
		double bestKeylengthScore = Integer.MAX_VALUE;
		int guessedKeylength = 0;
		for(int i = this.minKeylength; i <= this.maxKeylength; i++)
		{
			double keylengthScore = this.performKeyAnalysis(i, this.cipherText);
			if(keylengthScore < bestKeylengthScore)
			{
				bestKeylengthScore = keylengthScore;
				guessedKeylength = i;
			}
		}
		
		String guessedKey = this.guessedKeys.get(guessedKeylength);
		String guessedPlaintext = this.decipher(guessedKey, this.cipherText);
		
		System.out.println("***************************************");
		System.out.println("Guessed key:\t" + guessedKey);
		System.out.println("Length:\t" + guessedKey.length());
		System.out.println("Score:\t" + bestKeylengthScore);
		System.out.println();
		System.out.println("Cipher decrypted using key '" + guessedKey + "':\n");
		System.out.println(guessedPlaintext);
	}
	
	
	/*****************************
	 * 
	 *	Return the currently loaded ciphertext 
	 * 
	 *****************************/
	public String getCipherText()
	{
		return this.cipherText;
	}
	
	/*****************************
	 * 
	 *	Loads ciphertext from a text file
	 * 
	 *****************************/
	public void loadCipherTextFile(String filepath)
	{
		try
		{
			BufferedReader reader = new BufferedReader(new FileReader(filepath));
			this.cipherText = "";
			String line = reader.readLine();
			while(line != null)
			{
				this.cipherText += line;
				line = reader.readLine();
			}
			
			this.cipherText = this.cipherText.toLowerCase();
			
			System.out.println("Ciphertext Loaded:\n" + this.cipherText + "\n\n");
		}
		catch(IOException e)
		{
			System.err.println(e.getMessage());
		}
	}
	
	/*****************************
	 * 
	 *	Returns the ratio of occurrences of 'letter' in 'str' to length of 'str'
	 *	as a double value 0 <= x <= 1
	 * 
	 *****************************/
	public double getLetterFrequency(char letter, String str)
	{
		int count = 0;
		for(int i = 0; i < str.length(); i++)
			if(str.charAt(i) == letter)
				count++;
		return (double)Math.round((((double)count/(double)str.length()) * 1000))/1000;
	}
	
	
	/*****************************
	 * 
	 *	Returns a Chi-Squared statistic that indicates the strength with which the
	 *	specified observed frequencies (frequencies[]) correspond to the expected frequencies
	 *	(letterFrequencies[]). 
	 * 
	 * The shift parameter optionally allows to perform the test on a shift of the observed frequencies. Otherwise should pass 0.
	 * 
	 * The length is the length of the original text the frequencies occurred in.
	 * 
	 * NOTE: Lower chi-squared values indicate stronger correspondence between observed/expected frequencies
	 *****************************/
	public double getXSQFrequencyScore(double[] frequencies, int shift, int length)
	{
		double[] letterFrequencies = new double[26];
		letterFrequencies[0]	= .08167;
		letterFrequencies[1]	= .01492;
		letterFrequencies[2]	= .02782;
		letterFrequencies[3]	= .04253;
		letterFrequencies[4]	= .12702;
		letterFrequencies[5]	= .02228;
		letterFrequencies[6]	= .02015;
		letterFrequencies[7]	= .06094;
		letterFrequencies[8]	= .06966;
		letterFrequencies[9]	= .00153;
		letterFrequencies[10]	= .00772;
		letterFrequencies[11]	= .04025;
		letterFrequencies[12]	= .02406;
		letterFrequencies[13]	= .06749;
		letterFrequencies[14]	= .07507;
		letterFrequencies[15]	= .01929;
		letterFrequencies[16]	= .00095;
		letterFrequencies[17]	= .05987;
		letterFrequencies[18]	= .06327;
		letterFrequencies[19]	= .09056;
		letterFrequencies[20] 	= .02758;
		letterFrequencies[21] 	= .00978;
		letterFrequencies[22] 	= .02360;
		letterFrequencies[23] 	= .00150;
		letterFrequencies[24] 	= .01974;
		letterFrequencies[25] 	= .00074;
		
		//perform shift
		double[] shifted = new double[26];
		for(int i = 0; i < 26; i++)
		{
			shifted[i] = frequencies[(i + shift) % 26];
		}
		
		//determine chi squared test statistc
		double xsq = 0;
		
		for(int i = 0; i < frequencies.length; i++)
		{
			xsq += Math.pow((double)(shifted[i]*length - letterFrequencies[i]*length), 2)/(double)(letterFrequencies[i]*length);
		}
		
		return xsq;
	}
	
	/*****************************
	 * 
	 *	The "solver" function. Non-deterministic in the sense that it does not guarantee an answer, but can make some pretty good guesses and gives a good basis for further analysis if required.
	 *
	 *	This function takes a guessed key length and the autokey-encrypted ciphertext.
	 *	It then follows the procedure:
	 *		for each character position [0...keylength-1] in the key
	 *			for each possible value for this position (a...z)
	 *				generate the set of characters the would be produced in the entire plaintext message by having this position in the key take this character value
	 *				perform a frequency analysis on that set to get a xsq goodness-of-fit score
	 *			take the BEST (lowest) xsq value and assert that as the character for this position in the key for this key length
	 *		generate a score for this key length taken as the average of xsq scores for each position... we can use this to evaluate the approximate likelihood of the key being this length
	 *		return the constructed 'most likely' key for this length
	 *
	 *	Outputs results to console.
	 * 
	 *  Returns a 'goodness' score for this key length, taken as the average of the xsq values for each of the characters in the positions in the key. 
	 * 
	 *****************************/
	public double performKeyAnalysis(int keyLength, String ciphertext)
	{
		String key = "";
		
		//for each character in the key of fixed length
		double keyScore = 0;
		for(int i = 0; i < keyLength; i++)
		{
			//determine the most likely character
			double minxsq = Integer.MAX_VALUE;
			char mostLikelyKeyChar = 0;
			for(int j = 0; j < 26; j++)
			{
				String set = this.getGeneratedSet(i, keyLength, (char)(j+97), ciphertext);
				double[] letterFrequencies = this.getLetterFrequencies(set);
				double score = this.getXSQFrequencyScore(letterFrequencies, 0, ciphertext.length());
				if(score < minxsq)
				{
					minxsq = score;
					mostLikelyKeyChar = (char)(97 + j);
				}
			}
			
			key += mostLikelyKeyChar;
			keyScore += minxsq;
		}
		
		keyScore /= (double)keyLength;
		
		System.out.println("Possible key for length " + keyLength + ":\t" + key);
		System.out.println("Score:\t\t" + keyScore);
		System.out.println("Deciphered text using key:");
		System.out.println("\""+this.decipher(key, this.cipherText)+"\"");
		System.out.println();
		
		this.guessedKeys.put(keyLength, key);
		
		return keyScore;
	}
	
	/*****************************
	 * 
	 *	returns a double[26] of frequencies for each letter (a..z) in the string 'text'
	 * 
	 *****************************/
	public double[] getLetterFrequencies(String text)
	{
		double[] freqs = new double[26];
		for(int i = 0; i < 26; i++)
			freqs[i] = this.getLetterFrequency((char)(97 + i), text);
		return freqs;
	}
	
	/*****************************
	 * 
	 *	Returns an arraylist of integer factors of the number 'n'
	 * 
	 *****************************/
	public ArrayList<Integer> getFactors(int n)
	{
		ArrayList<Integer> factors = new ArrayList<Integer>();
		factors.add(n);
		factors.add(1);
		for(int test = n - 1; test >= Math.sqrt(n); test--)
		{
			if(n % test == 0)
			{
				factors.add(test);
				factors.add(n / test);
			}
		}
		return factors;
	}
	
	
	/*****************************
	 * 
	 *	Gets a set of characters generated from the ciphertext using a character 'c' at position 'keyPosition' in a key of length 'keyLength'
	 *
	 *	If 'c' is the correct character for position 'keyPosition' and 'keyLength' is the correct keylength, then this will decrypt a portion of
	 *	the enciphered message back to plaintext, leaving it vulnerable to frequency analysis. Specifically, it will decrypt every nth character, offset by keyPosition, where
	 *  n == keyLength
	 *  
	 *  e.g.
	 *  
	 *  plaintext:		hellomynameishose
	 *  key:			ab
	 *  enciphered:		hfspzxmzyzeuwpgzs
	 *
	 * getGeneratedSet(0, 2, 'a', "hfspzxmzyzeuwpgzs"): hloyaesoe
	 * 
	 * 				hellomynameishose
	 * 				h l o y a e s o e
	 * 
	 * getGeneratedSet(1, 2, 'b', "hfspzxmzyzeuwpgzs"): elmnmihs
	 * 
	 * 				hellomynameishose
	 * 				 e l m n m i h s
	 * 
	 *****************************/
	public String getGeneratedSet(int keyPosition, int keyLength, char c, String cipher)
	{
		int shiftAmount = (int)c - 97;
		String set = "";
		for(int i = keyPosition; i < cipher.length(); i += keyLength)
		{
			char currentEncipheredChar = cipher.charAt(i);
			char decipheredChar = this.unshiftChar(currentEncipheredChar, shiftAmount);
			shiftAmount = (int)decipheredChar - 97;
			set += decipheredChar;
		}
		return set;
	}
	
	
	/*****************************
	 * 
	 *	Shifts a character left by 'shift' amount
	 * 
	 *  Useful for decryption.
	 * 
	 *****************************/
	public char unshiftChar(char c, int shift)
	{
		return (char)(((int)c + 26 -  97 - shift) % 26 + 97);
	}
	
	
	/*****************************
	 * 
	 *	Shifts a character right by 'shift' amount
	 *
	 *	Useful for encryption.
	 * 
	 *****************************/
	public char shiftChar(char c, int shift)
	{
		return (char)(((int)c + shift - 97) % 26 + 97); 
	}
	
	/*****************************
	 * 
	 *	Enciphers a string 'plaintext' using key 'key' with the Vigenere Autokey Cipher
	 * 
	 *****************************/
	public String encipher(String key, String plaintext)
	{
		String fullKey = key + plaintext;
		String ciphertext = "";
		for(int i = 0; i < plaintext.length(); i++)
		{
			int shift = (int)fullKey.charAt(i) - 97;
			char plaintextChar = plaintext.charAt(i);
			char encipheredChar = this.shiftChar(plaintextChar, shift);
			ciphertext += "" + encipheredChar;
		}
		return ciphertext;
	}
	
	
	/*****************************
	 * 
	 *	Deciphers a string 'ciphertext' using key 'key' that has been enciphered using the Vigenere Autokey Cipher
	 * 
	 *****************************/
	public String decipher(String key, String ciphertext)
	{
		String plaintext = "";
		for(int i = 0; i < ciphertext.length(); i++)
		{
			char currentKeyChar = 0;
			if(i < key.length())
				currentKeyChar = key.charAt(i);
			else
				currentKeyChar = plaintext.charAt(i - key.length());
			char encipheredChar = ciphertext.charAt(i);
			int shift = (int)currentKeyChar - 97;
			char decipheredChar = this.unshiftChar(encipheredChar, shift);
			plaintext += "" + decipheredChar;
		}
		return plaintext;
	}
}