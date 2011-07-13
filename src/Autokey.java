public class Autokey
{
	public static void main(String[] args)
	{
		AutokeySolver solver;
		if(args.length != 3)
			System.err.println("Invalid number of arguments. Please pass main: args[0]= ciphertext filepath       args[1]= min key length        args[2] = max key length");
		else
		{
			solver = new AutokeySolver(args[0]);
			solver.setMinKeylength(Integer.parseInt(args[1]));
			solver.setMaxKeylength(Integer.parseInt(args[2]));
			solver.analyze();
		}
	}
}