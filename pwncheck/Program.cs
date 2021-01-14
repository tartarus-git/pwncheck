using System;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;

namespace pwncheck
{
    class Program
    {
        const string HELP_TEXT = "Usage: pwncheck <password>/-h\n\n" +

            "Description: Uses the haveibeenpwned.com API (v3) to check for the given password in known " +
            "password hash leaks.\n\n" +

            "Argument Definitions:\n" +
                "\t<password> --> The password to check against the haveibeenpwned.com database.\n" +
                "\t-h         --> Display the help text.";

        static void ShowHelp()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(HELP_TEXT);
            Console.ResetColor();
            Environment.Exit(0);
        }

        static void ThrowError(string Message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERROR: " + Message);
            ShowHelp();
        }

        static void CheckArgs(string[] args)
        {
            switch (args.Length)
            {
                case 0:
                    ThrowError("No arguments.");
                    break;
                case 1:
                    if (args[0] == "-h") { ShowHelp(); }
                    break;
                default:
                    ThrowError("Too many arguments.");
                    break;
            }
        }

        static void Main(string[] args)
        {
            CheckArgs(args);
            int Matches = CheckForAPIMatches(SHA1.Hash(Encoding.ASCII.GetBytes(args[0])).ToHex());
            if (Matches == 0) { Console.WriteLine("No matches found."); return; }
            Console.WriteLine("Matches found: " + Matches);
        }

        static int CheckForAPIMatches(string Hash)
        {
            using (HttpClient Client = new HttpClient())
            {
                // Get data.
                Client.DefaultRequestHeaders.Add("Add-Padding", "true");
                Task<HttpResponseMessage> ResponseTask = null;
                try
                {
                    ResponseTask = Client.GetAsync(
                        "https://api.pwnedpasswords.com/range/" + Hash.Substring(0, 5));
                }
                catch (HttpRequestException e)
                {
                    ThrowError("Encountered HttpRequestException while requesting data. " +
                        "Message: " + e.Message);
                }
                ResponseTask.Wait();

                // Parse response.
                using (HttpResponseMessage Response = ResponseTask.Result)
                {
                    if (Response.StatusCode == HttpStatusCode.OK)
                    {
                        Task<string> ResponseBodyTask = Response.Content.ReadAsStringAsync();
                        ResponseBodyTask.Wait();
                        return FindMatches(ResponseBodyTask.Result.ToCharArray(), Hash.Substring(5));
                    }
                    ThrowError("Invalid response recieved from server.");
                }
                // This should never be reached.
                return 0;
            }
        }

        static int FindMatches(char[] Data, string HashSuffix)
        {
            int ValidPos = 0;
            for (int i = 0; i < Data.Length; i++)
            {
                //Console.WriteLine("Looping.");
                if (Data[i] == HashSuffix[ValidPos])
                {
                    if (ValidPos == 34)
                    {
                        // Get number of matches for the, now found, hash.
                        i += 2;
                        int Matches = 0;
                        for (; Data[i] != '\n'; i++)
                        {
                            switch (Data[i])
                            {
                                // TODO: This could be optimized by using the codex table and subtracting.
                                case '0':
                                    Matches *= 10;
                                    break;
                                case '1':
                                    Matches = Matches * 10 + 1;
                                    break;
                                case '2':
                                    Matches = Matches * 10 + 2;
                                    break;
                                case '3':
                                    Matches = Matches * 10 + 3;
                                    break;
                                case '4':
                                    Matches = Matches * 10 + 4;
                                    break;
                                case '5':
                                    Matches = Matches * 10 + 5;
                                    break;
                                case '6':
                                    Matches = Matches * 10 + 6;
                                    break;
                                case '7':
                                    Matches = Matches * 10 + 7;
                                    break;
                                case '8':
                                    Matches = Matches * 10 + 8;
                                    break;
                                case '9':
                                    Matches = Matches * 10 + 9;
                                    break;
                            }
                        }
                        return Matches;
                    }
                    ValidPos++;
                    continue;
                }

                // If the hash suffix is invalid, reset ValidPos and skip past the next newline character.
                ValidPos = 0;
                do
                {
                    i++;
                    // If there is nothing to skip over, return 0 matches because we found none.
                    if (i == Data.Length) { return 0; }
                }
                while (Data[i] != '\n');
            }
            // This should never theoretically never be reached.
            return 0;
        }
    }
}
