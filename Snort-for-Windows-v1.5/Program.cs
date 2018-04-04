using System;
using System.Text.RegularExpressions;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//Request library
using System.Net;
using System.IO;
using System.Collections.Generic;
using static System.Console;

namespace Snort_for_Windows_v1.5
{
    class Program
    {
        public static void Welcome()
        {
            Console.WriteLine("                     _____             _        _____     _          ");
            Console.WriteLine("                    |   __|___ ___ ___| |_     | __  |_ _| |___ ___  ");
            Console.WriteLine("                    |__   |   | . |  _|  _|    |    -| | | | -_|_ -| ");
            Console.WriteLine("                    |_____|_|_|___|_| |_|      |__|__|___|_|___|___| ");
            Console.WriteLine("                      ___            _ _ _ _       _                 ");
            Console.WriteLine("                     |  _|___ ___   | | | |_|___ _| |___ _ _ _ ___   ");
            Console.WriteLine("                     |  _| . |  _|  | | | | |   | . | . | | | |_ -|  ");
            Console.WriteLine("                     |_| |___|_|    |_____|_|_|_|___|___|_____|___|  ");
            Console.WriteLine("");
            Console.WriteLine("  *************************************************************************************");
            Console.WriteLine("  *                  Welcome to the Snort Rules finder for Windows!                   *");
            Console.WriteLine("  *                                  *  *  *  *  *  *                                 *");
            Console.WriteLine("  *  When searching the full rule set, it may take a few minutes to locate your SID.  *");
            Console.WriteLine("  *               Use 'Ctrl + C' if you need to force quit the program                *");
            Console.WriteLine("  *************************************************************************************");
        }

        public static void GetRules(string sid)
        {
            string snortNum = sid;                                      //Resting variable to empty string.
            string html = "";
            //string html = string.Empty;               //Temporarily commented out to see if changing from string.Empty to a blank string "" fixes loop timeout error
            string url = @"http://securityonion2.vcu.edu:50000/downloaded.rules";

            Dictionary<string, string> allTheThings = new Dictionary<string, string>();

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                //html = reader.ReadToEnd();          //Saves the downloaded.rules content to the string 'html'
                while (!sr.EndOfStream)
                {
                    string splitMe = sr.ReadLine();
                    string[] bananaSplits = splitMe.Split(new char[] { ':' }); //Split at the colons

                    if (bananaSplits.Length < 2) // If we get less than 2 results, discard them
                        continue;
                    else if (bananaSplits.Length == 2) // Easy part. If there are 2 results, add them to the dictionary
                        allTheThings.Add(bananaSplits[0].Trim(), bananaSplits[1].Trim());
                    else if (bananaSplits.Length > 2)
                        SplitItGood(splitMe, allTheThings); // Hard part. If there are more than 2 results, use the method below.
                }
            }


            //Console.WriteLine(html);              //This line will output the entire contents of the downloaded.rules file

            Regex r = new Regex(".*" + snortNum + ".*");
            // CaptureRegex cr = new CapturingRegex("sid:%9d");
            // foreach (Line l in html)
            // {
            //   SID = cr(line)
            //   myKVarray.Add( SID, line)
            // }

            foreach (Match m in r.Matches(html))
            {
                Console.WriteLine(m.Value);
                Console.WriteLine("");
                break;
            }

        }

        static void Main(string[] args)
        {
            string response = "Yes";
            Welcome();

            do
            {
                string sid = "";                                    //Resting variable to 0.

                Console.Write("\nPlease enter the Snort SID: ");      //Outputs message to console.
                sid = Console.ReadLine();                           //Accept user entered SID value.

                GetRules(sid);                                      //Pass 'sid' to the GetRules Function

                Console.Write("Would you like to search for another Snort Rule? (Yes or no?) ");
                response = Console.ReadLine();                      //Option for user to run program again to search for more rules.
            }
            while (response == "Yes" || response == "yes" || response == "Y" || response == "y");
            {
                Console.WriteLine("\nThank you for using the Snort Rule Program for Windows!");
            }

        }
    }
}
