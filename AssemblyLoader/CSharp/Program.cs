using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
namespace CSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            Process p = Process.Start("calc.exe");
            foreach (var s in args)
            {
                Console.WriteLine(s);
            }
        }
    }
}