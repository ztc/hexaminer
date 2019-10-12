using System;

namespace ZTC.Hexaminer
{
    class Program
    {
        static void Main(string[] args)
        {
            var argstr = string.Join(" ",args);
            Console.WriteLine($"hex {argstr}");
        }
    }
}
