using Crypto.Core;
using S = System.Security.Cryptography;

using Crypto.Symetrical;

namespace Crypto.Client {

    class Program
    {
        public static void Main(string[] args)
        {
            
            var factory = new DESFactory();

            var des = factory.Create();
            

        }
        
        
        
    }
}

