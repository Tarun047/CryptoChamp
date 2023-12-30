using CryptoChamp.Cli;

var alice = new CryptoUser();
var bob = new CryptoUser();

var encapsulation = alice.GenerateEncapsulation(bob);
bob.AcceptEncapsulation(alice, encapsulation);

var cipherText  = alice.EncryptMessage("This is a super Secret", bob);
Console.WriteLine(cipherText);
var plainText = bob.DecryptMessage(cipherText, alice);
Console.WriteLine(plainText);