//	Buts:
// - Crypter un message
// - Le décrypter
// - Tester si la clé (mdp) est bonne et après le décrypter

#include <iostream>
#include <string>
#include <vector>




// Base class for all encryption algorithms
class Encryption
{
public:
	// Returns the encrypted input
	virtual std::string encrypt(std::string input, const std::string& PASSWORD) const = 0;

	// Returns the decrypted encrypted input
	virtual std::string decrypt(std::string encrypted, const std::string& PASSWORD) const = 0;

	// Checks if the password is correct
	// If correct, returns the decrypted encrypted input
	virtual std::pair<bool, std::string> check(std::string encrypted, const std::string& PASSWORD) const = 0;
};



/*
 *		Algorithm:
 * - Struct:
 * The encrypted data is composed by a header of 12 bytes and the encrypted input.
 *
 *
 * - Encryption: 
 * For the header we encrypt 3 ints (12 bytes) such that:
 * > a + b = c
 * We add for each character of the input the assigned password value such that: 
 * > input[i] += password[i % password.size()]
 *
 * - Decryption:
 * We subtract for each character of the input the assigned password value such that:
 * > input[i] -= password[i % password.size()]
 *
 * - Check:
 * We decrypt the first 12 bytes of the encrypted input, we have now 3 uints and the password is correct if:
 * > a + b = c
 */
class SimpleEncryption : public Encryption
{
private:
	struct Header
	{
		Header(const unsigned int a, const unsigned int b)
			: a(a), b(b), c(a * b)
		{}

		// Returns the data in string
		std::string toString() const
		{
			char *data = new char[12U];

			*reinterpret_cast<unsigned int*>(data + 0U) = a;
			*reinterpret_cast<unsigned int*>(data + 4U) = b;
			*reinterpret_cast<unsigned int*>(data + 8U) = c;
			

			return std::string(data, data + 12U);
		}

		unsigned int a,
			b,
			c;
	};


public:
	virtual std::string encrypt(std::string input, const std::string& PASSWORD) const override
	{
		// Header //
		// To assume that we can't overflow
		const Header HEADER(rand() % (1U << 16U), rand() % (1U << 16U));
		input = HEADER.toString() + input;

		// Encryption //
		// The shift of the index
		size_t passwordIndex = 0U;

		const size_t INPUT_SIZE = input.size();
		for (size_t i = 0U; i < INPUT_SIZE; i++)
		{
			input[i] += PASSWORD[passwordIndex];

			passwordIndex++;
			if (passwordIndex == PASSWORD.size())
				passwordIndex = 0U;
		}

		return input;
	}

	virtual std::string decrypt(std::string encrypted, const std::string& PASSWORD) const override
	{
		// Decryption //
		// The shift of the index
		size_t passwordIndex = 0U;

		const size_t ENCRYPTED_SIZE = encrypted.size();
		for (size_t i = 0U; i < ENCRYPTED_SIZE; i++)
		{
			encrypted[i] -= PASSWORD[passwordIndex];

			passwordIndex++;
			if (passwordIndex == PASSWORD.size())
				passwordIndex = 0U;
		}

		// We don't return the header
		return std::string(encrypted.begin() + 12U, encrypted.end());
	}

	// ! encrypted must have 12 chars in the minimal case
	virtual std::pair<bool, std::string> check(std::string encrypted, const std::string& PASSWORD) const override
	{
		// Decryption //
		// The shift of the index
		size_t passwordIndex = 0U;

		const size_t ENCRYPTED_SIZE = encrypted.size();

		// Header //
		size_t i = 0U;
		for (; i < 12U; i++)
		{
			encrypted[i] -= PASSWORD[passwordIndex];

			passwordIndex++;
			if (passwordIndex == PASSWORD.size())
				passwordIndex = 0U;
		}

		// We retrieve all the data of the header in the numerical form
		const unsigned int
			A = *reinterpret_cast<unsigned int*>(&encrypted[0U]),
			B = *reinterpret_cast<unsigned int*>(&encrypted[4U]),
			C = *reinterpret_cast<unsigned int*>(&encrypted[8U]);

		// Incorrect password
		if (A * B != C)
			return {false, ""};

		// Content //
		for (; i < ENCRYPTED_SIZE; i++)
		{
			encrypted[i] -= PASSWORD[passwordIndex];

			passwordIndex++;
			if (passwordIndex == PASSWORD.size())
				passwordIndex = 0U;
		}

		return { true, std::string(encrypted.begin() + 12U, encrypted.end()) };
	}
};




std::string strInput(const std::string& MSG)
{
	std::string in;

	std::cout << "- " << MSG << "\n> ";
	std::cin >> in;

	return in;
}



int main() {
	using namespace std;

	srand(1234U);


	// Encryption algorithm
	const Encryption* ALGO = new SimpleEncryption();

	
	// Encryption //
	const std::string INPUT = strInput("Data to encrypt"),
		PASSWORD = strInput("Password");

	const std::string ENCRYPTED = ALGO->encrypt(INPUT, PASSWORD);

	printf("\nEncryted: %s\n\n", ENCRYPTED.c_str());


	// Decryption //
	const std::string DECRYPTION_PASSWORD = strInput("Password to decrypt");

	const std::pair<bool, std::string> DECRYPTED = ALGO->check(ENCRYPTED, DECRYPTION_PASSWORD);

	// If correct we display the result
	if (DECRYPTED.first)
		printf("Good password!\n\n%s\n\n", DECRYPTED.second.c_str());
	else
		puts("Wrong password...\n\n");



	delete ALGO;

	return 0;
}
