import unittest

from greeting import greeting


class GreetingTests(unittest.TestCase):
    def test_greeting_includes_punctuation(self) -> None:
        self.assertEqual(greeting("Ada"), "Hello, Ada!")


if __name__ == "__main__":
    unittest.main()

