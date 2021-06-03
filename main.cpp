#include <UnitTest++/UnitTest++.h>
#include <Cipher.h>
#include <iostream>
#include <locale>
#include <codecvt>
using namespace std;
struct KeyB_fixture {
    Cipher * p;
    KeyB_fixture()
    {
        p = new Cipher(L"4");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("Б-О-Б-АА", codec.to_bytes(Cipher(L"4").encrypt(L"БОИОБ")));
    }
    TEST(LongKey) {
        CHECK_EQUAL("-АБОБА",codec.to_bytes(Cipher(L"6").encrypt(L"БОИОБ")));
    }
    TEST(NegativeKey) {
        CHECK_THROW(Cipher cp(L"-4"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(Cipher cp(L"Б,В"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(Cipher cp(L"1 1"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(Cipher cp(L""),cipher_error);
    }
    TEST(AlphaAndPunctuationInKey) {
        CHECK_THROW(Cipher cp(L"ДЭБ4!!!"),cipher_error);
    }
}
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("О-И-О-ББ",
                    codec.to_bytes(p->encrypt(L"БОИОБ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("О-И-О-ББ",
                    codec.to_bytes(p->encrypt(L"боиоб")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("О-И-О-ББ",
                    codec.to_bytes(p->encrypt(L"Б!О И О,Б")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("О-И-О-ББ", codec.to_bytes(p->encrypt(L"БО11И3ОБ")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"),cipher_error);
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("БОИОБ",
                    codec.to_bytes(p->decrypt(L"О-И-О-ББ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"О-И-О-ББ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"О-И-О -ББ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"О-23И-О-ББ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHsssssssECK_THROW(p->decrypt(L"О-И,-О-Б,Б"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}
int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
