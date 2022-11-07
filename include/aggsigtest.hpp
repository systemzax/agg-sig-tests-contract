#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/crypto_bls_ext.hpp>

using namespace eosio;

CONTRACT aggsigtest : public contract {
   public:
      using contract::contract;

      ACTION test(bls_public_key pubkey, bls_signature sig);
      ACTION test2(std::vector<bls_signature> sigs, bls_signature aggregate);
      ACTION test3(std::vector<bls_public_key> pubkeys, bls_signature aggregate);
      ACTION test4(std::vector<bls_public_key> pubkeys, std::vector<bls_signature> sigs);

      using test_action = action_wrapper<"test"_n, &aggsigtest::test>;



};