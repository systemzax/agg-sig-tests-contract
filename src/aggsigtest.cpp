#include <aggsigtest.hpp>

std::vector<uint8_t> msg_1 = {51, 23, 56, 93, 212, 129, 128, 27, 
                         251, 12, 42, 129, 210, 9, 34, 98};

std::vector<uint8_t> msg_2 = { 16, 38, 54, 125, 71, 214, 217, 78, 
                            73, 23, 127, 235, 8, 94, 41, 53};



ACTION aggsigtest::test(bls_public_key pubkey, bls_signature sig) {

   bool ok = bls_verify(pubkey, sig, msg_1);

   print(ok, "\n");

   check(ok==true, "signature verification failed");

}


ACTION aggsigtest::test2(std::vector<bls_signature> sigs, bls_signature aggregate){

   bls_signature agg_result = bls_aggregate_sigs(sigs);

   check(agg_result == aggregate, "aggregates don't match" );

}

ACTION aggsigtest::test3(std::vector<bls_public_key> pubkeys, bls_signature aggregate){

   std::vector<std::vector<uint8_t>> msgs = {msg_1, msg_2};

   bool ok = bls_aggregate_verify(pubkeys, msgs, aggregate);
   
   print(ok, "\n");
   
   check(ok==true, "aggregate signature verification failed");

}

ACTION aggsigtest::test4(std::vector<bls_public_key> pubkeys, std::vector<bls_signature> sigs){

   bls_public_key aggpub = bls_aggregate_pubkeys(pubkeys);
   bls_signature aggsig = bls_aggregate_sigs(sigs);

   bool ok = bls_verify(aggpub, aggsig, msg_1);
   
   print(ok, "\n");
   
   check(ok==true, "aggregate signature verification failed");

}