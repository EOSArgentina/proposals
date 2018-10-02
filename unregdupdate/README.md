# Overview

https://eosauthority.com/approval/view.php?scope=argentinaeos&name=unregdupdate

The `unregdupdate` proposal adds three functions to the `eosio.unregd` contract (besides other actions, see below).

```c++
void regaccount(const bytes& signature, const string& account, const string& eos_pubkey);
void setmaxeos(const asset& maxeos);
void chngaddress(const ethereum_address& old_address, const ethereum_address& new_address);
```

##### regaccount
Allows a user who didn't registered a public key in the contribution period to claim their EOS tokens.
This is being done by providing a signature using the ETH private key of the account used to make the contribution.

##### setmaxeos
Determines the max amount of EOS that the contract will pay when creating a new account with 8k of RAM.
This function gives control to the BPs on how much to spend for the account creation of unregistered users.
Must be called periodically based on current RAM price.

##### chngaddress
This function allows to change the Ethereum address that owns an EOS balance in the `eosio.unregd` addresses table.
This will be useful for ETH addresses that the owner doesn't have a private key for (contracts).

Also based on the feedback provided by b1, now the contract works in this way:

- Accounts are created by `eosio.unregd` (this is to prevent making `eosio.unregd` a privileged account)
- No new tokens are issued by `eosio.unregd`
- RAM costs are deducted from the `eosio.regram` account balance
- BPs can set the MAX amount of EOS willing to pay for a new account (8k of RAM)

*See discussion here: https://github.com/eoscanada/eos-bios/pull/33*

# Important notes for top 21 BPs

**The `regaccount` action is CPU heavy.**

Most of the time spent by this action is used by the `uECC_decompress` function call which is 100% implemented on WASM.

This is because the `recover_key` intrinsic used to get the ECC public key from the signature, returns the public key in compressed format and the contract needs the uncompressed version to calculate the ETH address.

Tests on i7-7700HQ CPU with `binaryen` runtime shows **~40ms** of cpu usage.

Tests Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz with `wabt` runtime shows **~25ms** of cpu usage.

Examples on Kylin:
- https://kylin.bloks.io/block/13274487 (~77ms)
- https://kylin.bloks.io/block/13275281 (~23ms)
- https://kylin.bloks.io/block/13275667 (~20ms)

# Build latest eosio.unregd

```shell
git clone https://github.com/eoscanada/eos-bios.git

cd eos-bios/eosio.unregd

eosiocpp -o eosio.unregd.wast eosio.unregd.cpp
```

# Validate unregdupdate proposal

## Dump proposal

```shell
cleos -u https://api.eosargentina.io multisig review argentinaeos unregdupdate > unregdupdate.json
```

## Show proposal actions
```shell
cat unregdupdate.json | jq -r '.transaction.actions[] | (.account+"::"+.name)'
```

```
eosio::newaccount
eosio::buyrambytes
eosio.token::transfer
eosio::updateauth
eosio::setcode
eosio::setabi
eosio.unregd::setmaxeos
```

## Validating 1st action (eosio.regram account creation)

```shell
cat unregdupdate.json | jq '.transaction.actions[0].data'
```

```json
{
  "creator": "eosio",
  "name": "eosio.regram",
  "owner": {
    "threshold": 1,
    "keys": [],
    "accounts": [
      {
        "permission": {
          "actor": "eosio",
          "permission": "active"
        },
        "weight": 1
      }
    ],
    "waits": []
  },
  "active": {
    "threshold": 1,
    "keys": [],
    "accounts": [
      {
        "permission": {
          "actor": "eosio",
          "permission": "active"
        },
        "weight": 1
      },
      {
        "permission": {
          "actor": "eosio.unregd",
          "permission": "eosio.code"
        },
        "weight": 1
      }
    ],
    "waits": []
  }
}
```

## Validating 2nd action (buy 2k of RAM for eosio.regram)

```shell
cat unregdupdate.json | jq '.transaction.actions[1].data'
```

```json
{
  "payer": "eosio",
  "receiver": "eosio.regram",
  "bytes": 2000
}
```


## Validating 3rd action (transfer 26000.0000 EOS from eosio.saving to eosio.regram)

*Note: 26000 EOS ~= number_of_unregistered_accounts * max_eos_willing_to_pay_for_8k_of_RAM*


```shell
cat unregdupdate.json | jq '.transaction.actions[2].data'
```

```json
{
  "from": "eosio.saving",
  "to": "eosio.regram",
  "quantity": "26000.0000 EOS",
  "memo": "to pay for RAM costs of unregistered accounts"
}
```

## Validating 4th action (add eosio.unregd@eosio.code to the *active* permission of eosio.unregd)

```shell
cat unregdupdate.json | jq '.transaction.actions[3].data'
```

```json
{
  "account": "eosio.unregd",
  "permission": "active",
  "parent": "owner",
  "auth": {
    "threshold": 1,
    "keys": [],
    "accounts": [
      {
        "permission": {
          "actor": "eosio",
          "permission": "active"
        },
        "weight": 1
      },
      {
        "permission": {
          "actor": "eosio.unregd",
          "permission": "eosio.code"
        },
        "weight": 1
      }
    ],
    "waits": []
  }
}
```

## Validating 5th action (set new code for eosio.unregd)

```shell
cat unregdupdate.json | jq '.transaction.actions[4].data.code' | xxd -r -p | sha256sum 
eefd39e3bb5ad6d723cc9863cd3ed6d8c612259cbe17f3ec9af2a2229bf07d7e

sha256sum eos-bios/eosio.unregd/eosio.unregd.wasm 
eefd39e3bb5ad6d723cc9863cd3ed6d8c612259cbe17f3ec9af2a2229bf07d7e  eosio.unregd.wasm
```

## Validating 6th action (set new ABI for eosio.unregd)

```shell
cat unregdupdate.json | jq -r '.transaction.actions[5].data.abi' | abi_hex_to_json | jq '' > /tmp/abi1.json
cat eos-bios/eosio.unregd/eosio.unregd.abi | jq '' > /tmp/abi2.json
diff /tmp/abi1.json /tmp/abi2.json
```

```diff
1a2
>   "____comment": "This file was generated by eosio-abigen. DO NOT EDIT - 2018-09-02T08:20:41",
```

*abi_hex_to_json: https://gist.github.com/elmato/4fce5bd325ca56bf037f4f906d0a67ae*


## Validating 6th action (set max EOS for 8k RAM (1.30 EOS or 0.1625 EOS per k))

```shell
curl -s -X POST -d '{"code":"eosio.unregd","action":"setmaxeos","binargs":"'$(cat unregdupdate.json | jq -r '.transaction.actions[6].data')'"}' https://api-kylin.eosasia.one/v1/chain/abi_bin_to_json | jq '.args'
```

```json
{
  "maxeos": "1.3000 EOS"
}
```

# eosio.unregd.hpp diff

```diff
diff --git a/eosio.unregd/eosio.unregd.hpp b/eosio.unregd/eosio.unregd.hpp
index 1a71230..5bc6c68 100644
--- a/eosio.unregd/eosio.unregd.hpp
+++ b/eosio.unregd/eosio.unregd.hpp
@@ -1,9 +1,34 @@
 #include <functional>
 #include <string>
+#include <cmath>
 
-#include <eosiolib/asset.hpp>
+#include <eosiolib/transaction.h>
 #include <eosiolib/eosio.hpp>
+#include <eosiolib/asset.hpp>
+#include <eosiolib/multi_index.hpp>
 #include <eosiolib/fixed_key.hpp>
+#include <eosiolib/public_key.hpp>
+
+#include "ram/exchange_state.cpp"
+
+#define USE_KECCAK
+#include "sha3/byte_order.c"
+#include "sha3/sha3.c"
+
+#include "abieos_numeric.hpp"
+#define uECC_SUPPORTS_secp160r1 0
+#define uECC_SUPPORTS_secp192r1 0
+#define uECC_SUPPORTS_secp224r1 0
+#define uECC_SUPPORTS_secp256r1 0
+#define uECC_SUPPORTS_secp256k1 1
+#define uECC_SUPPORT_COMPRESSED_POINT 1
+#include "ecc/uECC.c"
+
+using namespace eosio;
+using namespace std;
+
+#include "utils/inline_calls_helper.hpp"
+#include "utils/snapshot.hpp"
 
 // Macro
 #define TABLE(X) ::eosio::string_to_name(#X)
@@ -22,11 +47,15 @@ namespace eosio {
 
 class unregd : public contract {
  public:
-  unregd(account_name contract_account)
-      : eosio::contract(contract_account), addresses(contract_account, contract_account) {}
+  unregd(account_name contract_account) : eosio::contract(contract_account),
+      addresses(_self, _self),
+      settings(_self, _self) {}
 
   // Actions
   void add(const ethereum_address& ethereum_address, const asset& balance);
+  void regaccount(const bytes& signature, const string& account, const string& eos_pubkey);
+  void setmaxeos(const asset& maxeos);
+  void chngaddress(const ethereum_address& old_address, const ethereum_address& new_address);
 
  private:
   static uint8_t hex_char_to_uint(char character) {
@@ -50,6 +79,11 @@ class unregd : public contract {
     return key256::make_from_word_sequence<uint32_t>(p32[0], p32[1], p32[2], p32[3], p32[4]);
   }
 
+  static key256 compute_ethereum_address_key256(uint8_t* ethereum_key) {
+    const uint32_t* p32 = reinterpret_cast<const uint32_t*>(ethereum_key);
+    return key256::make_from_word_sequence<uint32_t>(p32[0], p32[1], p32[2], p32[3], p32[4]);
+  }
+
   //@abi table addresses i64
   struct address {
     uint64_t id;
@@ -67,9 +101,21 @@ class unregd : public contract {
       indexed_by<N(ethereum_address), const_mem_fun<address, key256, &address::by_ethereum_address>>>
       addresses_index;
 
+  //@abi table settings i64
+  struct settings {
+    uint64_t id;
+    asset    max_eos_for_8k_of_ram;
+
+    uint64_t primary_key() const { return id; }
+    EOSLIB_SERIALIZE(settings, (id)(max_eos_for_8k_of_ram))
+  };
+
+  typedef eosio::multi_index<TABLE(settings), settings> settings_index;
+
   void update_address(const ethereum_address& ethereum_address, const function<void(address&)> updater);
 
   addresses_index addresses;
+  settings_index settings;
 };
 
 }  // namespace eosio
```

# eosio.unregd.cpp diff
```diff
diff --git a/eosio.unregd/eosio.unregd.cpp b/eosio.unregd/eosio.unregd.cpp
index b976810..c84d558 100644
--- a/eosio.unregd/eosio.unregd.cpp
+++ b/eosio.unregd/eosio.unregd.cpp
@@ -1,8 +1,8 @@
 #include "eosio.unregd.hpp"
-
+#include <eosiolib/crypto.h>
 using eosio::unregd;
 
-EOSIO_ABI(eosio::unregd, (add))
+EOSIO_ABI(eosio::unregd, (add)(regaccount)(setmaxeos)(chngaddress))
 
 /**
  * Add a mapping between an ethereum_address and an initial EOS token balance.
@@ -21,6 +21,159 @@ void unregd::add(const ethereum_address& ethereum_address, const asset& balance)
   });
 }
 
+/**
+ * Change the ethereum address that owns a balance
+ */
+void unregd::chngaddress(const ethereum_address& old_address, const ethereum_address& new_address) {
+  require_auth(_self);
+
+  eosio_assert(old_address.length() == 42, "Old Ethereum address should have exactly 42 characters");
+  eosio_assert(new_address.length() == 42, "New Ethereum address should have exactly 42 characters");
+
+  auto index = addresses.template get_index<N(ethereum_address)>();
+  auto itr = index.find(compute_ethereum_address_key256(old_address));
+
+  eosio_assert( itr != index.end(), "Old Ethereum address not found");
+
+  index.modify(itr, _self, [&](auto& address) {
+    address.ethereum_address = new_address;
+  });
+}
+
+/**
+ * Sets the maximum amount of EOS this contract is willing to pay when creating a new account
+ */
+void unregd::setmaxeos(const asset& maxeos) {
+  require_auth(_self);
+
+  auto symbol = maxeos.symbol;
+  eosio_assert(symbol.is_valid() && symbol == CORE_SYMBOL, "maxeos invalid symbol");
+
+  auto itr = settings.find(1);
+  if (itr == settings.end()) {
+    settings.emplace(_self, [&](auto& s) {
+      s.id = 1;
+      s.max_eos_for_8k_of_ram = maxeos;
+    });
+  } else {
+    settings.modify(itr, 0, [&](auto& s) {
+      s.max_eos_for_8k_of_ram = maxeos;
+    });
+  }
+}
+
+/**
+ * Register an EOS account using the stored information (address/balance) verifying an ETH signature
+ */
+void unregd::regaccount(const bytes& signature, const string& account, const string& eos_pubkey_str) {
+
+  eosio_assert(signature.size() == 66, "Invalid signature");
+  eosio_assert(account.size() == 12, "Invalid account length");
+
+  // Verify that the destination account name is valid
+  for(const auto& c : account) {
+    if(!((c >= 'a' && c <= 'z') || (c >= '1' && c <= '5')))
+      eosio_assert(false, "Invalid account name");
+  }
+
+  auto naccount = string_to_name(account.c_str());
+
+  // Verify that the account does not exists
+  eosio_assert(!is_account(naccount), "Account already exists");
+
+  // Rebuild signed message based on current TX block num/prefix, pubkey and name
+  const abieos::public_key eos_pubkey = abieos::string_to_public_key(eos_pubkey_str);
+
+  char tmpmsg[128];
+  sprintf(tmpmsg, "%u,%u,%s,%s", tapos_block_num(), tapos_block_prefix(),
+    eos_pubkey_str.c_str(), account.c_str());
+
+  //Add prefix and length of signed message
+  char message[128];
+  sprintf(message, "%s%s%d%s", "\x19", "Ethereum Signed Message:\n", strlen(tmpmsg), tmpmsg);
+
+  //Calculate sha3 hash of message
+  sha3_ctx shactx;
+  checksum256 msghash;
+  rhash_keccak_256_init(&shactx);
+  rhash_keccak_update(&shactx, (const uint8_t*)message, strlen(message));
+  rhash_keccak_final(&shactx, msghash.hash);
+
+  // Recover compressed pubkey from signature
+  uint8_t pubkey[64];
+  uint8_t compressed_pubkey[34];
+  auto res = recover_key(
+    &msghash,
+    signature.data(),
+    signature.size(),
+    (char*)compressed_pubkey,
+    34
+  );
+
+  eosio_assert(res == 34, "Recover key failed");
+
+  // Decompress pubkey
+  uECC_decompress(compressed_pubkey+1, pubkey, uECC_secp256k1());
+
+  // Calculate ETH address based on decompressed pubkey
+  checksum256 pubkeyhash;
+  rhash_keccak_256_init(&shactx);
+  rhash_keccak_update(&shactx, pubkey, 64);
+  rhash_keccak_final(&shactx, pubkeyhash.hash);
+
+  uint8_t eth_address[20];
+  memcpy(eth_address, pubkeyhash.hash + 12, 20);
+
+  // Verify that the ETH address exists in the "addresses" eosio.unregd contract table
+  addresses_index addresses(_self, _self);
+  auto index = addresses.template get_index<N(ethereum_address)>();
+
+  auto itr = index.find(compute_ethereum_address_key256(eth_address));
+  eosio_assert(itr != index.end(), "Address not found");
+
+  // Split contribution balance into cpu/net/liquid
+  auto balances = split_snapshot_abp(itr->balance);
+  eosio_assert(balances.size() == 3, "Unable to split snapshot");
+  eosio_assert(itr->balance == balances[0] + balances[1] + balances[2], "internal error");
+
+  // Get max EOS willing to spend for 8kb of RAM
+  asset max_eos_for_8k_of_ram = asset(0);
+  auto sitr = settings.find(1);
+  if( sitr != settings.end() ) {
+    max_eos_for_8k_of_ram = sitr->max_eos_for_8k_of_ram;
+  }
+
+  // Calculate the amount of EOS to purchase 8k of RAM
+  auto amount_to_purchase_8kb_of_RAM = buyrambytes(8*1024);
+  eosio_assert(amount_to_purchase_8kb_of_RAM <= max_eos_for_8k_of_ram, "price of RAM too high");
+
+  // Build authority with the pubkey passed as parameter
+  const auto auth = authority{
+    1, {{{(uint8_t)eos_pubkey.type, eos_pubkey.data} , 1}}, {}, {}
+  };
+
+  // Create account with the same key for owner/active
+  INLINE_ACTION_SENDER(call::eosio, newaccount)( N(eosio), {{N(eosio.unregd),N(active)}},
+    {N(eosio.unregd), naccount, auth, auth});
+
+  // Buy RAM for this account (8k)
+  INLINE_ACTION_SENDER(call::eosio, buyram)( N(eosio), {{N(eosio.regram),N(active)}},
+    {N(eosio.regram), naccount, amount_to_purchase_8kb_of_RAM});
+
+  // Delegate bandwith
+  INLINE_ACTION_SENDER(call::eosio, delegatebw)( N(eosio), {{N(eosio.unregd),N(active)}},
+    {N(eosio.unregd), naccount, balances[0], balances[1], 1});
+
+  // Transfer remaining if any (liquid EOS)
+  if( balances[2] != asset(0) ) {
+    INLINE_ACTION_SENDER(call::token, transfer)( N(eosio.token), {{N(eosio.unregd),N(active)}},
+    {N(eosio.unregd), naccount, balances[2], ""});
+  }
+
+  // Remove information for the ETH address from the eosio.unregd DB
+  index.erase(itr);
+}
+
 void unregd::update_address(const ethereum_address& ethereum_address, const function<void(address&)> updater) {
   auto index = addresses.template get_index<N(ethereum_address)>();
 
```

# Apendix

#### balance split function used by the contract (ABP)
```c++
   vector<asset> split_snapshot_abp(const asset& balance) {

      eosio_assert( balance >= asset(1000), "insuficient balance" );

      asset floatingAmount;

      if (balance > asset(110000)) { 
         floatingAmount = asset(100000);
      } else if (balance > asset(30000)) { 
         floatingAmount = asset(20000); 
      } else { 
         floatingAmount = asset(1000);
      }

      asset to_split  = balance - floatingAmount;
      
      asset split_cpu = to_split/2; 
      asset split_net = to_split - split_cpu;

      return {split_net, split_cpu, floatingAmount};
   }
```

#### ECC library
https://github.com/kmackay/micro-ecc

#### SHA3 library from RHash
https://github.com/rhash/RHash
