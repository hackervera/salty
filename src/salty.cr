require "./salty/*"

@[Link("sodium")]
lib Sodium
  fun sodium_version_string : UInt8*
  fun crypto_generichash_primitive : UInt8*
  fun crypto_generichash_blake2b_bytes_min : UInt8
  fun crypto_generichash_blake2b_bytes_max : UInt8
  fun crypto_sign_ed25519_seedbytes : UInt16
  fun crypto_sign_ed25519_publickeybytes : UInt16
  fun crypto_sign_ed25519_secretkeybytes : UInt16
  fun randombytes_buf(UInt8*, UInt16)
  fun crypto_sign_ed25519
end

module Salty
  # TODO Put your code here
  puts String.new(Sodium.sodium_version_string)
  puts String.new(Sodium.crypto_generichash_primitive)
  puts Sodium.crypto_generichash_blake2b_bytes_min
  puts Sodium.crypto_generichash_blake2b_bytes_max
  puts Sodium.crypto_sign_ed25519_seedbytes
  puts Sodium.crypto_sign_ed25519_publickeybytes
  puts Sodium.crypto_sign_ed25519_secretkeybytes
  randseed = Pointer(UInt8).malloc(Sodium.crypto_sign_ed25519_seedbytes)
  Sodium.randombytes_buf(randseed, Sodium.crypto_sign_ed25519_seedbytes)
  pk = Pointer(Uint8).malloc(Sodium.crypto_sign_ed25519_publickeybytes)
  sk = Pointer(Uint8).malloc(Sodium.crypto_sign_ed25519_secretkeybytes)
  puts String.new(randseed)
end
