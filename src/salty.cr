require "./salty/*"
require "base64"

@[Link("sodium")]
lib Sodium
  fun sodium_version_string : UInt8*
  fun crypto_generichash_primitive : UInt8*
  fun crypto_generichash_blake2b_bytes_min : UInt8
  fun crypto_generichash_blake2b_bytes_max : UInt8
  fun crypto_sign_ed25519_seedbytes : UInt16
  fun crypto_sign_ed25519_publickeybytes : UInt16
  fun crypto_sign_ed25519_secretkeybytes : UInt16
  fun crypto_sign_ed25519_bytes : UInt16
  fun crypto_sign_ed25519_seed_keypair(UInt8*, UInt8*, UInt8*) : LibC::Int
  fun randombytes_buf(UInt8*, UInt16)
  fun crypto_sign_ed25519(UInt8*, UInt64*, UInt8*, UInt64, UInt8*) : LibC::Int
  fun crypto_sign_ed25519_open(UInt8*, UInt64*, UInt8*, UInt64, UInt8*) : LibC::Int
  fun crypto_sign_ed25519_verify_detached(UInt8*, UInt8*, UInt64, UInt8*) : LibC::Int
end

module Salty
  def self.genseed
    randseed = Slice(UInt8).new(Sodium.crypto_sign_ed25519_seedbytes)
    Sodium.randombytes_buf(randseed, Sodium.crypto_sign_ed25519_seedbytes)
    randseed.to_unsafe
  end

  def self.genkey(seed)
    pk = Slice(UInt8).new(Sodium.crypto_sign_ed25519_publickeybytes)
    sk = Slice(UInt8).new(Sodium.crypto_sign_ed25519_secretkeybytes)
    Sodium.crypto_sign_ed25519_seed_keypair(pk, sk, seed)
    {pk, sk}
  end

  def self.sign(msg, sk)
    signature = Slice(UInt8).new(Sodium.crypto_sign_ed25519_bytes)
    signature.copy_from msg.to_slice
    buf_len = Slice(UInt64).new(64)
    Sodium.crypto_sign_ed25519(signature, buf_len, msg, msg.bytesize, sk)
    signature
  end

  def self.verify(signature, msg, pk)
    sm = String.new(signature) + msg
    buffer = Slice(UInt8).new(sm.bytesize)
    buf_len = Slice(UInt64).new(64)
    Sodium.crypto_sign_ed25519_open(buffer, buf_len, sm, sm.bytesize, pk) == 0 ? true : false
  end

  abort "use genkey, sign, or verify" if ARGV.size == 0
  case ARGV.first
  when "genkey"
    pk, sk = genkey(genseed)
    puts "public key: #{Base64.strict_encode(pk)}"
    puts "private key: #{Base64.strict_encode(sk)}"
  when "sign"
    message = ARGV[1]
    sk = Base64.decode ARGV[2]
    sig = sign(message, sk)
    puts "Signature: #{Base64.strict_encode(sig)}"
  when "verify"
    message = ARGV[1]
    sig = Base64.decode ARGV[2]
    pk = Base64.decode ARGV[3]
    puts verify(sig, message, pk)
  end

  # p ARGV.first
  # seed = genseed
  # pk, sk = genkey(seed)
  # sig = sign("Monkey", sk)
  # p verify(sig, "Monkey", pk)

  # TODO Put your code here
  # puts String.new(Sodium.sodium_version_string)
  # puts String.new(Sodium.crypto_generichash_primitive)
  # puts Sodium.crypto_generichash_blake2b_bytes_min
  # puts Sodium.crypto_generichash_blake2b_bytes_max
  # puts Sodium.crypto_sign_ed25519_seedbytes
  # puts Sodium.crypto_sign_ed25519_publickeybytes
  # puts Sodium.crypto_sign_ed25519_secretkeybytes
  # msg = "Hello"
  # randseed = Slice(UInt8).new(Sodium.crypto_sign_ed25519_seedbytes)
  # puts randseed
  # Sodium.randombytes_buf(randseed, Sodium.crypto_sign_ed25519_seedbytes)
  # puts randseed
  # pk = Slice(UInt8).new(Sodium.crypto_sign_ed25519_publickeybytes)
  # sk = Slice(UInt8).new(Sodium.crypto_sign_ed25519_secretkeybytes)
  # p Sodium.crypto_sign_ed25519_seed_keypair(pk, sk, randseed)
  # signature = Slice(UInt8).new(Sodium.crypto_sign_ed25519_bytes)
  # puts signature.bytesize
  # puts msg.bytesize
  # # msg.to_slice.copy_to signature
  # signature.copy_from msg.to_slice
  # puts signature
  # # puts String.new(signature)
  # puts signature.bytesize
  # # # buf_len = Pointer(UInt64).malloc(64)
  # buf_len = Slice(UInt64).new(64)
  # p Sodium.crypto_sign_ed25519(signature, buf_len, msg, msg.bytesize, sk)
  # puts signature
  # # puts String.new(signature)
  # puts signature.bytesize
  # # buf_len = Slice(UInt64).new(64)
  # sm = String.new(signature) + msg
  # puts sm
  # # # buffer = Pointer(UInt8).malloc(sm.bytesize)
  # buffer = Slice(UInt8).new(sm.bytesize)
  # p Sodium.crypto_sign_ed25519_open(buffer, buf_len, sm, sm.bytesize, pk)
end
