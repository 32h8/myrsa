{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module OAEP
    ( hLen
    , maxMessageSizeBytes
    , encode
    , decode
    , minModulusSizeBytes
    , prop_encodeDecode
    ) where

import MGF (mgf1)

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Data.Bits
import Crypto.Util (bs2i, i2bs)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.UTF8 as BSU
import Test.QuickCheck 

-- length of the output of the hash function in bytes
hLen :: Int
hLen = 32

-- empty label
labelStr :: String
labelStr = ""

checkHashLen :: ByteString -> ByteString
checkHashLen bs = 
    if B.length bs /= hLen
    then error "error when hashing a label. Expected different hash length."
    else bs

-- hash of label
labelHash :: ByteString
labelHash = checkHashLen $ SHA256.hash $ BSU.fromString labelStr

maxMessageSizeBytes :: Int -> Int
maxMessageSizeBytes k = k - 2 * hLen - 2

-- size in bytes
minModulusSizeBytes :: Int
minModulusSizeBytes = 128

-- RFC 8017 for PKCS#1 v2.2
encode :: Int -> ByteString -> ByteString -> ByteString
encode k seed msg
    | k < minModulusSizeBytes = error $ "encoding error: length of modulus should be at least " ++ show minModulusSizeBytes ++ " bytes"
    | mLen > maxMessageSizeBytes k = error "encoding error: message is too big to encode"
    | B.length seed /= hLen = error "encoding error: seed has invalid size"
    | otherwise = B.singleton 0x00 <> maskedSeed <> maskedDB
    where
        mLen = B.length msg
        psLen = k - mLen - (2 * hLen) - 2
        ps :: ByteString = B.replicate psLen 0x00
        db :: ByteString = labelHash <> ps <> B.singleton 0x01 <> msg
        dbMask :: ByteString = mgf1 seed (k - hLen - 1)
        maskedDB :: ByteString = 
            if B.length db /= B.length dbMask 
            then error "encoding error: data block mask length is invalid"
            else B.packZipWith xor db dbMask
        seedMask :: ByteString = mgf1 maskedDB hLen
        maskedSeed :: ByteString =
            if B.length seed /= B.length seedMask
            then error "encoding error: seed mask length is invalid"
            else B.packZipWith xor seed seedMask

decode :: Int -> ByteString -> ByteString
decode k bs
    | k < minModulusSizeBytes = error "decoding error: length of modulus should be at least 128 bytes"
    | B.length bs /= k = error $ "decoding error: invalid padding: wrong block length, expected " ++ show k ++ " length." 
    | B.head bs /= 0x00 = error "decoding error: invalid padding: first byte should be 0x00"
    | otherwise = 
        let (maskedSeed, maskedDB) = B.splitAt hLen (B.tail bs)
            seedMask = mgf1 maskedDB hLen 
            seed = B.packZipWith xor maskedSeed seedMask
            dbMask = mgf1 seed (k - hLen - 1)
            db = if B.length dbMask /= B.length maskedDB
                then error "decoding internal error: invalid dbMask length"
                else B.packZipWith xor maskedDB dbMask
        in case B.stripPrefix labelHash db of
            Nothing -> error "decoding error: invalid padding: label hash doesn't match"
            (Just dbSuffixNoLHash) ->
                let dbSuffixNoPS = B.dropWhile (== 0x00) dbSuffixNoLHash
                in if B.length dbSuffixNoPS < 1
                    then error "decoding error: invalid padding: missing separator byte 0x01"
                    else if B.head dbSuffixNoPS /= 0x01
                        then error "decoding error: invalid padding: wrong separator byte"
                        else B.tail dbSuffixNoPS

prop_encodeDecode :: Property
prop_encodeDecode =
    forAll (vectorOf hLen arbitrary) $ \(xs :: [Word8]) ->
        let seed = B.pack xs in 
        forAll (chooseInt (128, 256)) $ \k ->
        let maxMsgBytes = maxMessageSizeBytes k in
        forAll (chooseInt (0, maxMsgBytes)) $ \mLen ->
        forAll (vectorOf mLen arbitrary) $ \(ms :: [Word8]) ->
        let msg = B.pack ms in
        decode k (encode k seed msg) == msg 