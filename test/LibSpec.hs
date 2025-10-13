{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}

module LibSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Control.Exception (evaluate)
import Lib
import Data.Bits
import Crypto.Number.Basic (numBytes)
import Crypto.Util (bs2i, i2bs)
import Data.List (foldl')

spec :: Spec
spec = do
    expmodSpec
    nOfBytesSpec
    myLogSpec
    encryptDecryptSpec
    decryptSpec

expmodSpec :: Spec
expmodSpec = do
    describe "expmod" $ do
        modifyMaxSuccess (const 20) $ 
            prop "equal to other implementation" $ 
                prop_expmod

prop_expmod :: Property
prop_expmod =
    forAll (chooseInteger (10, 1000)) $ \m ->
    forAll (chooseInteger (1, 100)) $ \a ->
    forAll (chooseInteger (1, 100)) $ \k ->
    expmod m a k == expmod2 m a k
    where 
    expmod2 :: (Integral t, Integral a) => a -> a -> t -> a
    expmod2 m a 0 = 1
    expmod2 m a k =
        if even k
        then expmod2 m ((a*a) `mod` m) (k `div` 2)
        else (a * expmod2 m a (k - 1)) `mod` m

nOfBytesSpec :: Spec
nOfBytesSpec = do
    describe "nOfBytes" $ do
        prop "equal to other implementation" $ 
            prop_bytes

prop_bytes = \(LargeInteger (x :: Integer)) -> 
    nOfBytes x == numBytes x

newtype LargeInteger = LargeInteger Integer deriving (Show, Eq, Ord, Num)

instance Arbitrary LargeInteger where
    arbitrary :: Gen LargeInteger
    arbitrary = LargeInteger . fromWords <$> arbitrary
      where
        fromWords :: [Word8] -> Integer
        fromWords = foldl' go 0
        go :: Integer -> Word8 -> Integer
        go acc w = (acc `shiftL` 8) + fromIntegral w
    

prop_log = \(Positive (Large (x :: Int))) -> myLog x == helperLog x
    where
    helperLog :: Integral a => a -> Int
    helperLog x =
        if x <= 1
        then 0
        else 1 + helperLog (x `div` 2)

myLogSpec :: Spec
myLogSpec = do
    describe "myLog" $ do
        prop "equal to other implementation" $ 
            prop_log

encryptDecryptSpec :: Spec
encryptDecryptSpec = do
    describe "encrypt decrypt" $ do
        prop "encrypt then decrypt" $ 
            prop_encryptDecrypt

prop_encryptDecrypt :: Property
prop_encryptDecrypt = ioProperty $ do
    let modulusSizeBytes = 128
    let modulusSizeBits = modulusSizeBytes * 8
    (pubKey, privKey) <- genKeysSilent modulusSizeBits
    let bs :: ByteString = B.singleton 0x00 <> B.replicate (modulusSizeBytes - 1) 0b101
    let m = bs2i bs
    let mEncrypted = encrypt pubKey m
    return $ 
        decryptClassic privKey mEncrypted == m 

decryptSpec :: Spec
decryptSpec = do
    describe "decryption" $ do
        prop "decryptClassic is equal to decryptCRT" $ 
            prop_decrypt

prop_decrypt :: Property
prop_decrypt = ioProperty $ do
    let modulusSizeBytes = 128
    let modulusSizeBits = modulusSizeBytes * 8
    (pubKey, privKey) <- genKeysSilent modulusSizeBits
    let bs :: ByteString = B.singleton 0x00 <> B.replicate (modulusSizeBytes - 1) 0b101
    let m = bs2i bs
    let mEncrypted = encrypt pubKey m
    return $ 
        decryptClassic privKey mEncrypted == decryptCRT privKey mEncrypted