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
import Data.List (foldl')

spec :: Spec
spec = do
    encInputBlockSizeSpec
    encOutputBlockSizeSpec
    expmodSpec
    nOfBytesSpec
    myLogSpec

-- condition: the number formed by input block needs to be less than modulus
-- finds the max size of such block
encInputBlockSizeSpec :: Spec
encInputBlockSizeSpec = 
    describe "encInputBlockSize" $ do
        it "throws when arg <= 255" $
            evaluate (encInputBlockSize 0x_ff) `shouldThrow` anyErrorCall
        it "returns 1 byte" $ do
            encInputBlockSize 0x_____1_00 `shouldBe` 1 
        it "returns 1 byte" $ do
            encInputBlockSize 0x____ff_ff `shouldBe` 1
        it "returns 2 bytes" $ do
            encInputBlockSize 0x_01_00_00 `shouldBe` 2
        it "returns 2 bytes" $ do
            encInputBlockSize 0x_ff_ff_ff `shouldBe` 2
        prop "returns l for modulus 1^(8*l)" $
            \(Positive (l :: Int)) ->
                let modulus :: Integer = (1 `shiftL` (8 * l))
                in encInputBlockSize modulus == l
        prop "returns l - 1 for modulus 1^(8*l) - 1" $
            \(Positive (l :: Int)) ->
                let l2 = l + 1
                    modulus :: Integer = (1 `shiftL` (8 * l2)) - 1
                in encInputBlockSize modulus == l2 - 1


-- condition: output block must store the max output number (which is modulus - 1)
-- finds the minimum size of such block
encOutputBlockSizeSpec :: Spec
encOutputBlockSizeSpec = 
    describe "encOutputBlockSize" $ do
        it "returns 1 byte" $
            encOutputBlockSize 0x_______1 `shouldBe` 1
        it "returns 1 byte" $
            encOutputBlockSize 0x____1_00 `shouldBe` 2
        it "returns 2 bytes" $
            encOutputBlockSize 0x____1_01 `shouldBe` 2
        it "returns 2 bytes" $
            encOutputBlockSize 0x_1_00_00 `shouldBe` 3
        it "returns 3 bytes" $
            encOutputBlockSize 0x_1_00_01 `shouldBe` 3
        prop "returns l + 1 for modulus 1^(8*l)" $
            \(Positive (l :: Int)) ->
                let modulus :: Integer = (1 `shiftL` (8 * l))
                in encOutputBlockSize modulus == l + 1

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