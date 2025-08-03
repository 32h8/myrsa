{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module LibSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Control.Exception (evaluate)
import Lib (encInputBlockSize, encOutputBlockSize, expmod)

spec :: Spec
spec = do
    encInputBlockSizeSpec
    encOutputBlockSizeSpec
    expmodSpec

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

-- condition: output block must store the max output number (which is modulus - 1)
-- finds the minimum size of such block
encOutputBlockSizeSpec :: Spec
encOutputBlockSizeSpec = 
    describe "encOutputBlockSize" $ do
        it "returns 1 byte" $
            encOutputBlockSize 0x_______1 `shouldBe` 1
        it "returns 1 byte" $
            encOutputBlockSize 0x____1_00 `shouldBe` 1
        it "returns 2 bytes" $
            encOutputBlockSize 0x____1_01 `shouldBe` 2
        it "returns 2 bytes" $
            encOutputBlockSize 0x_1_00_00 `shouldBe` 2
        it "returns 3 bytes" $
            encOutputBlockSize 0x_1_00_01 `shouldBe` 3

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