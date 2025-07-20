{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Lib
    ( enc, dec, genKeys, nOfBits, PubKey(..), PrivKey(..)
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits
import System.IO
import Crypto.Number.Prime (generatePrime)
import Crypto.Number.Basic (gcde)
import Crypto.Util (bs2i, i2bs)
import GHC.Num (integerFromInt, integerToInt)
import Control.Monad (when)

someFunc :: IO ()
someFunc = putStrLn "someFunc"

newtype PubKey = PubKey (Integer, Integer)
newtype PrivKey = PrivKey (Integer, Integer)

-- returns floor of logarithm with base 2
myLog :: Integer -> Int
myLog x =
    if x <= 1
    then 0
    else 1 + myLog (x `div` 2)

nOfBits :: Integer -> Int
nOfBits x = 1 + myLog x  

-- number of bytes in encryption input block
-- argument is modulus
encInputBlockSize :: Integer -> Int
encInputBlockSize n
    | n <= (2^8 - 1) = error "too small n: can't encrypt even 1 byte"
    | otherwise = go 1 (2^8)
    where
    -- max value for k bytes is (2^8)^k - 1
    -- finds maximum k such that
    -- (2^8)^k - 1 < n
    -- so (2^8)^k < n + 1
    n2 = n + 1
    go :: Int -> Integer -> Int
    go !k x =
        let x2 = x `shiftL` 8 
        in if x2 < n2 then go (k+1) x2 else k

-- number of bytes in encryption output block
-- argument is modulus
encOutputBlockSize :: Integer -> Int
encOutputBlockSize n = go 1 (2^8)
    where
    -- max value for k bytes is (2^8)^k - 1 
    -- finds minimum k such that 
    -- (2^8)^k - 1 >= n - 1
    -- so (2^8)^k >= n
    go :: Int -> Integer -> Int
    go !k x =
        if x >= n
        then k
        else go (k+1) $ x `shiftL` 8 

-- expmod m a k = a^k mod m 
expmod :: (Integral a, Integral p) => p -> p -> a -> p
expmod m a k = expmod' a k 1
    where
    expmod' a k s
        | k == 0 = s
        | otherwise = expmod' (a*a `mod` m) (k `div` 2) $ if even k then s else s*a `mod` m

enc :: PubKey -> Handle -> Handle -> IO ()
enc (PubKey (n, e)) hIn hOut = 
    loop
    where
    inBlockSize = encInputBlockSize n -- bytes
    outBlockSize = encOutputBlockSize n
    outBits = (outBlockSize * 8)

    loop = do
        bs <- B.hGet hIn inBlockSize
        let m = bs2i bs
        let m2 = expmod n m e
        let bsOut = i2bs outBits m2
        B.hPut hOut bsOut
        eof <- hIsEOF hIn
        if eof 
        then do
            -- we write the size (in bytes) of last chunk (in plaintext)
            let lastChunkSize = integerFromInt $ B.length bs
            B.hPut hOut $
                i2bs outBits lastChunkSize
        else loop

dec :: PrivKey -> Handle -> Handle -> IO ()
dec (PrivKey (n, d)) hIn hOut = 
    go
    where
    inBlockSize = encOutputBlockSize n
    outBlockSize = encInputBlockSize n
    outBits = outBlockSize * 8

    go :: IO ()
    go = do
        bs <- B.hGet hIn inBlockSize
        eof <- hIsEOF hIn
        if eof
        then return ()
        else do
            let m = bs2i bs
            let m2 = expmod n m d
            loop m2
    loop prevDecryptedBlock = do
        bs <- B.hGet hIn inBlockSize
        eof <- hIsEOF hIn
        if eof
        then do
            let lastChunkBytes = integerToInt $ bs2i bs
            B.hPut hOut $ i2bs (lastChunkBytes * 8) prevDecryptedBlock
        else do
            B.hPut hOut $ i2bs outBits prevDecryptedBlock
            let m = bs2i bs
            let m2 = expmod n m d
            loop m2

genKeys :: Int -> IO (PubKey, PrivKey)
genKeys size = do
    putStrLn $ "generating keys of size " ++ show size ++ " bits"
    -- TODO: check if size is valid
    let primeSize = size `div` 2
    when (primeSize < 5) $ error "Aborting. Invalid key size which should be >= 10bits."
    hFlush stdout
    p <- generatePrime primeSize
    q <- generatePrime primeSize
    let n = p * q
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits"
    hFlush stdout
    -- Euler's totient function
    let tot = (p - 1) * (q - 1)
    let e = 2^16 + 1
    putStrLn $ "using public exponent e = " ++ show e
    when (not $ 1 < e) $ error "error: e param should be > 1"
    when (not $ e < tot) $ error "error: e param should be < totient. Try increasing key size."
    let d = mminv e tot
    return (PubKey (n, e), PrivKey (n, d)) 

-- modular multiplicative inverse of a modulo m
mminv :: Integer -> Integer -> Integer
mminv a m =
    let (x, _y, gcd_am) = mygcde a m
    -- let (x, _y, gcd_am) = gcde a m -- external func
    in if gcd_am /= 1
        then error "cannot find modular multiplicative inverse of a modulo m because a and m are not coprime"
        else x `mod` m -- fixes sign 

-- extended Euclidean algorithm
-- ax + by = gdc(a,b)
-- egcde a b == (x,y,gcd a b)
mygcde :: Integer -> Integer -> (Integer, Integer, Integer)
mygcde a b = 
    loop a b 1 0 0 1
    where
    loop !old_r !r !old_s !s !old_t !t =
        if r /= 0
        then 
            let qoutient = old_r `div` r
                (old_r', r') = (r, old_r - qoutient * r)
                (old_s', s') = (s, old_s - qoutient * s)
                (old_t', t') = (t, old_t - qoutient * t)
            in loop old_r' r' old_s' s' old_t' t'
        else (old_s, old_t, old_r)