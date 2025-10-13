{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Lib
    ( enc
    , dec
    , genKeys
    , nOfBits
    , nOfBytes
    , myLog
    , PubKey(..)
    , PrivKey(..)
    , expmod
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Data.Bits

import System.IO
import Crypto.Number.Prime (generatePrime)
import Crypto.Number.Basic (gcde, numBytes)
import Crypto.Util (bs2i, i2bs)
import GHC.Num (integerFromInt, integerToInt)
import Control.Monad (when)
import Data.Maybe (isJust, fromJust)
import Control.Exception (evaluate)

import Test.QuickCheck

import qualified OAEP
import System.Entropy (getEntropy)
import Control.Concurrent.Async
import Control.Concurrent.STM 
import Control.Concurrent.STM.TBMQueue
import Control.Concurrent (getNumCapabilities)

newtype PubKey = PubKey (Integer, Integer)
data PrivKey = PrivKey
    { privN :: Integer
    , privP :: Integer
    , privQ :: Integer
    , privDp :: Integer
    , privDq :: Integer
    , privQinv :: Integer
    , privD :: Integer
    }

-- returns floor of logarithm with base 2
myLog :: Integral a => a -> Int
myLog x = go 0 x
    where
    go !k !y = if y <= 1 then k else go (k + 1) (y `div` 2)

prop_bs = 
      forAll (resize 1000 $ listOf arbitrary) $ \(xs :: [Word8]) -> 
        let bs = B.pack xs
            in collect (length xs) $ i2bs (8 * B.length bs) (bs2i bs) == bs


nOfBits :: Integer -> Int
nOfBits x = 1 + myLog x  

nOfBytes :: Integer -> Int
nOfBytes n = go 0 n
    where
        go !k x = 
            if x > 0 
            then go (k + 1) (x `shiftR` 8) 
            else k


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
    k = nOfBytes n
    kInBits = k * 8
    maxMsgLen = OAEP.maxMessageSizeBytes k

    encBS :: ByteString -> IO ByteString
    encBS bs = do
        seed <- getEntropy OAEP.hLen
        let encoded = OAEP.encode k seed bs
        let m = bs2i encoded
        return $ i2bs kInBits $ expmod n m e 

    loop = do
        m <- B.hGet hIn maxMsgLen
        c <- encBS m
        B.hPut hOut c
        eof <- hIsEOF hIn
        when (not eof) loop

decryptClassic :: PrivKey -> Integer -> Integer
decryptClassic key c = expmod key.privN c key.privD

-- optimization based on Chinese Remainder Theorem 
decryptCRT :: PrivKey -> Integer -> Integer 
decryptCRT key c = 
    let 
        p = key.privP
        q = key.privQ
        dP = key.privDp
        dQ = key.privDq
        qInv = key.privQinv

        m1 = expmod p c dP
        m2 = expmod q c dQ
        h = (qInv * (m1 - m2)) `mod` p
        m = m2 + h * q
    in m

dec :: Bool -> PrivKey -> Handle -> Handle -> IO ()
dec noCRT key hIn hOut = do
    caps <- getNumCapabilities
    putStrLn $ "getNumCapabilities = " ++ show caps
    let queueCapacity = max 1 (caps - 2)
    queue <- newTBMQueueIO queueCapacity
    putStrLn $ "queue capacity = " ++ show queueCapacity
    withAsync (readQueue queue) $ \reading -> 
        withAsync (fillQueue queue reading) $ \filling -> do
            link2 reading filling
            waitBoth reading filling
            return ()
    where
    n = key.privN
    k = nOfBytes n
    kInBits = k * 8
    
    aux :: Integer -> Integer
    aux = if noCRT 
        then decryptClassic key 
        else decryptCRT key

    decryptAndDecode :: ByteString -> ByteString
    decryptAndDecode bs = OAEP.decode k $ i2bs kInBits $ aux $ bs2i bs 

    job :: ByteString -> IO ByteString
    job bs = evaluate $ decryptAndDecode bs

    fillQueue :: TBMQueue (Async ByteString) -> Async a -> IO ()
    fillQueue queue reading = do 
        eof <- hIsEOF hIn
        if eof
        then atomically $ closeTBMQueue queue
        else do
            bs <- B.hGet hIn k
            when (B.length bs /= k) $ evaluate $ error "decoding error: invalid block size"
            a <- async (job bs)
            link a
            link2 a reading
            atomically $ writeTBMQueue queue a
            fillQueue queue reading

    readQueue :: TBMQueue (Async ByteString) -> IO ()
    readQueue queue = do
        r <- atomically $ readTBMQueue queue
        case r of
            Nothing -> return ()
            (Just a) -> do
                bs <- wait a
                B.hPut hOut bs
                readQueue queue

genKeys :: Int -> IO (PubKey, PrivKey)
genKeys sizeBits = do
    let minKeySizeBits = OAEP.minModulusSizeBytes * 8
    when (sizeBits < minKeySizeBits) $
        evaluate $ error $ "key bit size must be >= " ++ show minKeySizeBits ++ " bits"
    putStrLn $ "generating keys of size " ++ show sizeBits ++ " bits"
    let primeSizeBits = sizeBits `div` 2
    when (primeSizeBits < 5) $ error "Aborting. Invalid key size which should be >= 10bits."
    hFlush stdout
    p <- generatePrime primeSizeBits
    q <- generatePrime primeSizeBits
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
    let privKey = PrivKey 
            { privN = n
            , privP = p
            , privQ = q
            , privDp = d `mod` (p - 1) 
            , privDq = d `mod` (q - 1)
            , privQinv = mminv q p
            , privD = d
            }
    return (PubKey (n, e), privKey) 

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