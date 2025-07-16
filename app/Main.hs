{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main (main) where

import Lib

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits
import System.IO
import Control.Monad
import Crypto.Number.Prime (generatePrime)
import Crypto.Number.Basic (gcde)

import System.Environment (getArgs)
import Crypto.Util (bs2i, i2bs)
import GHC.Num (integerFromInt, integerToInt)

newtype PubKey = PubKey (Integer, Integer)
newtype PrivKey = PrivKey (Integer, Integer)

-- TODO: add description to README file: RSA encryption without padding (aka “textbook RSA”),

-- returns floor of logarithm with base 2
myLog :: Integer -> Int
myLog x =
    if x <= 1
    then 0
    else 1 + myLog (x `div` 2)

nOfBits :: Integer -> Int
nOfBits x = 1 + myLog x  

-- stack run -- --help

pubKeyFileName :: String
pubKeyFileName = "PUB.txt"
privKeyFileName :: String
privKeyFileName = "PRIV.txt"

-- TODO: add key size when generating keys
-- TODO: use package optparse-applicative for parsing command line options

main :: IO ()
main = do
    args <- getArgs
    -- let helpMsg = "Usage:\n  myrsa-exe [--help] [-k | [-e | -d] INFILE OUTFILE]\n"
    let exeName = "myrsa-exe"
    let helpMsg = "Usage: " ++ exeName ++ " [OPTIONS]\n"
            ++ "\nOptions:"
            ++ "\n  -h, --help               print help"
            ++ "\n  -e <INFILE> <OUTFILE>    encrypt file"
            ++ "\n  -d <INFILE> <OUTFILE>    decrypt file"
            ++ "\n  -c <INFILE> <OUTFILE>    copy file"
            ++ "\n  -k                       generate keys"
            ++ "\nExpecting private key in file " ++ privKeyFileName
            ++ "\nExpecting public key in file " ++ pubKeyFileName
            ++ "\n"
    case args of
        ("--help":_) -> putStrLn helpMsg
        ("-h":_) -> putStrLn helpMsg
        ("-c":inFile:outFile:[]) -> do
            copyFile inFile outFile 
        ("-e":inFile:outFile:[]) -> do
            key <- readPubKey
            putStrLn $ "encrypting " ++ inFile ++ " to " ++ outFile
            hFlush stdout
            hIn <- openBinaryFile inFile ReadMode
            hOut <- openBinaryFile outFile WriteMode
            enc key hIn hOut
            hClose hOut
            hClose hIn
        ("-d":inFile:outFile:[]) -> do
            key <- readPrivKey 
            putStrLn $ "decrypting " ++ inFile ++ " to " ++ outFile
            hFlush stdout
            hIn <- openBinaryFile inFile ReadMode
            hOut <- openBinaryFile outFile WriteMode
            dec key hIn hOut
            hClose hOut
            hClose hIn
        ("-k":[]) -> do
            (PubKey (n, e), PrivKey (_, d)) <- genKeys
            writeIntegers pubKeyFileName n e
            writeIntegers privKeyFileName n d
            putStrLn $ "public encryption key saved in file " ++ pubKeyFileName
            putStrLn $ "private decryption key saved in file " ++ privKeyFileName
        _ -> putStrLn helpMsg

readPrivKey :: IO PrivKey
readPrivKey = do
    let file = privKeyFileName
    putStrLn $ "reading private key from file " ++ file 
    hFlush stdout
    (n, d) <- readIntegers file
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits" 
    hFlush stdout
    return $ PrivKey (n, d)

readPubKey :: IO PubKey
readPubKey = do
    let file = pubKeyFileName
    putStrLn $ "reading public key from file " ++ file 
    hFlush stdout
    (n, e) <- readIntegers file
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits" 
    hFlush stdout
    return $ PubKey (n, e)

readIntegers :: FilePath -> IO (Integer, Integer)
readIntegers file = do
    handle <- openFile file ReadMode
    str1 <- hGetLine handle
    let a = read str1 :: Integer
    str2 <- hGetLine handle
    let b = read str2 :: Integer
    hClose handle
    return (a, b)

writeIntegers :: FilePath -> Integer -> Integer -> IO ()
writeIntegers file a b = do
    handle <- openFile file WriteMode
    hPutStrLn handle $ show a
    hPutStrLn handle $ show b
    hClose handle
    
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

-- copying binary file
copyFile :: FilePath -> FilePath -> IO ()
copyFile inFile outFile = do
    putStrLn $ "copying file " ++ inFile ++ " to " ++ outFile
    hFlush stdout
    hIn <- openBinaryFile inFile ReadMode
    hOut <- openBinaryFile outFile WriteMode
    copyLoop hIn hOut
    hClose hOut
    hClose hIn

copyLoop :: Handle -> Handle -> IO ()
copyLoop hIn hOut = do
    let chunkSize = 10
    bs <- B.hGet hIn chunkSize
    B.hPut hOut bs
    eof <- hIsEOF hIn
    if not eof
    then copyLoop hIn hOut
    else putStrLn "finished copying"

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

-- Key generation

genKeys :: IO (PubKey, PrivKey)
genKeys = do
    putStrLn $ "generating keys"
    hFlush stdout
    p <- generatePrime 1024
    q <- generatePrime 1024
    let n = p * q
    putStrLn $ "key (modulus) size: " ++ show (nOfBits n) ++ " bits"
    hFlush stdout
    -- Euler's totient function
    let tot = (p - 1) * (q - 1)
    let e = 2^16 + 1
    if not (1 < e && e < tot)
    then error "error generating keys: wrong e param"
    else do
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