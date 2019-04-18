{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators     #-}
{-# LANGUAGE DataKinds         #-}
module Main where

import Lib
import Data.ByteString as B
import Data.ByteArray (convert, ByteArray)
import Crypto.ECC.Edwards25519
import Crypto.Hash
import Crypto.Error
import Data.Serialize.Put
import Data.Serialize.Get (
        getWord64le,
        runGet
    )
import Data.Serialize (encode)
import Data.Word
import Data.Modular
import Data.Either

type PrimeOrder = Integer/7237005577332262213973186563042994240857116359379907606001950938285454250989

s2bs :: Scalar -> ByteString
s2bs = scalarEncode

main :: IO ()
main = do
    schnorr
    fiatShamir
    schnorrWithMessage ""

schnorr :: IO ()
schnorr = do
    α <- scalarGenerate
    challenge <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs :: Point
        lhs  = toPoint response
        rhs :: Point
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

fiatShamir :: IO ()
fiatShamir = do
    α <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        challenge :: Scalar
        challenge = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (pointEncode αG :: ByteString)
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs :: Point
        lhs  = toPoint response
        rhs :: Point
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

type Message = ByteString

schnorrWithMessage :: Message -> IO ()
schnorrWithMessage m = do
    α <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        αG' :: ByteString
        αG' = pointEncode αG
        challenge :: Scalar
        challenge = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (B.concat [m, αG'])
        response :: Scalar
        response = α `scalarSub` (challenge `scalarMul` privateKey)
        lhs :: Scalar
        lhs = challenge
        rhs :: Scalar
        rhs = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (
                B.concat [
                    m,
                    pointEncode $ toPoint response `pointAdd` (challenge `pointMul` publicKey)
                 ]
          )
    print . B.unpack . s2bs $ lhs
    print . B.unpack . s2bs $ rhs

scalarSub :: Scalar -> Scalar -> Scalar
scalarSub a b = throwCryptoError . scalarDecodeLong . fromPrimeOrder $ a' - b'
    where
        a' :: PrimeOrder
        a' = toPrimeOrder $ scalarEncode a
        b' :: PrimeOrder
        b' = toPrimeOrder $ scalarEncode b
        toPrimeOrder :: ByteString -> PrimeOrder
        toPrimeOrder = toMod . B.foldr (\ y x -> (256 * x) + (fromIntegral y)) 0
        fromPrimeOrder :: PrimeOrder -> ByteString
        fromPrimeOrder = B.unfoldr (\i' -> if i' == 0 then Nothing else Just (fromIntegral i', i' `div` 256)) . unMod
