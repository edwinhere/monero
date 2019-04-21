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
import Data.Modular
import Control.Monad (replicateM)

type PrimeOrder = Integer/7237005577332262213973186563042994240857116359379907606001950938285454250989
type PrivateKey = Scalar
type PublicKey  = Point
type Message = ByteString


s2bs :: Scalar -> ByteString
s2bs = scalarEncode

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

main :: IO ()
main = do
    schnorr
    fiatShamir
    schnorrWithMessage ""
    edDSA ""

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

edDSASign :: PrivateKey -> Message -> (Point, Scalar)
edDSASign k m = (αG, response)
    where
        publicKey :: Point
        publicKey = toPoint k
        hk :: ByteString
        hk = convert . hashWith SHA256 . s2bs $ k
        α :: Scalar
        α = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (B.concat [hk, m])
        αG :: Point
        αG = toPoint α
        challenge :: Scalar
        challenge = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (B.concat [pointEncode αG, pointEncode publicKey, m])
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` k)

edDSAVerify :: PublicKey -> (Point, Scalar) -> Message -> Bool
edDSAVerify publicKey (αG, response) m = result
    where
        challenge' :: Scalar
        challenge' = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (B.concat [pointEncode αG, pointEncode publicKey, m])
        lhs :: Point
        lhs = pointMulByCofactor $ toPoint response
        rhs :: Point
        rhs = pointMulByCofactor $ αG `pointAdd` (challenge' `pointMul` publicKey)
        result :: Bool
        result = lhs == rhs

edDSA :: Message -> IO ()
edDSA m = do
    privateKey <- scalarGenerate
    let publicKey = toPoint privateKey
    let (αG, response) = edDSASign privateKey m
    let result = edDSAVerify publicKey (αG, response) m
    print result

lsag :: IO ()
lsag = do
    keyPairs <- ((\x -> (x, toPoint x)) <$>) <$>
        replicateM 3 scalarGenerate
    let publicKeys = snd <$> keyPairs
        privateKey = (fst <$> keyPairs) !! 2
        keyImage = toKeyImage publicKeys privateKey
    α <- scalarGenerate
    fakeResposes <- replicateM 3 scalarGenerate
    return ()

hashToScalar :: ByteString -> Scalar
hashToScalar bs = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ bs

hashToPoint :: ByteString -> Point
hashToPoint = toPoint . hashToScalar

toKeyImage :: [PublicKey] -> PrivateKey -> Point
toKeyImage publicKeys privateKey = privateKey `pointMul` hashToPoint (
        B.concat (pointEncode <$> publicKeys)
    )
