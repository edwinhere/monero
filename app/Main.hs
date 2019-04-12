{-# LANGUAGE OverloadedStrings #-}
module Main where

import Lib
import Data.ByteString (ByteString)
import Data.ByteArray (convert, ByteArray)
import Crypto.ECC.Edwards25519
import Crypto.Hash
import Crypto.Error

main :: IO ()
main = do
    schnorr
    fiatShamir

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
        challenge = generateChallenge αG
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs :: Point
        lhs  = toPoint response
        rhs :: Point
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

generateChallenge :: Point -> Scalar
generateChallenge αG = challenge
    where
        challenge = throwCryptoError challenge'
        challenge' :: CryptoFailable Scalar
        challenge' = scalarDecodeLong hashedPoint'
        encodedPoint :: ByteString
        encodedPoint = pointEncode αG
        hashedPoint :: Digest SHA256
        hashedPoint = hashWith SHA256 encodedPoint
        hashedPoint' :: ByteString
        hashedPoint' = convert hashedPoint
