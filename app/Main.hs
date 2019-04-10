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
        publicKey = toPoint privateKey
        αG = toPoint α
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs  = toPoint response
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

fiatShamir :: IO ()
fiatShamir = do
    α <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey = toPoint privateKey
        αG = toPoint α
        challenge = generateChallenge αG
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs  = toPoint response
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
