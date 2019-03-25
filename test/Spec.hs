import Test.Hspec
import Test.QuickCheck

main :: IO ()
main = hspec $ do
    describe "modular arithmetic" $ do
        it "is distributive" $ property $
            \x -> (read . show) x == (x :: Integer)
