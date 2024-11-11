import binascii

class KettleTwoWayPasswordEncoder:
    """
    A class to handle two-way password encryption and decryption using a seed value.

    Ported from the original Java implementation.
    https://github.com/pentaho/pentaho-kettle/blob/master/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L132

    Attributes:
        seed (str): The seed value used for encryption and decryption.

    Methods:
        __init__(env_seed="0933910847463829827159347601486730416058"):
            Initializes the encoder with a given seed value.
        
        get_seed():
            Returns the seed value used for encryption and decryption.
        
        decrypt_password_internal(encrypted):
            Decrypts an encrypted password string using the seed value.
    """
    def __init__(self, env_seed="0933910847463829827159347601486730416058"):
        self.seed = env_seed

    def get_seed(self):
        return self.seed

    def decrypt_password_internal(self, encrypted):
        if encrypted is None or len(encrypted) == 0:
            return ""

        bi_confuse = int(self.get_seed())

        try:
            bi_r1 = int(encrypted, 16)
            bi_r0 = bi_r1 ^ bi_confuse

            return binascii.unhexlify(format(bi_r0, 'x')).decode('utf-8')
        except Exception as e:
            return ""