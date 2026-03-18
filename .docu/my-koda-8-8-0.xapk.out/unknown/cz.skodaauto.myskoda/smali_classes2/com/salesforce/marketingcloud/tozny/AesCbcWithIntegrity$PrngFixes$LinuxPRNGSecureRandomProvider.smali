.class Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandomProvider;
.super Ljava/security/Provider;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0

    .line 2
    .line 3
    const-string v2, "A Linux-specific random number provider that uses /dev/urandom"

    .line 4
    .line 5
    const-string v3, "LinuxPRNG"

    .line 6
    .line 7
    invoke-direct {p0, v3, v0, v1, v2}, Ljava/security/Provider;-><init>(Ljava/lang/String;DLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-class v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "SecureRandom.SHA1PRNG"

    .line 17
    .line 18
    invoke-virtual {p0, v1, v0}, Ljava/util/Dictionary;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    const-string v0, "SecureRandom.SHA1PRNG ImplementedIn"

    .line 22
    .line 23
    const-string v1, "Software"

    .line 24
    .line 25
    invoke-virtual {p0, v0, v1}, Ljava/util/Dictionary;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    return-void
.end method
