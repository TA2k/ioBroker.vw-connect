.class public Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final SECRET_LENGTH:I = 0x10


# instance fields
.field public final activationId:Ljava/lang/String;

.field public final authenticationFactors:I

.field public final identifier:Ljava/lang/String;

.field public final name:Ljava/lang/String;

.field public final secret:[B


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_5

    .line 9
    .line 10
    check-cast p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;

    .line 11
    .line 12
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->secret:[B

    .line 13
    .line 14
    array-length v1, v1

    .line 15
    const/16 v3, 0x10

    .line 16
    .line 17
    if-ne v1, v3, :cond_5

    .line 18
    .line 19
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->identifier:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_5

    .line 26
    .line 27
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->name:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-nez v1, :cond_5

    .line 34
    .line 35
    iget-object v1, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->secret:[B

    .line 36
    .line 37
    array-length v1, v1

    .line 38
    if-ne v1, v3, :cond_5

    .line 39
    .line 40
    iget-object v1, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->identifier:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    iget-object v1, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->name:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->name:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v3, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->name:Ljava/lang/String;

    .line 59
    .line 60
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_1

    .line 65
    .line 66
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->identifier:Ljava/lang/String;

    .line 67
    .line 68
    iget-object v3, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->identifier:Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-eqz v1, :cond_1

    .line 75
    .line 76
    iget-object v1, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->secret:[B

    .line 77
    .line 78
    iget-object v3, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->secret:[B

    .line 79
    .line 80
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([B[B)Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_1

    .line 85
    .line 86
    move v1, v0

    .line 87
    goto :goto_0

    .line 88
    :cond_1
    move v1, v2

    .line 89
    :goto_0
    if-eqz v1, :cond_4

    .line 90
    .line 91
    iget-object p0, p0, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->activationId:Ljava/lang/String;

    .line 92
    .line 93
    if-eqz p0, :cond_2

    .line 94
    .line 95
    move v3, v0

    .line 96
    goto :goto_1

    .line 97
    :cond_2
    move v3, v2

    .line 98
    :goto_1
    iget-object p1, p1, Lio/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData;->activationId:Ljava/lang/String;

    .line 99
    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    move v0, v2

    .line 104
    :goto_2
    if-ne v3, v0, :cond_5

    .line 105
    .line 106
    if-eqz v3, :cond_4

    .line 107
    .line 108
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    return p0

    .line 113
    :cond_4
    return v1

    .line 114
    :cond_5
    return v2
.end method
