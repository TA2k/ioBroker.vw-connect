.class public abstract Ljb0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;)Lmb0/c;
    .locals 6

    .line 1
    new-instance v0, Lmb0/c;

    .line 2
    .line 3
    new-instance v1, Lqr0/q;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;->getTemperatureValue()D

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;->getTemperatureUnit()Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto$TemperatureUnit;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    sget-object v5, Ljb0/s;->a:[I

    .line 14
    .line 15
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    aget v4, v5, v4

    .line 20
    .line 21
    const/4 v5, 0x1

    .line 22
    if-eq v4, v5, :cond_1

    .line 23
    .line 24
    const/4 v5, 0x2

    .line 25
    if-ne v4, v5, :cond_0

    .line 26
    .line 27
    sget-object v4, Lqr0/r;->e:Lqr0/r;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_1
    sget-object v4, Lqr0/r;->d:Lqr0/r;

    .line 37
    .line 38
    :goto_0
    invoke-direct {v1, v2, v3, v4}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {v0, v1, p0}, Lmb0/c;-><init>(Lqr0/q;Ljava/time/OffsetDateTime;)V

    .line 46
    .line 47
    .line 48
    return-object v0
.end method
