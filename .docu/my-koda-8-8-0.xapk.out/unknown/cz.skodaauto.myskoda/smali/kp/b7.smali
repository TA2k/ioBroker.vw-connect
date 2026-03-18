.class public abstract Lkp/b7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(IIIZ)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-lt p1, p2, :cond_1

    .line 3
    .line 4
    if-eqz p3, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    sub-int/2addr p2, p1

    .line 8
    return p2

    .line 9
    :cond_1
    if-nez p3, :cond_2

    .line 10
    .line 11
    if-gt p1, p0, :cond_4

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_2
    sub-int v1, p2, p1

    .line 15
    .line 16
    if-le v1, p0, :cond_4

    .line 17
    .line 18
    :goto_0
    if-eqz p3, :cond_3

    .line 19
    .line 20
    goto :goto_2

    .line 21
    :cond_3
    sub-int/2addr p0, p1

    .line 22
    return p0

    .line 23
    :cond_4
    if-eqz p3, :cond_5

    .line 24
    .line 25
    if-gt p1, p0, :cond_7

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_5
    sub-int v1, p2, p1

    .line 29
    .line 30
    if-le v1, p0, :cond_7

    .line 31
    .line 32
    :goto_1
    if-nez p3, :cond_6

    .line 33
    .line 34
    :goto_2
    return p0

    .line 35
    :cond_6
    sub-int/2addr p0, p1

    .line 36
    return p0

    .line 37
    :cond_7
    if-nez p3, :cond_8

    .line 38
    .line 39
    return v0

    .line 40
    :cond_8
    sub-int/2addr p2, p1

    .line 41
    return p2
.end method

.method public static final b(Lcz/myskoda/api/bff/v1/CardDto;)Lon0/a0;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lon0/a0;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->isDefault()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getExpiryMonth()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getExpiryYear()I

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getId()J

    .line 21
    .line 22
    .line 23
    move-result-wide v5

    .line 24
    invoke-static {v5, v6}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->isExpired()Z

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getLastDigits()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v8, ""

    .line 45
    .line 46
    if-nez v0, :cond_0

    .line 47
    .line 48
    move-object v0, v8

    .line 49
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getType()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v9

    .line 53
    if-nez v9, :cond_1

    .line 54
    .line 55
    move-object v9, v8

    .line 56
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CardDto;->getDescription()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-nez p0, :cond_2

    .line 61
    .line 62
    move-object v10, v8

    .line 63
    :goto_0
    move-object v8, v0

    .line 64
    goto :goto_1

    .line 65
    :cond_2
    move-object v10, p0

    .line 66
    goto :goto_0

    .line 67
    :goto_1
    invoke-direct/range {v1 .. v10}, Lon0/a0;-><init>(ZIILjava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    return-object v1
.end method

.method public static final c(Lcz/myskoda/api/bff/v1/ParkingPriceDetailsDto;Ljava/lang/String;)Lv40/c;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lv40/c;

    .line 7
    .line 8
    new-instance v1, Lol0/a;

    .line 9
    .line 10
    new-instance v2, Ljava/math/BigDecimal;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ParkingPriceDetailsDto;->getFeeIncludingVat()F

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    invoke-static {v3}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-direct {v2, v3}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {v1, v2, p1}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lol0/a;

    .line 27
    .line 28
    new-instance v3, Ljava/math/BigDecimal;

    .line 29
    .line 30
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ParkingPriceDetailsDto;->getFeeExcludingVat()F

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    invoke-static {v4}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    invoke-direct {v3, v4}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-direct {v2, v3, p1}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v3, Lol0/a;

    .line 45
    .line 46
    new-instance v4, Ljava/math/BigDecimal;

    .line 47
    .line 48
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ParkingPriceDetailsDto;->getVat()F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-static {p0}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {v4, p0}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-direct {v3, v4, p1}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-direct {v0, v1, v2, v3}, Lv40/c;-><init>(Lol0/a;Lol0/a;Lol0/a;)V

    .line 63
    .line 64
    .line 65
    return-object v0
.end method
