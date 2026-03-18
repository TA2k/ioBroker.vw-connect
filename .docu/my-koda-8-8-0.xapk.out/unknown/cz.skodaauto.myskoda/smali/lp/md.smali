.class public abstract Llp/md;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcm0/b;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_3

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_3

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-eq p0, v0, :cond_2

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    if-eq p0, v0, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    if-ne p0, v0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    const-string p0, "mocck.test-api.connect.skoda-auto.cz"

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    const-string p0, "document-consent-sandbox.vwgroup.io"

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_3
    const-string p0, "document-consent.vwgroup.io"

    .line 38
    .line 39
    return-object p0
.end method

.method public static final b(Lao0/a;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 7
    .line 8
    iget-wide v2, p0, Lao0/a;->a:J

    .line 9
    .line 10
    iget-boolean v4, p0, Lao0/a;->b:Z

    .line 11
    .line 12
    iget-object v0, p0, Lao0/a;->c:Ljava/time/LocalTime;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/time/LocalTime;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v5

    .line 18
    const-string v0, "toString(...)"

    .line 19
    .line 20
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lao0/a;->d:Ljava/time/LocalTime;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/time/LocalTime;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v6

    .line 29
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-direct/range {v1 .. v6}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;-><init>(JZLjava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-object v1
.end method

.method public static final c(Lcz/myskoda/api/bff/v1/ChargingTimeDto;)Lao0/a;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lao0/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->getId()J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->getEnabled()Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->getStartTime()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    const-string v0, "parse(...)"

    .line 25
    .line 26
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->getEndTime()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 34
    .line 35
    .line 36
    move-result-object v6

    .line 37
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-direct/range {v1 .. v6}, Lao0/a;-><init>(JZLjava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 41
    .line 42
    .line 43
    return-object v1
.end method
