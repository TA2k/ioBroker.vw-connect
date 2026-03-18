.class public final Lgz0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a()Lgz0/b0;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lgz0/a0;->c(Ljava/time/ZoneId;)Lgz0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    return-object v0
.end method

.method public static b(Ljava/lang/String;)Lgz0/b0;
    .locals 1

    .line 1
    const-string v0, "zoneId"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v0, "z"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const-string p0, "Z"

    .line 15
    .line 16
    :cond_0
    invoke-static {p0}, Ljava/time/ZoneId;->of(Ljava/lang/String;)Ljava/time/ZoneId;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const-string v0, "of(...)"

    .line 21
    .line 22
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Lgz0/a0;->c(Ljava/time/ZoneId;)Lgz0/b0;

    .line 26
    .line 27
    .line 28
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    return-object p0

    .line 30
    :catch_0
    move-exception p0

    .line 31
    instance-of v0, p0, Ljava/time/DateTimeException;

    .line 32
    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    new-instance v0, Lgz0/a;

    .line 36
    .line 37
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :cond_1
    throw p0
.end method

.method public static c(Ljava/time/ZoneId;)Lgz0/b0;
    .locals 4

    .line 1
    instance-of v0, p0, Ljava/time/ZoneOffset;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lgz0/n;

    .line 6
    .line 7
    new-instance v1, Lgz0/d0;

    .line 8
    .line 9
    check-cast p0, Ljava/time/ZoneOffset;

    .line 10
    .line 11
    invoke-direct {v1, p0}, Lgz0/d0;-><init>(Ljava/time/ZoneOffset;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v0, p0}, Lgz0/b0;-><init>(Ljava/time/ZoneId;)V

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Ljava/time/ZoneId;->getRules()Ljava/time/zone/ZoneRules;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0}, Ljava/time/zone/ZoneRules;->isFixedOffset()Z

    .line 23
    .line 24
    .line 25
    move-result v0
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    goto :goto_0

    .line 27
    :catch_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    if-eqz v0, :cond_1

    .line 29
    .line 30
    new-instance v0, Lgz0/n;

    .line 31
    .line 32
    new-instance v1, Lgz0/d0;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/time/ZoneId;->normalized()Ljava/time/ZoneId;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const-string v3, "null cannot be cast to non-null type java.time.ZoneOffset"

    .line 39
    .line 40
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    check-cast v2, Ljava/time/ZoneOffset;

    .line 44
    .line 45
    invoke-direct {v1, v2}, Lgz0/d0;-><init>(Ljava/time/ZoneOffset;)V

    .line 46
    .line 47
    .line 48
    invoke-direct {v0, p0}, Lgz0/b0;-><init>(Ljava/time/ZoneId;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance v0, Lgz0/b0;

    .line 53
    .line 54
    invoke-direct {v0, p0}, Lgz0/b0;-><init>(Ljava/time/ZoneId;)V

    .line 55
    .line 56
    .line 57
    :goto_1
    return-object v0
.end method


# virtual methods
.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Lmz0/l;->a:Lmz0/l;

    .line 2
    .line 3
    return-object p0
.end method
