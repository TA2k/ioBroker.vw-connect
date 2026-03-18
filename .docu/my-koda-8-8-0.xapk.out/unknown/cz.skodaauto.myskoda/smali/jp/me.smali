.class public abstract Ljp/me;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lol0/a;Lqr0/s;Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "units"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "fallback"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    return-object p2

    .line 14
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    const/4 v0, 0x2

    .line 19
    const/4 v1, 0x1

    .line 20
    if-eqz p2, :cond_3

    .line 21
    .line 22
    if-eq p2, v1, :cond_2

    .line 23
    .line 24
    if-ne p2, v0, :cond_1

    .line 25
    .line 26
    sget-object p2, Lqr0/t;->d:Lqr0/t;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    new-instance p0, La8/r0;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    sget-object p2, Lqr0/t;->e:Lqr0/t;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    sget-object p2, Lqr0/t;->e:Lqr0/t;

    .line 39
    .line 40
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    if-eqz p1, :cond_5

    .line 45
    .line 46
    if-eq p1, v1, :cond_5

    .line 47
    .line 48
    if-ne p1, v0, :cond_4

    .line 49
    .line 50
    new-instance p1, Lol0/a;

    .line 51
    .line 52
    iget-object v1, p0, Lol0/a;->a:Ljava/math/BigDecimal;

    .line 53
    .line 54
    new-instance v2, Ljava/math/BigDecimal;

    .line 55
    .line 56
    const-wide v3, 0x400e4885edeb2a86L    # 3.7854117

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    invoke-static {v3, v4}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-direct {v2, v3}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1, v2}, Ljava/math/BigDecimal;->multiply(Ljava/math/BigDecimal;)Ljava/math/BigDecimal;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    const-string v2, "multiply(...)"

    .line 73
    .line 74
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lol0/a;->b:Ljava/lang/String;

    .line 78
    .line 79
    invoke-direct {p1, v1, p0}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    move-object p0, p1

    .line 83
    goto :goto_1

    .line 84
    :cond_4
    new-instance p0, La8/r0;

    .line 85
    .line 86
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_5
    :goto_1
    invoke-static {p0, v0}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-static {p2}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    const-string p2, " / "

    .line 99
    .line 100
    invoke-static {p0, p2, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method

.method public static final b(Lfp0/b;)Lcp0/a;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcp0/a;

    .line 7
    .line 8
    iget-object v1, p0, Lfp0/b;->a:Lfp0/c;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v2, p0, Lfp0/b;->b:Ljava/lang/Integer;

    .line 15
    .line 16
    iget-object v3, p0, Lfp0/b;->c:Ljava/lang/Integer;

    .line 17
    .line 18
    iget-object p0, p0, Lfp0/b;->d:Lqr0/d;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-wide v4, p0, Lqr0/d;->a:D

    .line 23
    .line 24
    double-to-int p0, v4

    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    :goto_0
    invoke-direct {v0, v1, v2, v3, p0}, Lcp0/a;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final c(Lcp0/a;)Lfp0/b;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcp0/a;->a:Ljava/lang/String;

    .line 7
    .line 8
    sget-object v1, Lfp0/c;->h:Lfp0/c;

    .line 9
    .line 10
    invoke-static {}, Lfp0/c;->values()[Lfp0/c;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    array-length v3, v2

    .line 15
    const/4 v4, 0x0

    .line 16
    :goto_0
    const/4 v5, 0x0

    .line 17
    if-ge v4, v3, :cond_1

    .line 18
    .line 19
    aget-object v6, v2, v4

    .line 20
    .line 21
    invoke-virtual {v6}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    if-eqz v7, :cond_0

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    move-object v6, v5

    .line 36
    :goto_1
    if-nez v6, :cond_2

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    move-object v1, v6

    .line 40
    :goto_2
    iget-object v0, p0, Lcp0/a;->b:Ljava/lang/Integer;

    .line 41
    .line 42
    iget-object v2, p0, Lcp0/a;->c:Ljava/lang/Integer;

    .line 43
    .line 44
    iget-object p0, p0, Lcp0/a;->d:Ljava/lang/Integer;

    .line 45
    .line 46
    if-eqz p0, :cond_3

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    int-to-double v3, p0

    .line 53
    new-instance v5, Lqr0/d;

    .line 54
    .line 55
    invoke-direct {v5, v3, v4}, Lqr0/d;-><init>(D)V

    .line 56
    .line 57
    .line 58
    :cond_3
    new-instance p0, Lfp0/b;

    .line 59
    .line 60
    invoke-direct {p0, v1, v0, v2, v5}, Lfp0/b;-><init>(Lfp0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lqr0/d;)V

    .line 61
    .line 62
    .line 63
    return-object p0
.end method
