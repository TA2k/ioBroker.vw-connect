.class public final Lp60/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# virtual methods
.method public final a(Ljava/net/URI;)Lq60/a;
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_2

    .line 3
    .line 4
    sget-object v1, Lq60/c;->f:Lsx0/b;

    .line 5
    .line 6
    invoke-virtual {v1}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    move-object v3, v2

    .line 21
    check-cast v3, Lq60/c;

    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/net/URI;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    const-string v5, "toString(...)"

    .line 28
    .line 29
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object v3, v3, Lq60/c;->d:Ljava/lang/String;

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-static {v4, v3, v5}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    move-object v2, v0

    .line 43
    :goto_0
    check-cast v2, Lq60/c;

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    move-object v2, v0

    .line 47
    :goto_1
    const/4 v1, -0x1

    .line 48
    if-nez v2, :cond_3

    .line 49
    .line 50
    move v2, v1

    .line 51
    goto :goto_2

    .line 52
    :cond_3
    sget-object v3, Lp60/e0;->a:[I

    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    aget v2, v3, v2

    .line 59
    .line 60
    :goto_2
    if-eq v2, v1, :cond_6

    .line 61
    .line 62
    const/4 p0, 0x1

    .line 63
    if-eq v2, p0, :cond_5

    .line 64
    .line 65
    const/4 p0, 0x2

    .line 66
    if-ne v2, p0, :cond_4

    .line 67
    .line 68
    sget-object p0, Lq60/a;->e:Lq60/a;

    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_4
    new-instance p0, La8/r0;

    .line 72
    .line 73
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_5
    sget-object p0, Lq60/a;->d:Lq60/a;

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_6
    sget-object v1, Lq60/a;->f:Lq60/a;

    .line 81
    .line 82
    new-instance v2, Lkc0/j0;

    .line 83
    .line 84
    const/4 v3, 0x1

    .line 85
    invoke-direct {v2, p1, v3}, Lkc0/j0;-><init>(Ljava/net/URI;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {v0, p0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 89
    .line 90
    .line 91
    return-object v1
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/net/URI;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lp60/f0;->a(Ljava/net/URI;)Lq60/a;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
