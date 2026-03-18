.class public abstract Lkp/h6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/text/NumberFormat;->getInstance()Ljava/text/NumberFormat;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {v0, p0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object v0, Lqr0/o;->f:Lqr0/o;

    .line 14
    .line 15
    invoke-static {v0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, " "

    .line 20
    .line 21
    invoke-static {p0, v1, v0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public static b(Lne0/c;Lij0/a;I)Lql0/g;
    .locals 9

    .line 1
    and-int/lit8 v0, p2, 0x2

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v0, v2

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    :goto_0
    and-int/lit8 v3, p2, 0x4

    .line 10
    .line 11
    if-eqz v3, :cond_1

    .line 12
    .line 13
    const v3, 0x7f12038b

    .line 14
    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    const v3, 0x7f12038c

    .line 18
    .line 19
    .line 20
    :goto_1
    const-string v4, "<this>"

    .line 21
    .line 22
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v4, "stringResource"

    .line 26
    .line 27
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-array v4, v2, [Ljava/lang/Object;

    .line 31
    .line 32
    move-object v6, p1

    .line 33
    check-cast v6, Ljj0/f;

    .line 34
    .line 35
    const v7, 0x7f1202c6

    .line 36
    .line 37
    .line 38
    invoke-virtual {v6, v7, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    const v7, 0x7f1202c5

    .line 43
    .line 44
    .line 45
    new-array v8, v2, [Ljava/lang/Object;

    .line 46
    .line 47
    invoke-virtual {v6, v7, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    new-array v8, v2, [Ljava/lang/Object;

    .line 52
    .line 53
    invoke-virtual {v6, v3, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    const v0, 0x7f120373

    .line 60
    .line 61
    .line 62
    new-array v2, v2, [Ljava/lang/Object;

    .line 63
    .line 64
    invoke-virtual {v6, v0, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    :goto_2
    move-object v2, v4

    .line 69
    move-object v4, v3

    .line 70
    move-object v3, v7

    .line 71
    goto :goto_3

    .line 72
    :cond_2
    const/4 v0, 0x0

    .line 73
    goto :goto_2

    .line 74
    :goto_3
    sget-object v7, Lql0/e;->a:Lql0/e;

    .line 75
    .line 76
    const/16 v8, 0x20

    .line 77
    .line 78
    const/4 v6, 0x0

    .line 79
    move-object v1, p1

    .line 80
    move-object v5, v0

    .line 81
    move-object v0, p0

    .line 82
    invoke-static/range {v0 .. v8}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    return-object v0
.end method
