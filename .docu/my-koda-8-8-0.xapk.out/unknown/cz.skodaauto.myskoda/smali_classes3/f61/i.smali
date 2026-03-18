.class public final Lf61/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Law0/h;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lf61/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lf61/h;

    .line 7
    .line 8
    iget v1, v0, Lf61/h;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lf61/h;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf61/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lf61/h;-><init>(Lf61/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lf61/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf61/h;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :catch_0
    move-exception p1

    .line 42
    goto :goto_2

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :try_start_1
    invoke-static {p1}, Lfw0/k;->b(Law0/h;)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_4

    .line 59
    .line 60
    iput v3, v0, Lf61/h;->f:I

    .line 61
    .line 62
    sget-object p2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 63
    .line 64
    invoke-static {p1, p2, v0}, Lo5/c;->a(Law0/h;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    if-ne p2, v1, :cond_3

    .line 69
    .line 70
    return-object v1

    .line 71
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/String;

    .line 72
    .line 73
    sget-object p1, Lf61/j;->g:Lvz0/t;

    .line 74
    .line 75
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v1, Lf61/d;->Companion:Lf61/c;

    .line 79
    .line 80
    invoke-virtual {v1}, Lf61/c;->serializer()Lqz0/a;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    check-cast v1, Lqz0/a;

    .line 85
    .line 86
    invoke-virtual {p1, p2, v1}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    check-cast p1, Lf61/d;

    .line 91
    .line 92
    iget-object p0, p1, Lf61/d;->a:Lf61/j;

    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_4
    sget-object p1, Lx51/c;->o1:Lx51/b;

    .line 96
    .line 97
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    new-instance v1, Lf2/h0;

    .line 102
    .line 103
    const/4 v2, 0x4

    .line 104
    invoke-direct {v1, v2}, Lf2/h0;-><init>(I)V

    .line 105
    .line 106
    .line 107
    const/4 v2, 0x6

    .line 108
    invoke-static {p1, p2, v4, v1, v2}, Lx51/c;->f(Lx51/c;Ljava/lang/String;Ljava/lang/Exception;Lay0/a;I)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 109
    .line 110
    .line 111
    return-object v4

    .line 112
    :goto_2
    sget-object p2, Lx51/c;->o1:Lx51/b;

    .line 113
    .line 114
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    new-instance v1, Lf2/h0;

    .line 119
    .line 120
    const/4 v2, 0x5

    .line 121
    invoke-direct {v1, v2}, Lf2/h0;-><init>(I)V

    .line 122
    .line 123
    .line 124
    const/4 v2, 0x4

    .line 125
    invoke-static {p2, p0, p1, v1, v2}, Lx51/c;->f(Lx51/c;Ljava/lang/String;Ljava/lang/Exception;Lay0/a;I)V

    .line 126
    .line 127
    .line 128
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V

    .line 133
    .line 134
    .line 135
    return-object v4
.end method

.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Lf61/a;->a:Lf61/a;

    .line 2
    .line 3
    return-object p0
.end method
