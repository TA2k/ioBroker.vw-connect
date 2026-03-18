.class public final Lhc0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgc0/a;


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lhc0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhc0/b;

    .line 7
    .line 8
    iget v1, v0, Lhc0/b;->f:I

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
    iput v1, v0, Lhc0/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhc0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhc0/b;-><init>(Lhc0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lhc0/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lhc0/b;->f:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    const-class v1, Las/d;

    .line 56
    .line 57
    invoke-virtual {p0, v1}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    check-cast p0, Las/d;

    .line 62
    .line 63
    const-string v1, "getInstance(...)"

    .line 64
    .line 65
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Las/d;->j:Laq/t;

    .line 69
    .line 70
    iget-object v3, p0, Las/d;->h:Ljava/util/concurrent/Executor;

    .line 71
    .line 72
    new-instance v4, Las/c;

    .line 73
    .line 74
    invoke-direct {v4, p0}, Las/c;-><init>(Las/d;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1, v3, v4}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    iput v2, v0, Lhc0/b;->f:I

    .line 82
    .line 83
    invoke-static {p0, v0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-ne p0, p1, :cond_3

    .line 88
    .line 89
    return-object p1

    .line 90
    :cond_3
    :goto_1
    check-cast p0, Las/b;

    .line 91
    .line 92
    iget-object p0, p0, Las/b;->a:Ljava/lang/String;

    .line 93
    .line 94
    const-string p1, "getToken(...)"

    .line 95
    .line 96
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    return-object p0
.end method
