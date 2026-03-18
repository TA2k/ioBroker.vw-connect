.class public abstract Lkp/i8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a()Llw/h;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    int-to-float v0, v0

    .line 3
    new-instance v1, Llw/h;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Llw/h;-><init>(F)V

    .line 6
    .line 7
    .line 8
    return-object v1
.end method

.method public static final b(Landroidx/lifecycle/r;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lsm/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lsm/c;

    .line 7
    .line 8
    iget v1, v0, Lsm/c;->g:I

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
    iput v1, v0, Lsm/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lsm/c;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lsm/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lsm/c;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v0, Lsm/c;->e:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    iget-object v0, v0, Lsm/c;->d:Landroidx/lifecycle/r;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    sget-object v2, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 64
    .line 65
    invoke-virtual {p1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-ltz p1, :cond_3

    .line 70
    .line 71
    return-object v3

    .line 72
    :cond_3
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 73
    .line 74
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 75
    .line 76
    .line 77
    :try_start_1
    iput-object p0, v0, Lsm/c;->d:Landroidx/lifecycle/r;

    .line 78
    .line 79
    iput-object p1, v0, Lsm/c;->e:Lkotlin/jvm/internal/f0;

    .line 80
    .line 81
    iput v4, v0, Lsm/c;->g:I

    .line 82
    .line 83
    new-instance v2, Lvy0/l;

    .line 84
    .line 85
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-direct {v2, v4, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 93
    .line 94
    .line 95
    new-instance v0, Lsm/d;

    .line 96
    .line 97
    const/4 v4, 0x0

    .line 98
    invoke-direct {v0, v2, v4}, Lsm/d;-><init>(Lvy0/l;I)V

    .line 99
    .line 100
    .line 101
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 102
    .line 103
    invoke-virtual {p0, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 110
    if-ne v0, v1, :cond_4

    .line 111
    .line 112
    return-object v1

    .line 113
    :cond_4
    move-object v0, p0

    .line 114
    move-object p0, p1

    .line 115
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p0, Landroidx/lifecycle/w;

    .line 118
    .line 119
    if-eqz p0, :cond_5

    .line 120
    .line 121
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 122
    .line 123
    .line 124
    :cond_5
    return-object v3

    .line 125
    :catchall_1
    move-exception v0

    .line 126
    move-object v5, v0

    .line 127
    move-object v0, p0

    .line 128
    move-object p0, p1

    .line 129
    move-object p1, v5

    .line 130
    :goto_2
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p0, Landroidx/lifecycle/w;

    .line 133
    .line 134
    if-eqz p0, :cond_6

    .line 135
    .line 136
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    throw p1
.end method
