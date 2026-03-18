.class public abstract Lvy0/n0;
.super Lcz0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public f:I


# direct methods
.method public constructor <init>(I)V
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-direct {p0, v0, v1, v2}, Lcz0/i;-><init>(JZ)V

    .line 5
    .line 6
    .line 7
    iput p1, p0, Lvy0/n0;->f:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public a(Ljava/util/concurrent/CancellationException;)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract d()Lkotlin/coroutines/Continuation;
.end method

.method public e(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 1

    .line 1
    instance-of p0, p1, Lvy0/u;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    check-cast p1, Lvy0/u;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object p1, v0

    .line 10
    :goto_0
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p0, p1, Lvy0/u;->a:Ljava/lang/Throwable;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_1
    return-object v0
.end method

.method public f(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    return-object p1
.end method

.method public final g(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    new-instance v0, Lvy0/d0;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Fatal exception in coroutines machinery for "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v2, ". Please read KDoc to \'handleFatalException\' method and report this incident to maintainers"

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-direct {v0, v1, p1}, Ljava/lang/Error;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lvy0/n0;->d()Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0, v0}, Lvy0/e0;->y(Lpx0/g;Ljava/lang/Throwable;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public abstract i()Ljava/lang/Object;
.end method

.method public final run()V
    .locals 11

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lvy0/n0;->d()Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTask>"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    check-cast v0, Laz0/f;

    .line 11
    .line 12
    iget-object v1, v0, Laz0/f;->h:Lrx0/c;

    .line 13
    .line 14
    iget-object v0, v0, Laz0/f;->j:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {v2, v0}, Laz0/b;->n(Lpx0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sget-object v3, Laz0/b;->d:Lj51/i;

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    if-eq v0, v3, :cond_0

    .line 28
    .line 29
    invoke-static {v1, v2, v0}, Lvy0/e0;->Q(Lkotlin/coroutines/Continuation;Lpx0/g;Ljava/lang/Object;)Lvy0/i2;

    .line 30
    .line 31
    .line 32
    move-result-object v3
    :try_end_0
    .catch Lvy0/l0; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception v0

    .line 35
    goto/16 :goto_5

    .line 36
    .line 37
    :catch_0
    move-exception v0

    .line 38
    goto/16 :goto_6

    .line 39
    .line 40
    :cond_0
    move-object v3, v4

    .line 41
    :goto_0
    :try_start_1
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    invoke-virtual {p0}, Lvy0/n0;->i()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    invoke-virtual {p0, v6}, Lvy0/n0;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    if-nez v7, :cond_3

    .line 54
    .line 55
    iget v8, p0, Lvy0/n0;->f:I

    .line 56
    .line 57
    const/4 v9, 0x1

    .line 58
    if-eq v8, v9, :cond_2

    .line 59
    .line 60
    const/4 v10, 0x2

    .line 61
    if-ne v8, v10, :cond_1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    const/4 v9, 0x0

    .line 65
    :cond_2
    :goto_1
    if-eqz v9, :cond_3

    .line 66
    .line 67
    sget-object v4, Lvy0/h1;->d:Lvy0/h1;

    .line 68
    .line 69
    invoke-interface {v5, v4}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    check-cast v4, Lvy0/i1;

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :catchall_1
    move-exception v1

    .line 77
    goto :goto_4

    .line 78
    :cond_3
    :goto_2
    if-eqz v4, :cond_4

    .line 79
    .line 80
    invoke-interface {v4}, Lvy0/i1;->a()Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-nez v5, :cond_4

    .line 85
    .line 86
    invoke-interface {v4}, Lvy0/i1;->j()Ljava/util/concurrent/CancellationException;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-virtual {p0, v4}, Lvy0/n0;->a(Ljava/util/concurrent/CancellationException;)V

    .line 91
    .line 92
    .line 93
    invoke-static {v4}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    invoke-interface {v1, v4}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_4
    if-eqz v7, :cond_5

    .line 102
    .line 103
    invoke-static {v7}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-interface {v1, v4}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_5
    invoke-virtual {p0, v6}, Lvy0/n0;->f(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    invoke-interface {v1, v4}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 116
    .line 117
    .line 118
    :goto_3
    if-eqz v3, :cond_6

    .line 119
    .line 120
    :try_start_2
    invoke-virtual {v3}, Lvy0/i2;->p0()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-eqz v1, :cond_9

    .line 125
    .line 126
    :cond_6
    invoke-static {v2, v0}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    :goto_4
    if-eqz v3, :cond_7

    .line 131
    .line 132
    invoke-virtual {v3}, Lvy0/i2;->p0()Z

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    if-eqz v3, :cond_8

    .line 137
    .line 138
    :cond_7
    invoke-static {v2, v0}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_8
    throw v1
    :try_end_2
    .catch Lvy0/l0; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 142
    :goto_5
    invoke-virtual {p0, v0}, Lvy0/n0;->g(Ljava/lang/Throwable;)V

    .line 143
    .line 144
    .line 145
    goto :goto_7

    .line 146
    :goto_6
    invoke-virtual {p0}, Lvy0/n0;->d()Lkotlin/coroutines/Continuation;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    iget-object v0, v0, Lvy0/l0;->d:Ljava/lang/Throwable;

    .line 155
    .line 156
    invoke-static {p0, v0}, Lvy0/e0;->y(Lpx0/g;Ljava/lang/Throwable;)V

    .line 157
    .line 158
    .line 159
    :cond_9
    :goto_7
    return-void
.end method
