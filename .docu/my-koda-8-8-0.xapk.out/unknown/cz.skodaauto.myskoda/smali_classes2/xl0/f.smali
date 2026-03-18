.class public final Lxl0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxl0/f;Lretrofit2/Response;)Lne0/a;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance p0, Lne0/a;

    .line 5
    .line 6
    iget-object v0, p1, Lretrofit2/Response;->a:Ld01/t0;

    .line 7
    .line 8
    iget-object v0, v0, Ld01/t0;->d:Ld01/k0;

    .line 9
    .line 10
    iget-object v1, v0, Ld01/k0;->a:Ld01/a0;

    .line 11
    .line 12
    iget-object v1, v1, Ld01/a0;->i:Ljava/lang/String;

    .line 13
    .line 14
    const-class v2, Lcm0/e;

    .line 15
    .line 16
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 17
    .line 18
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const-string v3, "type"

    .line 23
    .line 24
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v2}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget-object v0, v0, Ld01/k0;->e:Ljp/ng;

    .line 32
    .line 33
    invoke-virtual {v0, v2}, Ljp/ng;->a(Lhy0/d;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lcm0/e;

    .line 42
    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    iget-object v0, v0, Lcm0/e;->a:Ljava/lang/String;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 v0, 0x0

    .line 49
    :goto_0
    iget-object p1, p1, Lretrofit2/Response;->a:Ld01/t0;

    .line 50
    .line 51
    iget-object p1, p1, Ld01/t0;->i:Ld01/y;

    .line 52
    .line 53
    const-string v2, "traceparent"

    .line 54
    .line 55
    invoke-virtual {p1, v2}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, v1, v0, p1}, Lne0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return-object p0
.end method

.method public static synthetic f(Lxl0/f;Lay0/k;Lay0/k;)Lyy0/m1;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method


# virtual methods
.method public final b(Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lxl0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lxl0/a;

    .line 7
    .line 8
    iget v1, v0, Lxl0/a;->f:I

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
    iput v1, v0, Lxl0/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lxl0/a;-><init>(Lxl0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lxl0/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lxl0/a;->f:I

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
    :try_start_0
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

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
    :try_start_1
    sget-object p0, Lge0/b;->c:Lcz0/d;

    .line 52
    .line 53
    new-instance v1, Lmy/r;

    .line 54
    .line 55
    const/4 v3, 0x2

    .line 56
    const/4 v4, 0x0

    .line 57
    invoke-direct {v1, p1, v4, v3}, Lmy/r;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 58
    .line 59
    .line 60
    iput v2, v0, Lxl0/a;->f:I

    .line 61
    .line 62
    invoke-static {p0, v1, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, p2, :cond_3

    .line 67
    .line 68
    return-object p2

    .line 69
    :cond_3
    :goto_1
    new-instance p1, Lne0/e;

    .line 70
    .line 71
    invoke-direct {p1, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 72
    .line 73
    .line 74
    return-object p1

    .line 75
    :catch_0
    move-exception v0

    .line 76
    move-object p0, v0

    .line 77
    instance-of p1, p0, Ljava/net/SocketTimeoutException;

    .line 78
    .line 79
    const-string p2, "Unable to proceed request."

    .line 80
    .line 81
    if-eqz p1, :cond_4

    .line 82
    .line 83
    new-instance v0, Lne0/c;

    .line 84
    .line 85
    new-instance v1, Lbm0/a;

    .line 86
    .line 87
    invoke-direct {v1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 88
    .line 89
    .line 90
    sget-object v4, Lne0/b;->f:Lne0/b;

    .line 91
    .line 92
    const/16 v5, 0xe

    .line 93
    .line 94
    const/4 v2, 0x0

    .line 95
    const/4 v3, 0x0

    .line 96
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 97
    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_4
    instance-of p1, p0, Ljava/net/UnknownHostException;

    .line 101
    .line 102
    if-nez p1, :cond_6

    .line 103
    .line 104
    instance-of p1, p0, Ljava/net/ConnectException;

    .line 105
    .line 106
    if-nez p1, :cond_6

    .line 107
    .line 108
    instance-of p1, p0, Ljava/io/IOException;

    .line 109
    .line 110
    if-eqz p1, :cond_5

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_5
    new-instance v0, Lne0/c;

    .line 114
    .line 115
    new-instance v1, Lbm0/a;

    .line 116
    .line 117
    invoke-direct {v1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 118
    .line 119
    .line 120
    sget-object v4, Lne0/b;->e:Lne0/b;

    .line 121
    .line 122
    const/16 v5, 0xe

    .line 123
    .line 124
    const/4 v2, 0x0

    .line 125
    const/4 v3, 0x0

    .line 126
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 127
    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_6
    :goto_2
    new-instance v1, Lne0/c;

    .line 131
    .line 132
    new-instance v2, Lbm0/a;

    .line 133
    .line 134
    invoke-direct {v2, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 135
    .line 136
    .line 137
    sget-object v5, Lne0/b;->g:Lne0/b;

    .line 138
    .line 139
    const/16 v6, 0xe

    .line 140
    .line 141
    const/4 v3, 0x0

    .line 142
    const/4 v4, 0x0

    .line 143
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 144
    .line 145
    .line 146
    move-object v0, v1

    .line 147
    :goto_3
    return-object v0
.end method

.method public final c(Lay0/k;)Lyy0/m1;
    .locals 2

    .line 1
    new-instance v0, Lws/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lws/b;-><init>(Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lyy0/m1;

    .line 8
    .line 9
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final d(Lay0/k;Lay0/k;)Lyy0/m1;
    .locals 2

    .line 1
    new-instance v0, Laa/i0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, p2, v1}, Laa/i0;-><init>(Lxl0/f;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lyy0/m1;

    .line 8
    .line 9
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;
    .locals 6

    .line 1
    new-instance v0, La7/k0;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    move-object v1, p0

    .line 5
    move-object v2, p1

    .line 6
    move-object v3, p2

    .line 7
    move-object v4, p3

    .line 8
    invoke-direct/range {v0 .. v5}, La7/k0;-><init>(Lxl0/f;Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lyy0/m1;

    .line 12
    .line 13
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public final g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v1, p4, Lxl0/c;

    .line 2
    .line 3
    if-eqz v1, :cond_0

    .line 4
    .line 5
    move-object v1, p4

    .line 6
    check-cast v1, Lxl0/c;

    .line 7
    .line 8
    iget v3, v1, Lxl0/c;->h:I

    .line 9
    .line 10
    const/high16 v4, -0x80000000

    .line 11
    .line 12
    and-int v5, v3, v4

    .line 13
    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    sub-int/2addr v3, v4

    .line 17
    iput v3, v1, Lxl0/c;->h:I

    .line 18
    .line 19
    :goto_0
    move-object v6, v1

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v1, Lxl0/c;

    .line 22
    .line 23
    invoke-direct {v1, p0, p4}, Lxl0/c;-><init>(Lxl0/f;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, v6, Lxl0/c;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, v6, Lxl0/c;->h:I

    .line 32
    .line 33
    const/4 v3, 0x3

    .line 34
    const/4 v4, 0x2

    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v1, :cond_4

    .line 37
    .line 38
    if-eq v1, v5, :cond_3

    .line 39
    .line 40
    if-eq v1, v4, :cond_2

    .line 41
    .line 42
    if-ne v1, v3, :cond_1

    .line 43
    .line 44
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_4

    .line 48
    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    return-object v0

    .line 61
    :cond_3
    iget-object v1, v6, Lxl0/c;->e:Lay0/k;

    .line 62
    .line 63
    iget-object v5, v6, Lxl0/c;->d:Lay0/k;

    .line 64
    .line 65
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object v10, v5

    .line 69
    move-object v5, v0

    .line 70
    move-object v0, v10

    .line 71
    goto :goto_2

    .line 72
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iput-object p2, v6, Lxl0/c;->d:Lay0/k;

    .line 76
    .line 77
    iput-object p3, v6, Lxl0/c;->e:Lay0/k;

    .line 78
    .line 79
    iput v5, v6, Lxl0/c;->h:I

    .line 80
    .line 81
    invoke-virtual {p0, p1, v6}, Lxl0/f;->b(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    if-ne v5, v7, :cond_5

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    move-object v0, p2

    .line 89
    move-object v1, p3

    .line 90
    :goto_2
    check-cast v5, Lne0/t;

    .line 91
    .line 92
    instance-of v8, v5, Lne0/e;

    .line 93
    .line 94
    if-eqz v8, :cond_9

    .line 95
    .line 96
    check-cast v5, Lne0/e;

    .line 97
    .line 98
    iget-object v5, v5, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v5, Lretrofit2/Response;

    .line 101
    .line 102
    iget-object v8, v5, Lretrofit2/Response;->a:Ld01/t0;

    .line 103
    .line 104
    iget-boolean v8, v8, Ld01/t0;->t:Z

    .line 105
    .line 106
    const/4 v9, 0x0

    .line 107
    if-eqz v8, :cond_7

    .line 108
    .line 109
    iput-object v9, v6, Lxl0/c;->d:Lay0/k;

    .line 110
    .line 111
    iput-object v9, v6, Lxl0/c;->e:Lay0/k;

    .line 112
    .line 113
    iput v4, v6, Lxl0/c;->h:I

    .line 114
    .line 115
    sget-object v8, Lge0/b;->c:Lcz0/d;

    .line 116
    .line 117
    move-object v3, v0

    .line 118
    new-instance v0, Lxl0/b;

    .line 119
    .line 120
    move-object v1, v5

    .line 121
    const/4 v5, 0x0

    .line 122
    move-object v2, p0

    .line 123
    move-object v4, v9

    .line 124
    invoke-direct/range {v0 .. v5}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 125
    .line 126
    .line 127
    invoke-static {v8, v0, v6}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-ne v0, v7, :cond_6

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_6
    return-object v0

    .line 135
    :cond_7
    move-object v4, v9

    .line 136
    iput-object v4, v6, Lxl0/c;->d:Lay0/k;

    .line 137
    .line 138
    iput-object v4, v6, Lxl0/c;->e:Lay0/k;

    .line 139
    .line 140
    iput v3, v6, Lxl0/c;->h:I

    .line 141
    .line 142
    sget-object v8, Lge0/b;->c:Lcz0/d;

    .line 143
    .line 144
    new-instance v0, Lxl0/b;

    .line 145
    .line 146
    move-object v3, v1

    .line 147
    move-object v1, v5

    .line 148
    const/4 v5, 0x1

    .line 149
    move-object v2, p0

    .line 150
    invoke-direct/range {v0 .. v5}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 151
    .line 152
    .line 153
    invoke-static {v8, v0, v6}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    if-ne v0, v7, :cond_8

    .line 158
    .line 159
    :goto_3
    return-object v7

    .line 160
    :cond_8
    :goto_4
    const-string v1, "null cannot be cast to non-null type cz.skodaauto.myskoda.library.data.infrastructure.Data.Error"

    .line 161
    .line 162
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    check-cast v0, Lne0/c;

    .line 166
    .line 167
    return-object v0

    .line 168
    :cond_9
    instance-of v0, v5, Lne0/c;

    .line 169
    .line 170
    if-eqz v0, :cond_a

    .line 171
    .line 172
    return-object v5

    .line 173
    :cond_a
    new-instance v0, La8/r0;

    .line 174
    .line 175
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 176
    .line 177
    .line 178
    throw v0
.end method

.method public final h(Lay0/k;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lxl0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lxl0/d;

    .line 7
    .line 8
    iget v1, v0, Lxl0/d;->g:I

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
    iput v1, v0, Lxl0/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lxl0/d;-><init>(Lxl0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lxl0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_4

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p3

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
    iget-object p2, v0, Lxl0/d;->d:Lay0/k;

    .line 52
    .line 53
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_3
    move-object v7, p2

    .line 57
    goto :goto_1

    .line 58
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p2, v0, Lxl0/d;->d:Lay0/k;

    .line 62
    .line 63
    iput v4, v0, Lxl0/d;->g:I

    .line 64
    .line 65
    invoke-virtual {p0, p1, v0}, Lxl0/f;->b(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p3

    .line 69
    if-ne p3, v1, :cond_3

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :goto_1
    check-cast p3, Lne0/t;

    .line 73
    .line 74
    instance-of p1, p3, Lne0/e;

    .line 75
    .line 76
    if-eqz p1, :cond_7

    .line 77
    .line 78
    check-cast p3, Lne0/e;

    .line 79
    .line 80
    iget-object p1, p3, Lne0/e;->a:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v5, p1

    .line 83
    check-cast v5, Lretrofit2/Response;

    .line 84
    .line 85
    iget-object p1, v5, Lretrofit2/Response;->a:Ld01/t0;

    .line 86
    .line 87
    iget-boolean p1, p1, Ld01/t0;->t:Z

    .line 88
    .line 89
    if-eqz p1, :cond_5

    .line 90
    .line 91
    new-instance p0, Lne0/e;

    .line 92
    .line 93
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-object p0

    .line 99
    :cond_5
    const/4 v8, 0x0

    .line 100
    iput-object v8, v0, Lxl0/d;->d:Lay0/k;

    .line 101
    .line 102
    iput v3, v0, Lxl0/d;->g:I

    .line 103
    .line 104
    sget-object p1, Lge0/b;->c:Lcz0/d;

    .line 105
    .line 106
    new-instance v4, Lxl0/b;

    .line 107
    .line 108
    const/4 v9, 0x1

    .line 109
    move-object v6, p0

    .line 110
    invoke-direct/range {v4 .. v9}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {p1, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-ne p0, v1, :cond_6

    .line 118
    .line 119
    :goto_2
    return-object v1

    .line 120
    :cond_6
    return-object p0

    .line 121
    :cond_7
    instance-of p0, p3, Lne0/c;

    .line 122
    .line 123
    if-eqz p0, :cond_8

    .line 124
    .line 125
    return-object p3

    .line 126
    :cond_8
    new-instance p0, La8/r0;

    .line 127
    .line 128
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 129
    .line 130
    .line 131
    throw p0
.end method

.method public final i(Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lxl0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lxl0/e;

    .line 7
    .line 8
    iget v1, v0, Lxl0/e;->f:I

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
    iput v1, v0, Lxl0/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lxl0/e;-><init>(Lxl0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lxl0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

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
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lxl0/e;->f:I

    .line 59
    .line 60
    invoke-virtual {p0, p1, v0}, Lxl0/f;->b(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    if-ne p2, v1, :cond_4

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 68
    .line 69
    instance-of p1, p2, Lne0/e;

    .line 70
    .line 71
    if-eqz p1, :cond_7

    .line 72
    .line 73
    check-cast p2, Lne0/e;

    .line 74
    .line 75
    iget-object p1, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v5, p1

    .line 78
    check-cast v5, Lretrofit2/Response;

    .line 79
    .line 80
    iget-object p1, v5, Lretrofit2/Response;->a:Ld01/t0;

    .line 81
    .line 82
    iget-boolean p1, p1, Ld01/t0;->t:Z

    .line 83
    .line 84
    if-eqz p1, :cond_5

    .line 85
    .line 86
    new-instance p0, Lne0/e;

    .line 87
    .line 88
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-object p0

    .line 94
    :cond_5
    iput v3, v0, Lxl0/e;->f:I

    .line 95
    .line 96
    sget-object p1, Lge0/b;->c:Lcz0/d;

    .line 97
    .line 98
    new-instance v4, Lxl0/b;

    .line 99
    .line 100
    const/4 v9, 0x1

    .line 101
    const/4 v7, 0x0

    .line 102
    move-object v8, v7

    .line 103
    move-object v6, p0

    .line 104
    invoke-direct/range {v4 .. v9}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 105
    .line 106
    .line 107
    invoke-static {p1, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p2

    .line 111
    if-ne p2, v1, :cond_6

    .line 112
    .line 113
    :goto_2
    return-object v1

    .line 114
    :cond_6
    :goto_3
    check-cast p2, Lne0/t;

    .line 115
    .line 116
    return-object p2

    .line 117
    :cond_7
    instance-of p0, p2, Lne0/c;

    .line 118
    .line 119
    if-eqz p0, :cond_8

    .line 120
    .line 121
    return-object p2

    .line 122
    :cond_8
    new-instance p0, La8/r0;

    .line 123
    .line 124
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 125
    .line 126
    .line 127
    throw p0
.end method
