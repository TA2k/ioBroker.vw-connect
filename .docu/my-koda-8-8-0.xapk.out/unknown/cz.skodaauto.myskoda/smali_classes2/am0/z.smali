.class public final Lam0/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lam0/u;


# direct methods
.method public constructor <init>(Lti0/a;Lam0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lam0/z;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lam0/z;->b:Lam0/u;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lam0/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lam0/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lam0/x;

    .line 7
    .line 8
    iget v1, v0, Lam0/x;->f:I

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
    iput v1, v0, Lam0/x;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lam0/x;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lam0/x;-><init>(Lam0/z;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lam0/x;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lam0/x;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto/16 :goto_7

    .line 43
    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p1, p0, Lam0/z;->a:Lti0/a;

    .line 60
    .line 61
    iput v4, v0, Lam0/x;->f:I

    .line 62
    .line 63
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-ne p1, v1, :cond_4

    .line 68
    .line 69
    goto/16 :goto_6

    .line 70
    .line 71
    :cond_4
    :goto_1
    check-cast p1, Ldx/i;

    .line 72
    .line 73
    if-eqz p1, :cond_c

    .line 74
    .line 75
    iput v3, v0, Lam0/x;->f:I

    .line 76
    .line 77
    new-instance v2, Lpx0/i;

    .line 78
    .line 79
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-direct {v2, v0}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 84
    .line 85
    .line 86
    iget-object v0, p0, Lam0/z;->b:Lam0/u;

    .line 87
    .line 88
    check-cast v0, Lxl0/h;

    .line 89
    .line 90
    iget v0, v0, Lxl0/h;->a:I

    .line 91
    .line 92
    new-instance v5, Lc2/k;

    .line 93
    .line 94
    const/4 v6, 0x1

    .line 95
    invoke-direct {v5, v6, v2, p0}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    const-string p0, "mode"

    .line 99
    .line 100
    invoke-static {v0, p0}, Lia/b;->q(ILjava/lang/String;)V

    .line 101
    .line 102
    .line 103
    new-instance p0, Ljava/util/Date;

    .line 104
    .line 105
    invoke-direct {p0}, Ljava/util/Date;-><init>()V

    .line 106
    .line 107
    .line 108
    const/4 v6, 0x3

    .line 109
    if-ne v0, v3, :cond_5

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_5
    new-instance v0, Ljava/util/Date;

    .line 113
    .line 114
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 115
    .line 116
    .line 117
    monitor-enter p1

    .line 118
    :try_start_0
    invoke-virtual {p1}, Ldx/i;->b()V

    .line 119
    .line 120
    .line 121
    iget-object v7, p1, Ldx/i;->f:Lcom/wultra/android/sslpinning/model/CachedData;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 122
    .line 123
    monitor-exit p1

    .line 124
    if-nez v7, :cond_6

    .line 125
    .line 126
    :goto_2
    move v3, v4

    .line 127
    goto :goto_3

    .line 128
    :cond_6
    invoke-virtual {v7, v0}, Lcom/wultra/android/sslpinning/model/CachedData;->numberOfValidCertificates$library_release(Ljava/util/Date;)I

    .line 129
    .line 130
    .line 131
    move-result v8

    .line 132
    if-nez v8, :cond_7

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_7
    invoke-virtual {v7}, Lcom/wultra/android/sslpinning/model/CachedData;->getNextUpdate()Ljava/util/Date;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    invoke-virtual {v4, v0}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    if-eqz v0, :cond_8

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_8
    move v3, v6

    .line 147
    :goto_3
    move v4, v3

    .line 148
    :goto_4
    iget-object v0, p1, Ldx/i;->i:Landroid/os/Handler;

    .line 149
    .line 150
    new-instance v3, Ldx/a;

    .line 151
    .line 152
    invoke-direct {v3, v5, v4}, Ldx/a;-><init>(Lc2/k;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 156
    .line 157
    .line 158
    if-eq v4, v6, :cond_9

    .line 159
    .line 160
    new-instance v0, Ldx/b;

    .line 161
    .line 162
    invoke-direct {v0, p1, p0, v5, v4}, Ldx/b;-><init>(Ldx/i;Ljava/util/Date;Lc2/k;I)V

    .line 163
    .line 164
    .line 165
    new-instance p0, Ljava/lang/Thread;

    .line 166
    .line 167
    invoke-direct {p0, v0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 168
    .line 169
    .line 170
    const-string p1, "SilentCertStoreUpdate"

    .line 171
    .line 172
    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const/16 p1, 0xa

    .line 176
    .line 177
    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setPriority(I)V

    .line 178
    .line 179
    .line 180
    new-instance p1, Ldx/c;

    .line 181
    .line 182
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V

    .line 189
    .line 190
    .line 191
    goto :goto_5

    .line 192
    :cond_9
    iget-object p0, p1, Ldx/i;->i:Landroid/os/Handler;

    .line 193
    .line 194
    new-instance p1, La8/j0;

    .line 195
    .line 196
    const/4 v0, 0x3

    .line 197
    invoke-direct {p1, v5, v4, v0}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 201
    .line 202
    .line 203
    :goto_5
    invoke-virtual {v2}, Lpx0/i;->a()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    if-ne p1, v1, :cond_a

    .line 208
    .line 209
    :goto_6
    return-object v1

    .line 210
    :cond_a
    :goto_7
    check-cast p1, Lne0/t;

    .line 211
    .line 212
    if-nez p1, :cond_b

    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_b
    return-object p1

    .line 216
    :catchall_0
    move-exception p0

    .line 217
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 218
    throw p0

    .line 219
    :cond_c
    :goto_8
    new-instance p0, Lne0/e;

    .line 220
    .line 221
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 222
    .line 223
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    return-object p0
.end method
