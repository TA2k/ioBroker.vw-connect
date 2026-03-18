.class public final Lyy0/c2;
.super Lzy0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j1;
.implements Lyy0/i;
.implements Lzy0/o;


# static fields
.field public static final synthetic i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _state$volatile:Ljava/lang/Object;

.field public h:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Ljava/lang/Object;

    .line 2
    .line 3
    const-string v1, "_state$volatile"

    .line 4
    .line 5
    const-class v2, Lyy0/c2;

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lyy0/c2;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/c2;->_state$volatile:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x1

    .line 5
    return p0
.end method

.method public final b(Lpx0/g;ILxy0/a;)Lyy0/i;
    .locals 1

    .line 1
    if-ltz p2, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    if-ge p2, v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, -0x2

    .line 8
    if-ne p2, v0, :cond_1

    .line 9
    .line 10
    :goto_0
    sget-object v0, Lxy0/a;->e:Lxy0/a;

    .line 11
    .line 12
    if-ne p3, v0, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    invoke-static {p0, p1, p2, p3}, Lyy0/u;->y(Lyy0/n1;Lpx0/g;ILxy0/a;)Lyy0/i;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_1
    return-object p0
.end method

.method public final c()Ljava/util/List;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lyy0/b2;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lyy0/b2;

    .line 13
    .line 14
    iget v4, v3, Lyy0/b2;->k:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lyy0/b2;->k:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lyy0/b2;

    .line 27
    .line 28
    invoke-direct {v3, v1, v2}, Lyy0/b2;-><init>(Lyy0/c2;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lyy0/b2;->i:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lyy0/b2;->k:I

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x3

    .line 39
    const/4 v8, 0x2

    .line 40
    const/4 v9, 0x1

    .line 41
    if-eqz v5, :cond_4

    .line 42
    .line 43
    if-eq v5, v9, :cond_3

    .line 44
    .line 45
    if-eq v5, v8, :cond_2

    .line 46
    .line 47
    if-ne v5, v7, :cond_1

    .line 48
    .line 49
    iget-object v0, v3, Lyy0/b2;->h:Ljava/lang/Object;

    .line 50
    .line 51
    iget-object v1, v3, Lyy0/b2;->g:Lvy0/i1;

    .line 52
    .line 53
    iget-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 54
    .line 55
    iget-object v10, v3, Lyy0/b2;->e:Lyy0/j;

    .line 56
    .line 57
    iget-object v11, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 58
    .line 59
    :try_start_0
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    move-object v2, v1

    .line 63
    move-object v1, v11

    .line 64
    goto :goto_2

    .line 65
    :catchall_0
    move-exception v0

    .line 66
    move-object v1, v11

    .line 67
    goto/16 :goto_8

    .line 68
    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget-object v0, v3, Lyy0/b2;->h:Ljava/lang/Object;

    .line 78
    .line 79
    iget-object v1, v3, Lyy0/b2;->g:Lvy0/i1;

    .line 80
    .line 81
    iget-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 82
    .line 83
    iget-object v10, v3, Lyy0/b2;->e:Lyy0/j;

    .line 84
    .line 85
    iget-object v11, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 86
    .line 87
    :try_start_1
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 88
    .line 89
    .line 90
    goto/16 :goto_5

    .line 91
    .line 92
    :cond_3
    iget-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 93
    .line 94
    iget-object v0, v3, Lyy0/b2;->e:Lyy0/j;

    .line 95
    .line 96
    iget-object v1, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 97
    .line 98
    :try_start_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :catchall_1
    move-exception v0

    .line 103
    goto/16 :goto_8

    .line 104
    .line 105
    :cond_4
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v1}, Lzy0/b;->d()Lzy0/d;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    move-object v5, v2

    .line 113
    check-cast v5, Lyy0/d2;

    .line 114
    .line 115
    :try_start_3
    instance-of v2, v0, Lyy0/f2;

    .line 116
    .line 117
    if-eqz v2, :cond_5

    .line 118
    .line 119
    move-object v2, v0

    .line 120
    check-cast v2, Lyy0/f2;

    .line 121
    .line 122
    iput-object v1, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 123
    .line 124
    iput-object v0, v3, Lyy0/b2;->e:Lyy0/j;

    .line 125
    .line 126
    iput-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 127
    .line 128
    iput v9, v3, Lyy0/b2;->k:I

    .line 129
    .line 130
    invoke-virtual {v2, v3}, Lyy0/f2;->b(Lrx0/c;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    if-ne v2, v4, :cond_5

    .line 135
    .line 136
    goto/16 :goto_7

    .line 137
    .line 138
    :cond_5
    :goto_1
    invoke-interface {v3}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    sget-object v10, Lvy0/h1;->d:Lvy0/h1;

    .line 143
    .line 144
    invoke-interface {v2, v10}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    check-cast v2, Lvy0/i1;

    .line 149
    .line 150
    move-object v10, v0

    .line 151
    move-object v0, v6

    .line 152
    :cond_6
    :goto_2
    sget-object v11, Lyy0/c2;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 153
    .line 154
    invoke-virtual {v11, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v11

    .line 158
    if-eqz v2, :cond_8

    .line 159
    .line 160
    invoke-interface {v2}, Lvy0/i1;->a()Z

    .line 161
    .line 162
    .line 163
    move-result v12

    .line 164
    if-eqz v12, :cond_7

    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_7
    invoke-interface {v2}, Lvy0/i1;->j()Ljava/util/concurrent/CancellationException;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    throw v0

    .line 172
    :cond_8
    :goto_3
    if-eqz v0, :cond_9

    .line 173
    .line 174
    invoke-virtual {v0, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v12

    .line 178
    if-nez v12, :cond_c

    .line 179
    .line 180
    :cond_9
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 181
    .line 182
    if-ne v11, v0, :cond_a

    .line 183
    .line 184
    move-object v0, v6

    .line 185
    goto :goto_4

    .line 186
    :cond_a
    move-object v0, v11

    .line 187
    :goto_4
    iput-object v1, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 188
    .line 189
    iput-object v10, v3, Lyy0/b2;->e:Lyy0/j;

    .line 190
    .line 191
    iput-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 192
    .line 193
    iput-object v2, v3, Lyy0/b2;->g:Lvy0/i1;

    .line 194
    .line 195
    iput-object v11, v3, Lyy0/b2;->h:Ljava/lang/Object;

    .line 196
    .line 197
    iput v8, v3, Lyy0/b2;->k:I

    .line 198
    .line 199
    invoke-interface {v10, v0, v3}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    if-ne v0, v4, :cond_b

    .line 204
    .line 205
    goto :goto_7

    .line 206
    :cond_b
    move-object v0, v11

    .line 207
    move-object v11, v1

    .line 208
    move-object v1, v2

    .line 209
    :goto_5
    move-object v2, v1

    .line 210
    move-object v1, v11

    .line 211
    :cond_c
    iget-object v11, v5, Lyy0/d2;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 212
    .line 213
    sget-object v12, Lyy0/u;->c:Lj51/i;

    .line 214
    .line 215
    invoke-virtual {v11, v12}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    sget-object v13, Lyy0/u;->d:Lj51/i;

    .line 223
    .line 224
    if-ne v11, v13, :cond_d

    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_d
    iput-object v1, v3, Lyy0/b2;->d:Lyy0/c2;

    .line 228
    .line 229
    iput-object v10, v3, Lyy0/b2;->e:Lyy0/j;

    .line 230
    .line 231
    iput-object v5, v3, Lyy0/b2;->f:Lyy0/d2;

    .line 232
    .line 233
    iput-object v2, v3, Lyy0/b2;->g:Lvy0/i1;

    .line 234
    .line 235
    iput-object v0, v3, Lyy0/b2;->h:Ljava/lang/Object;

    .line 236
    .line 237
    iput v7, v3, Lyy0/b2;->k:I

    .line 238
    .line 239
    sget-object v11, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    new-instance v13, Lvy0/l;

    .line 242
    .line 243
    invoke-static {v3}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 244
    .line 245
    .line 246
    move-result-object v14

    .line 247
    invoke-direct {v13, v9, v14}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v13}, Lvy0/l;->q()V

    .line 251
    .line 252
    .line 253
    iget-object v14, v5, Lyy0/d2;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 254
    .line 255
    :cond_e
    invoke-virtual {v14, v12, v13}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result v15

    .line 259
    if-eqz v15, :cond_f

    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_f
    invoke-virtual {v14}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v15

    .line 266
    if-eq v15, v12, :cond_e

    .line 267
    .line 268
    invoke-virtual {v13, v11}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 269
    .line 270
    .line 271
    :goto_6
    invoke-virtual {v13}, Lvy0/l;->p()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v12

    .line 275
    sget-object v13, Lqx0/a;->d:Lqx0/a;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 276
    .line 277
    if-ne v12, v13, :cond_10

    .line 278
    .line 279
    move-object v11, v12

    .line 280
    :cond_10
    if-ne v11, v4, :cond_6

    .line 281
    .line 282
    :goto_7
    return-object v4

    .line 283
    :goto_8
    invoke-virtual {v1, v5}, Lzy0/b;->g(Lzy0/d;)V

    .line 284
    .line 285
    .line 286
    throw v0
.end method

.method public final e()Lzy0/d;
    .locals 0

    .line 1
    new-instance p0, Lyy0/d2;

    .line 2
    .line 3
    invoke-direct {p0}, Lyy0/d2;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method

.method public final f()[Lzy0/d;
    .locals 0

    .line 1
    const/4 p0, 0x2

    .line 2
    new-array p0, p0, [Lyy0/d2;

    .line 3
    .line 4
    return-object p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 2
    .line 3
    sget-object v1, Lyy0/c2;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 4
    .line 5
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-ne p0, v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    :cond_0
    return-object p0
.end method

.method public final i(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 1

    .line 1
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    move-object p1, v0

    .line 6
    :cond_0
    if-nez p2, :cond_1

    .line 7
    .line 8
    move-object p2, v0

    .line 9
    :cond_1
    invoke-virtual {p0, p1, p2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final j(Ljava/lang/Object;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p1, Lzy0/c;->b:Lj51/i;

    .line 4
    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final k(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 9

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    sget-object v0, Lyy0/c2;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 3
    .line 4
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    const/4 v2, 0x0

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    monitor-exit p0

    .line 18
    return v2

    .line 19
    :catchall_0
    move-exception p1

    .line 20
    goto/16 :goto_5

    .line 21
    .line 22
    :cond_0
    :try_start_1
    invoke-static {v1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    const/4 v1, 0x1

    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    monitor-exit p0

    .line 30
    return v1

    .line 31
    :cond_1
    :try_start_2
    invoke-virtual {v0, p0, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget p1, p0, Lyy0/c2;->h:I

    .line 35
    .line 36
    and-int/lit8 p2, p1, 0x1

    .line 37
    .line 38
    if-nez p2, :cond_b

    .line 39
    .line 40
    add-int/2addr p1, v1

    .line 41
    iput p1, p0, Lyy0/c2;->h:I

    .line 42
    .line 43
    iget-object p2, p0, Lzy0/b;->d:[Lzy0/d;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 44
    .line 45
    monitor-exit p0

    .line 46
    :goto_0
    check-cast p2, [Lyy0/d2;

    .line 47
    .line 48
    if-eqz p2, :cond_9

    .line 49
    .line 50
    array-length v0, p2

    .line 51
    move v3, v2

    .line 52
    :goto_1
    if-ge v3, v0, :cond_9

    .line 53
    .line 54
    aget-object v4, p2, v3

    .line 55
    .line 56
    if-eqz v4, :cond_8

    .line 57
    .line 58
    iget-object v4, v4, Lyy0/d2;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 59
    .line 60
    :goto_2
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    if-nez v5, :cond_2

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_2
    sget-object v6, Lyy0/u;->d:Lj51/i;

    .line 68
    .line 69
    if-ne v5, v6, :cond_3

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    sget-object v7, Lyy0/u;->c:Lj51/i;

    .line 73
    .line 74
    if-ne v5, v7, :cond_6

    .line 75
    .line 76
    :cond_4
    invoke-virtual {v4, v5, v6}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-eqz v7, :cond_5

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_5
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v7

    .line 87
    if-eq v7, v5, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_6
    invoke-virtual {v4, v5, v7}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    if-eqz v6, :cond_7

    .line 95
    .line 96
    check-cast v5, Lvy0/l;

    .line 97
    .line 98
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    invoke-virtual {v5, v4}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_7
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    if-eq v6, v5, :cond_6

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_8
    :goto_3
    add-int/lit8 v3, v3, 0x1

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_9
    monitor-enter p0

    .line 115
    :try_start_3
    iget p2, p0, Lyy0/c2;->h:I

    .line 116
    .line 117
    if-ne p2, p1, :cond_a

    .line 118
    .line 119
    add-int/2addr p1, v1

    .line 120
    iput p1, p0, Lyy0/c2;->h:I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 121
    .line 122
    monitor-exit p0

    .line 123
    return v1

    .line 124
    :catchall_1
    move-exception p1

    .line 125
    goto :goto_4

    .line 126
    :cond_a
    :try_start_4
    iget-object p1, p0, Lzy0/b;->d:[Lzy0/d;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 127
    .line 128
    monitor-exit p0

    .line 129
    move v8, p2

    .line 130
    move-object p2, p1

    .line 131
    move p1, v8

    .line 132
    goto :goto_0

    .line 133
    :goto_4
    monitor-exit p0

    .line 134
    throw p1

    .line 135
    :cond_b
    add-int/lit8 p1, p1, 0x2

    .line 136
    .line 137
    :try_start_5
    iput p1, p0, Lyy0/c2;->h:I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 138
    .line 139
    monitor-exit p0

    .line 140
    return v1

    .line 141
    :goto_5
    monitor-exit p0

    .line 142
    throw p1
.end method
