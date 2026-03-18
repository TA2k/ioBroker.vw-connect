.class public final Lna/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lna/b;


# instance fields
.field public final d:Lna/t;

.field public final e:Lna/t;

.field public final f:Ldv/a;

.field public final g:Ljava/lang/ThreadLocal;

.field public final h:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final i:J

.field public final j:I


# direct methods
.method public constructor <init>(Lb81/c;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ldv/a;

    const/16 v1, 0xa

    .line 3
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 4
    iput-object v0, p0, Lna/f;->f:Ldv/a;

    .line 5
    new-instance v0, Ljava/lang/ThreadLocal;

    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    iput-object v0, p0, Lna/f;->g:Ljava/lang/ThreadLocal;

    .line 6
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lna/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 7
    sget v0, Lmy0/c;->g:I

    const/16 v0, 0x1e

    sget-object v1, Lmy0/e;->h:Lmy0/e;

    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    move-result-wide v0

    iput-wide v0, p0, Lna/f;->i:J

    const/4 v0, 0x2

    .line 8
    iput v0, p0, Lna/f;->j:I

    .line 9
    new-instance v0, Lna/t;

    new-instance v1, Lmc/e;

    const/16 v2, 0x9

    invoke-direct {v1, p1, v2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    const/4 p1, 0x1

    invoke-direct {v0, p1, v1}, Lna/t;-><init>(ILay0/a;)V

    iput-object v0, p0, Lna/f;->d:Lna/t;

    .line 10
    iput-object v0, p0, Lna/f;->e:Lna/t;

    return-void
.end method

.method public constructor <init>(Lb81/c;Ljava/lang/String;I)V
    .locals 4

    const-string v0, "fileName"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    new-instance v0, Ldv/a;

    const/16 v1, 0xa

    .line 13
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 14
    iput-object v0, p0, Lna/f;->f:Ldv/a;

    .line 15
    new-instance v0, Ljava/lang/ThreadLocal;

    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    iput-object v0, p0, Lna/f;->g:Ljava/lang/ThreadLocal;

    .line 16
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lna/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 17
    sget v0, Lmy0/c;->g:I

    const/16 v0, 0x1e

    sget-object v2, Lmy0/e;->h:Lmy0/e;

    invoke-static {v0, v2}, Lmy0/h;->s(ILmy0/e;)J

    move-result-wide v2

    iput-wide v2, p0, Lna/f;->i:J

    const/4 v0, 0x2

    .line 18
    iput v0, p0, Lna/f;->j:I

    if-lez p3, :cond_0

    .line 19
    new-instance v0, Lna/t;

    .line 20
    new-instance v2, Lna/c;

    invoke-direct {v2, p1, p2, v1}, Lna/c;-><init>(Lb81/c;Ljava/lang/String;I)V

    .line 21
    invoke-direct {v0, p3, v2}, Lna/t;-><init>(ILay0/a;)V

    .line 22
    iput-object v0, p0, Lna/f;->d:Lna/t;

    .line 23
    new-instance p3, Lna/t;

    new-instance v0, Lna/c;

    const/4 v1, 0x1

    invoke-direct {v0, p1, p2, v1}, Lna/c;-><init>(Lb81/c;Ljava/lang/String;I)V

    invoke-direct {p3, v1, v0}, Lna/t;-><init>(ILay0/a;)V

    .line 24
    iput-object p3, p0, Lna/f;->e:Lna/t;

    return-void

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Maximum number of readers must be greater than 0"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public final close()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    iget-object v2, p0, Lna/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lna/f;->d:Lna/t;

    .line 12
    .line 13
    invoke-virtual {v0}, Lna/t;->c()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lna/f;->e:Lna/t;

    .line 17
    .line 18
    invoke-virtual {p0}, Lna/t;->c()V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final u(ZLay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    instance-of v4, v3, Lna/d;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lna/d;

    .line 15
    .line 16
    iget v5, v4, Lna/d;->m:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lna/d;->m:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lna/d;

    .line 29
    .line 30
    invoke-direct {v4, v0, v3}, Lna/d;-><init>(Lna/f;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lna/d;->k:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lna/d;->m:I

    .line 38
    .line 39
    const-string v7, "ROLLBACK TRANSACTION"

    .line 40
    .line 41
    const-string v8, "<this>"

    .line 42
    .line 43
    iget-object v10, v0, Lna/f;->g:Ljava/lang/ThreadLocal;

    .line 44
    .line 45
    iget-object v11, v0, Lna/f;->e:Lna/t;

    .line 46
    .line 47
    iget-object v12, v0, Lna/f;->d:Lna/t;

    .line 48
    .line 49
    const/4 v15, 0x2

    .line 50
    iget-object v9, v0, Lna/f;->f:Ldv/a;

    .line 51
    .line 52
    const/4 v13, 0x1

    .line 53
    if-eqz v6, :cond_5

    .line 54
    .line 55
    if-eq v6, v13, :cond_4

    .line 56
    .line 57
    if-eq v6, v15, :cond_3

    .line 58
    .line 59
    const/4 v0, 0x3

    .line 60
    if-eq v6, v0, :cond_2

    .line 61
    .line 62
    const/4 v0, 0x4

    .line 63
    if-ne v6, v0, :cond_1

    .line 64
    .line 65
    iget-object v0, v4, Lna/d;->f:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v1, v0

    .line 68
    check-cast v1, Lkotlin/jvm/internal/f0;

    .line 69
    .line 70
    iget-object v0, v4, Lna/d;->e:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v2, v0

    .line 73
    check-cast v2, Lna/t;

    .line 74
    .line 75
    :try_start_0
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    .line 77
    .line 78
    move-object/from16 v17, v7

    .line 79
    .line 80
    goto/16 :goto_8

    .line 81
    .line 82
    :catchall_0
    move-exception v0

    .line 83
    move-object v15, v1

    .line 84
    move-object v4, v7

    .line 85
    move-object v1, v0

    .line 86
    goto/16 :goto_b

    .line 87
    .line 88
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 91
    .line 92
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw v0

    .line 96
    :cond_2
    iget-boolean v0, v4, Lna/d;->d:Z

    .line 97
    .line 98
    iget-object v1, v4, Lna/d;->j:Ldv/a;

    .line 99
    .line 100
    iget-object v2, v4, Lna/d;->i:Lkotlin/jvm/internal/f0;

    .line 101
    .line 102
    iget-object v6, v4, Lna/d;->h:Lpx0/g;

    .line 103
    .line 104
    iget-object v15, v4, Lna/d;->g:Lkotlin/jvm/internal/f0;

    .line 105
    .line 106
    const/16 v16, 0x0

    .line 107
    .line 108
    iget-object v14, v4, Lna/d;->f:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v14, Lna/t;

    .line 111
    .line 112
    iget-object v13, v4, Lna/d;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v13, Lay0/n;

    .line 115
    .line 116
    :try_start_1
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 117
    .line 118
    .line 119
    move-object/from16 v17, v7

    .line 120
    .line 121
    move-object/from16 v18, v8

    .line 122
    .line 123
    goto/16 :goto_5

    .line 124
    .line 125
    :catchall_1
    move-exception v0

    .line 126
    move-object v1, v0

    .line 127
    move-object v4, v7

    .line 128
    :goto_1
    move-object v2, v14

    .line 129
    goto/16 :goto_b

    .line 130
    .line 131
    :cond_3
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    return-object v3

    .line 135
    :cond_4
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    return-object v3

    .line 139
    :cond_5
    const/16 v16, 0x0

    .line 140
    .line 141
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iget-object v3, v0, Lna/f;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 145
    .line 146
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    if-nez v3, :cond_17

    .line 151
    .line 152
    invoke-virtual {v10}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    check-cast v3, Lna/a0;

    .line 157
    .line 158
    if-nez v3, :cond_7

    .line 159
    .line 160
    invoke-interface {v4}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    invoke-interface {v3, v9}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    check-cast v3, Lna/a;

    .line 169
    .line 170
    if-eqz v3, :cond_6

    .line 171
    .line 172
    iget-object v3, v3, Lna/a;->e:Lna/a0;

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_6
    move-object/from16 v3, v16

    .line 176
    .line 177
    :cond_7
    :goto_2
    if-eqz v3, :cond_d

    .line 178
    .line 179
    if-nez v1, :cond_9

    .line 180
    .line 181
    iget-boolean v0, v3, Lna/a0;->c:Z

    .line 182
    .line 183
    if-nez v0, :cond_8

    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_8
    const-string v0, "Cannot upgrade connection from reader to writer"

    .line 187
    .line 188
    const/4 v1, 0x1

    .line 189
    invoke-static {v1, v0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw v16

    .line 193
    :cond_9
    :goto_3
    invoke-interface {v4}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    invoke-interface {v0, v9}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    if-nez v0, :cond_b

    .line 202
    .line 203
    new-instance v0, Lna/a;

    .line 204
    .line 205
    invoke-direct {v0, v9, v3}, Lna/a;-><init>(Lpx0/f;Lna/a0;)V

    .line 206
    .line 207
    .line 208
    invoke-static {v10, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    new-instance v1, Laz0/t;

    .line 212
    .line 213
    invoke-direct {v1, v3, v10}, Laz0/t;-><init>(Ljava/lang/Object;Ljava/lang/ThreadLocal;)V

    .line 214
    .line 215
    .line 216
    invoke-static {v0, v1}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    new-instance v1, Lm70/i0;

    .line 221
    .line 222
    const/16 v6, 0x1d

    .line 223
    .line 224
    move-object/from16 v7, v16

    .line 225
    .line 226
    invoke-direct {v1, v6, v2, v3, v7}, Lm70/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 227
    .line 228
    .line 229
    const/4 v2, 0x1

    .line 230
    iput v2, v4, Lna/d;->m:I

    .line 231
    .line 232
    invoke-static {v0, v1, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    if-ne v0, v5, :cond_a

    .line 237
    .line 238
    goto/16 :goto_7

    .line 239
    .line 240
    :cond_a
    return-object v0

    .line 241
    :cond_b
    iput v15, v4, Lna/d;->m:I

    .line 242
    .line 243
    invoke-interface {v2, v3, v4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    if-ne v0, v5, :cond_c

    .line 248
    .line 249
    goto/16 :goto_7

    .line 250
    .line 251
    :cond_c
    return-object v0

    .line 252
    :cond_d
    if-eqz v1, :cond_e

    .line 253
    .line 254
    move-object v3, v12

    .line 255
    goto :goto_4

    .line 256
    :cond_e
    move-object v3, v11

    .line 257
    :goto_4
    new-instance v6, Lkotlin/jvm/internal/f0;

    .line 258
    .line 259
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 260
    .line 261
    .line 262
    :try_start_2
    invoke-interface {v4}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 263
    .line 264
    .line 265
    move-result-object v13

    .line 266
    iget-wide v14, v0, Lna/f;->i:J
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 267
    .line 268
    move-object/from16 v17, v7

    .line 269
    .line 270
    :try_start_3
    new-instance v7, Lc/d;

    .line 271
    .line 272
    move-object/from16 v18, v8

    .line 273
    .line 274
    const/16 v8, 0x8

    .line 275
    .line 276
    invoke-direct {v7, v0, v1, v8}, Lc/d;-><init>(Ljava/lang/Object;ZI)V

    .line 277
    .line 278
    .line 279
    iput-object v2, v4, Lna/d;->e:Ljava/lang/Object;

    .line 280
    .line 281
    iput-object v3, v4, Lna/d;->f:Ljava/lang/Object;

    .line 282
    .line 283
    iput-object v6, v4, Lna/d;->g:Lkotlin/jvm/internal/f0;

    .line 284
    .line 285
    iput-object v13, v4, Lna/d;->h:Lpx0/g;

    .line 286
    .line 287
    iput-object v6, v4, Lna/d;->i:Lkotlin/jvm/internal/f0;

    .line 288
    .line 289
    iput-object v9, v4, Lna/d;->j:Ldv/a;

    .line 290
    .line 291
    iput-boolean v1, v4, Lna/d;->d:Z

    .line 292
    .line 293
    const/4 v0, 0x3

    .line 294
    iput v0, v4, Lna/d;->m:I

    .line 295
    .line 296
    invoke-virtual {v3, v14, v15, v7, v4}, Lna/t;->b(JLc/d;Lrx0/c;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_4

    .line 300
    if-ne v0, v5, :cond_f

    .line 301
    .line 302
    goto :goto_7

    .line 303
    :cond_f
    move-object v14, v3

    .line 304
    move-object v15, v6

    .line 305
    move-object v3, v0

    .line 306
    move v0, v1

    .line 307
    move-object v1, v9

    .line 308
    move-object v6, v13

    .line 309
    move-object v13, v2

    .line 310
    move-object v2, v15

    .line 311
    :goto_5
    :try_start_4
    check-cast v3, Lna/g;

    .line 312
    .line 313
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 314
    .line 315
    .line 316
    const-string v7, "context"

    .line 317
    .line 318
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    iput-object v6, v3, Lna/g;->f:Lpx0/g;

    .line 322
    .line 323
    new-instance v6, Ljava/lang/Throwable;

    .line 324
    .line 325
    invoke-direct {v6}, Ljava/lang/Throwable;-><init>()V

    .line 326
    .line 327
    .line 328
    iput-object v6, v3, Lna/g;->g:Ljava/lang/Throwable;

    .line 329
    .line 330
    if-eq v12, v11, :cond_10

    .line 331
    .line 332
    if-eqz v0, :cond_10

    .line 333
    .line 334
    const/4 v0, 0x1

    .line 335
    goto :goto_6

    .line 336
    :cond_10
    const/4 v0, 0x0

    .line 337
    :goto_6
    new-instance v6, Lna/a0;

    .line 338
    .line 339
    invoke-direct {v6, v1, v3, v0}, Lna/a0;-><init>(Ldv/a;Lna/g;Z)V

    .line 340
    .line 341
    .line 342
    iput-object v6, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 343
    .line 344
    iget-object v0, v15, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 345
    .line 346
    if-eqz v0, :cond_14

    .line 347
    .line 348
    check-cast v0, Lna/a0;

    .line 349
    .line 350
    new-instance v1, Lna/a;

    .line 351
    .line 352
    invoke-direct {v1, v9, v0}, Lna/a;-><init>(Lpx0/f;Lna/a0;)V

    .line 353
    .line 354
    .line 355
    move-object/from16 v2, v18

    .line 356
    .line 357
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    new-instance v2, Laz0/t;

    .line 361
    .line 362
    invoke-direct {v2, v0, v10}, Laz0/t;-><init>(Ljava/lang/Object;Ljava/lang/ThreadLocal;)V

    .line 363
    .line 364
    .line 365
    invoke-static {v1, v2}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    new-instance v1, Lna/e;

    .line 370
    .line 371
    const/4 v2, 0x0

    .line 372
    const/4 v7, 0x0

    .line 373
    invoke-direct {v1, v2, v13, v15, v7}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 374
    .line 375
    .line 376
    iput-object v14, v4, Lna/d;->e:Ljava/lang/Object;

    .line 377
    .line 378
    iput-object v15, v4, Lna/d;->f:Ljava/lang/Object;

    .line 379
    .line 380
    iput-object v7, v4, Lna/d;->g:Lkotlin/jvm/internal/f0;

    .line 381
    .line 382
    iput-object v7, v4, Lna/d;->h:Lpx0/g;

    .line 383
    .line 384
    iput-object v7, v4, Lna/d;->i:Lkotlin/jvm/internal/f0;

    .line 385
    .line 386
    iput-object v7, v4, Lna/d;->j:Ldv/a;

    .line 387
    .line 388
    const/4 v2, 0x4

    .line 389
    iput v2, v4, Lna/d;->m:I

    .line 390
    .line 391
    invoke-static {v0, v1, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 395
    if-ne v3, v5, :cond_11

    .line 396
    .line 397
    :goto_7
    return-object v5

    .line 398
    :cond_11
    move-object v2, v14

    .line 399
    move-object v1, v15

    .line 400
    :goto_8
    iget-object v0, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast v0, Lna/a0;

    .line 403
    .line 404
    if-eqz v0, :cond_13

    .line 405
    .line 406
    iget-object v1, v0, Lna/a0;->b:Lna/g;

    .line 407
    .line 408
    iget-object v0, v0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 409
    .line 410
    const/4 v4, 0x0

    .line 411
    const/4 v5, 0x1

    .line 412
    invoke-virtual {v0, v4, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 413
    .line 414
    .line 415
    move-result v0

    .line 416
    if-eqz v0, :cond_12

    .line 417
    .line 418
    iget-object v0, v1, Lna/g;->d:Lua/a;

    .line 419
    .line 420
    invoke-interface {v0}, Lua/a;->inTransaction()Z

    .line 421
    .line 422
    .line 423
    move-result v0

    .line 424
    if-eqz v0, :cond_12

    .line 425
    .line 426
    move-object/from16 v4, v17

    .line 427
    .line 428
    invoke-static {v1, v4}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    :cond_12
    const/4 v7, 0x0

    .line 432
    iput-object v7, v1, Lna/g;->f:Lpx0/g;

    .line 433
    .line 434
    iput-object v7, v1, Lna/g;->g:Ljava/lang/Throwable;

    .line 435
    .line 436
    invoke-virtual {v2, v1}, Lna/t;->e(Lna/g;)V

    .line 437
    .line 438
    .line 439
    :cond_13
    return-object v3

    .line 440
    :catchall_2
    move-exception v0

    .line 441
    move-object/from16 v4, v17

    .line 442
    .line 443
    :goto_9
    move-object v1, v0

    .line 444
    goto/16 :goto_1

    .line 445
    .line 446
    :cond_14
    move-object/from16 v4, v17

    .line 447
    .line 448
    :try_start_5
    const-string v0, "Required value was null."

    .line 449
    .line 450
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 451
    .line 452
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    throw v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 456
    :catchall_3
    move-exception v0

    .line 457
    goto :goto_9

    .line 458
    :catchall_4
    move-exception v0

    .line 459
    move-object/from16 v4, v17

    .line 460
    .line 461
    :goto_a
    move-object v1, v0

    .line 462
    move-object v2, v3

    .line 463
    move-object v15, v6

    .line 464
    goto :goto_b

    .line 465
    :catchall_5
    move-exception v0

    .line 466
    move-object v4, v7

    .line 467
    goto :goto_a

    .line 468
    :goto_b
    :try_start_6
    throw v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 469
    :catchall_6
    move-exception v0

    .line 470
    move-object v3, v0

    .line 471
    :try_start_7
    iget-object v0, v15, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast v0, Lna/a0;

    .line 474
    .line 475
    if-eqz v0, :cond_16

    .line 476
    .line 477
    iget-object v5, v0, Lna/a0;->b:Lna/g;

    .line 478
    .line 479
    iget-object v6, v0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 480
    .line 481
    const/4 v7, 0x0

    .line 482
    const/4 v8, 0x1

    .line 483
    invoke-virtual {v6, v7, v8}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 484
    .line 485
    .line 486
    move-result v6

    .line 487
    if-eqz v6, :cond_15

    .line 488
    .line 489
    iget-object v6, v5, Lna/g;->d:Lua/a;

    .line 490
    .line 491
    invoke-interface {v6}, Lua/a;->inTransaction()Z

    .line 492
    .line 493
    .line 494
    move-result v6

    .line 495
    if-eqz v6, :cond_15

    .line 496
    .line 497
    invoke-static {v5, v4}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    :cond_15
    iget-object v0, v0, Lna/a0;->b:Lna/g;

    .line 501
    .line 502
    const/4 v7, 0x0

    .line 503
    iput-object v7, v0, Lna/g;->f:Lpx0/g;

    .line 504
    .line 505
    iput-object v7, v0, Lna/g;->g:Ljava/lang/Throwable;

    .line 506
    .line 507
    invoke-virtual {v2, v0}, Lna/t;->e(Lna/g;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 508
    .line 509
    .line 510
    goto :goto_c

    .line 511
    :catchall_7
    move-exception v0

    .line 512
    invoke-static {v1, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 513
    .line 514
    .line 515
    :cond_16
    :goto_c
    throw v3

    .line 516
    :cond_17
    const/16 v0, 0x15

    .line 517
    .line 518
    const-string v1, "Connection pool is closed"

    .line 519
    .line 520
    invoke-static {v0, v1}, Llp/k1;->e(ILjava/lang/String;)V

    .line 521
    .line 522
    .line 523
    const/16 v16, 0x0

    .line 524
    .line 525
    throw v16
.end method
