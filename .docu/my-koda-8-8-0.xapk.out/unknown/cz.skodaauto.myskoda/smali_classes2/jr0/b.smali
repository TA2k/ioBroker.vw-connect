.class public final Ljr0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljr0/c;

.field public e:Lkr0/b;

.field public f:Ljava/time/OffsetDateTime;

.field public g:I

.field public h:J

.field public i:I

.field public final synthetic j:Ljr0/c;

.field public final synthetic k:Lkr0/b;


# direct methods
.method public constructor <init>(Ljr0/c;Lkr0/b;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljr0/b;->j:Ljr0/c;

    .line 2
    .line 3
    iput-object p2, p0, Ljr0/b;->k:Lkr0/b;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance p1, Ljr0/b;

    .line 2
    .line 3
    iget-object v0, p0, Ljr0/b;->j:Ljr0/c;

    .line 4
    .line 5
    iget-object p0, p0, Ljr0/b;->k:Lkr0/b;

    .line 6
    .line 7
    invoke-direct {p1, v0, p0, p2}, Ljr0/b;-><init>(Ljr0/c;Lkr0/b;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljr0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljr0/b;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljr0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 46

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v0, v5, Ljr0/b;->i:I

    .line 6
    .line 7
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const-string v1, "useCase"

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v0, :cond_3

    .line 14
    .line 15
    if-eq v0, v3, :cond_1

    .line 16
    .line 17
    if-ne v0, v2, :cond_0

    .line 18
    .line 19
    iget-object v0, v5, Ljr0/b;->f:Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    check-cast v0, Lss0/k;

    .line 22
    .line 23
    iget-object v0, v5, Ljr0/b;->e:Lkr0/b;

    .line 24
    .line 25
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 26
    .line 27
    iget-object v0, v5, Ljr0/b;->d:Ljr0/c;

    .line 28
    .line 29
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 30
    .line 31
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-object v7

    .line 35
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :cond_1
    iget-wide v8, v5, Ljr0/b;->h:J

    .line 44
    .line 45
    iget v0, v5, Ljr0/b;->g:I

    .line 46
    .line 47
    iget-object v4, v5, Ljr0/b;->f:Ljava/time/OffsetDateTime;

    .line 48
    .line 49
    iget-object v10, v5, Ljr0/b;->e:Lkr0/b;

    .line 50
    .line 51
    iget-object v11, v5, Ljr0/b;->d:Ljr0/c;

    .line 52
    .line 53
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move v12, v0

    .line 57
    move-object/from16 v0, p1

    .line 58
    .line 59
    :cond_2
    move-object/from16 v23, v4

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object v11, v5, Ljr0/b;->j:Ljr0/c;

    .line 66
    .line 67
    iget-object v0, v11, Ljr0/c;->b:Ljr0/d;

    .line 68
    .line 69
    iget-object v10, v5, Ljr0/b;->k:Lkr0/b;

    .line 70
    .line 71
    iget-object v4, v10, Lkr0/b;->a:Lkr0/c;

    .line 72
    .line 73
    check-cast v0, Lhr0/a;

    .line 74
    .line 75
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, v0, Lhr0/a;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 79
    .line 80
    iget-object v4, v4, Lkr0/c;->a:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {v0, v4}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 87
    .line 88
    if-eqz v0, :cond_12

    .line 89
    .line 90
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    invoke-virtual {v4}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 95
    .line 96
    .line 97
    move-result-object v8

    .line 98
    invoke-virtual {v8}, Ljava/time/Instant;->toEpochMilli()J

    .line 99
    .line 100
    .line 101
    move-result-wide v8

    .line 102
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-virtual {v0}, Ljava/time/Instant;->toEpochMilli()J

    .line 107
    .line 108
    .line 109
    move-result-wide v12

    .line 110
    sub-long/2addr v8, v12

    .line 111
    iget-object v0, v11, Ljr0/c;->d:Lkf0/m;

    .line 112
    .line 113
    iput-object v11, v5, Ljr0/b;->d:Ljr0/c;

    .line 114
    .line 115
    iput-object v10, v5, Ljr0/b;->e:Lkr0/b;

    .line 116
    .line 117
    iput-object v4, v5, Ljr0/b;->f:Ljava/time/OffsetDateTime;

    .line 118
    .line 119
    const/4 v12, 0x0

    .line 120
    iput v12, v5, Ljr0/b;->g:I

    .line 121
    .line 122
    iput-wide v8, v5, Ljr0/b;->h:J

    .line 123
    .line 124
    iput v3, v5, Ljr0/b;->i:I

    .line 125
    .line 126
    invoke-virtual {v0, v5}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    if-ne v0, v6, :cond_2

    .line 131
    .line 132
    goto/16 :goto_d

    .line 133
    .line 134
    :goto_0
    instance-of v4, v0, Lne0/e;

    .line 135
    .line 136
    if-eqz v4, :cond_4

    .line 137
    .line 138
    check-cast v0, Lne0/e;

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_4
    const/4 v0, 0x0

    .line 142
    :goto_1
    if-eqz v0, :cond_5

    .line 143
    .line 144
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v0, Lss0/k;

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_5
    const/4 v0, 0x0

    .line 150
    :goto_2
    iget-object v4, v11, Ljr0/c;->c:Ljr0/a;

    .line 151
    .line 152
    check-cast v4, Llr0/a;

    .line 153
    .line 154
    iget-object v4, v4, Llr0/a;->a:Landroid/content/Context;

    .line 155
    .line 156
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    const-string v14, "getPackageName(...)"

    .line 161
    .line 162
    invoke-static {v4, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    const v14, 0xef93c9a

    .line 166
    .line 167
    .line 168
    invoke-static {v14}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v17

    .line 172
    if-eqz v0, :cond_9

    .line 173
    .line 174
    iget-object v0, v0, Lss0/k;->j:Lss0/n;

    .line 175
    .line 176
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    if-eqz v0, :cond_8

    .line 181
    .line 182
    if-eq v0, v3, :cond_7

    .line 183
    .line 184
    if-eq v0, v2, :cond_6

    .line 185
    .line 186
    const/4 v0, 0x0

    .line 187
    goto :goto_3

    .line 188
    :cond_6
    const-string v0, "MOD4"

    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_7
    const-string v0, "MOD3"

    .line 192
    .line 193
    goto :goto_3

    .line 194
    :cond_8
    const-string v0, "MOD1/2"

    .line 195
    .line 196
    :goto_3
    move-object/from16 v27, v0

    .line 197
    .line 198
    goto :goto_4

    .line 199
    :cond_9
    const/16 v27, 0x0

    .line 200
    .line 201
    :goto_4
    new-instance v0, Ljava/lang/Long;

    .line 202
    .line 203
    invoke-direct {v0, v8, v9}, Ljava/lang/Long;-><init>(J)V

    .line 204
    .line 205
    .line 206
    iget-object v14, v10, Lkr0/b;->a:Lkr0/c;

    .line 207
    .line 208
    iget-object v15, v10, Lkr0/b;->b:Ljava/lang/String;

    .line 209
    .line 210
    iget-object v13, v10, Lkr0/b;->c:Lkr0/a;

    .line 211
    .line 212
    iget-object v3, v10, Lkr0/b;->h:Ljava/lang/String;

    .line 213
    .line 214
    iget-object v2, v10, Lkr0/b;->i:Ljava/lang/String;

    .line 215
    .line 216
    move-object/from16 v24, v0

    .line 217
    .line 218
    iget-object v0, v10, Lkr0/b;->l:Ljava/lang/String;

    .line 219
    .line 220
    move-object/from16 v25, v0

    .line 221
    .line 222
    iget-object v0, v10, Lkr0/b;->m:Ljava/lang/Boolean;

    .line 223
    .line 224
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    move-object/from16 v26, v0

    .line 228
    .line 229
    const-string v0, "message"

    .line 230
    .line 231
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    const-string v0, "status"

    .line 235
    .line 236
    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    move-object/from16 v16, v13

    .line 240
    .line 241
    new-instance v13, Lkr0/b;

    .line 242
    .line 243
    const-string v18, "release"

    .line 244
    .line 245
    const-string v20, "8.8.0"

    .line 246
    .line 247
    move-object/from16 v22, v2

    .line 248
    .line 249
    move-object/from16 v21, v3

    .line 250
    .line 251
    move-object/from16 v19, v4

    .line 252
    .line 253
    const/4 v0, 0x0

    .line 254
    invoke-direct/range {v13 .. v27}, Lkr0/b;-><init>(Lkr0/c;Ljava/lang/String;Lkr0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    move-object/from16 v31, v13

    .line 258
    .line 259
    move-object/from16 v3, v17

    .line 260
    .line 261
    move-object/from16 v32, v18

    .line 262
    .line 263
    move-object/from16 v2, v19

    .line 264
    .line 265
    move-object/from16 v33, v20

    .line 266
    .line 267
    move-object/from16 v4, v21

    .line 268
    .line 269
    move-object/from16 v29, v22

    .line 270
    .line 271
    move-object/from16 v30, v25

    .line 272
    .line 273
    move-object/from16 v13, v27

    .line 274
    .line 275
    iget-object v0, v11, Ljr0/c;->b:Ljr0/d;

    .line 276
    .line 277
    iget-object v10, v10, Lkr0/b;->a:Lkr0/c;

    .line 278
    .line 279
    check-cast v0, Lhr0/a;

    .line 280
    .line 281
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    iget-object v0, v0, Lhr0/a;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 285
    .line 286
    iget-object v1, v10, Lkr0/c;->a:Ljava/lang/String;

    .line 287
    .line 288
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    iget-object v0, v11, Ljr0/c;->a:Ljr0/e;

    .line 292
    .line 293
    const/4 v1, 0x0

    .line 294
    iput-object v1, v5, Ljr0/b;->d:Ljr0/c;

    .line 295
    .line 296
    iput-object v1, v5, Ljr0/b;->e:Lkr0/b;

    .line 297
    .line 298
    iput-object v1, v5, Ljr0/b;->f:Ljava/time/OffsetDateTime;

    .line 299
    .line 300
    iput v12, v5, Ljr0/b;->g:I

    .line 301
    .line 302
    iput-wide v8, v5, Ljr0/b;->h:J

    .line 303
    .line 304
    const/4 v8, 0x2

    .line 305
    iput v8, v5, Ljr0/b;->i:I

    .line 306
    .line 307
    check-cast v0, Lhr0/c;

    .line 308
    .line 309
    new-instance v8, Lh50/q0;

    .line 310
    .line 311
    const/4 v9, 0x5

    .line 312
    move-object/from16 v10, v31

    .line 313
    .line 314
    invoke-direct {v8, v10, v9}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 315
    .line 316
    .line 317
    invoke-static {v1, v0, v8}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 318
    .line 319
    .line 320
    iget-object v0, v0, Lhr0/c;->a:Lz51/b;

    .line 321
    .line 322
    new-instance v8, Llx0/l;

    .line 323
    .line 324
    const-string v9, "app.build"

    .line 325
    .line 326
    invoke-direct {v8, v9, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    new-instance v3, Llx0/l;

    .line 330
    .line 331
    const-string v9, "app.buildType"

    .line 332
    .line 333
    move-object/from16 v11, v32

    .line 334
    .line 335
    invoke-direct {v3, v9, v11}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    new-instance v9, Llx0/l;

    .line 339
    .line 340
    const-string v11, "app.id"

    .line 341
    .line 342
    invoke-direct {v9, v11, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 343
    .line 344
    .line 345
    new-instance v2, Llx0/l;

    .line 346
    .line 347
    const-string v11, "app.version"

    .line 348
    .line 349
    move-object/from16 v12, v33

    .line 350
    .line 351
    invoke-direct {v2, v11, v12}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 352
    .line 353
    .line 354
    new-instance v11, Llx0/l;

    .line 355
    .line 356
    const-string v12, "errorCode"

    .line 357
    .line 358
    move-object/from16 v1, v29

    .line 359
    .line 360
    invoke-direct {v11, v12, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    if-eqz v23, :cond_a

    .line 364
    .line 365
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    if-eqz v1, :cond_a

    .line 370
    .line 371
    invoke-virtual {v1}, Ljava/time/Instant;->toEpochMilli()J

    .line 372
    .line 373
    .line 374
    move-result-wide v16

    .line 375
    invoke-static/range {v16 .. v17}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v1

    .line 379
    goto :goto_5

    .line 380
    :cond_a
    const/4 v1, 0x0

    .line 381
    :goto_5
    new-instance v12, Llx0/l;

    .line 382
    .line 383
    move-object/from16 v16, v0

    .line 384
    .line 385
    const-string v0, "occurrenceTimestamp"

    .line 386
    .line 387
    invoke-direct {v12, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual/range {v24 .. v24}, Ljava/lang/Long;->longValue()J

    .line 391
    .line 392
    .line 393
    move-result-wide v0

    .line 394
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    new-instance v1, Llx0/l;

    .line 399
    .line 400
    move-object/from16 v37, v2

    .line 401
    .line 402
    const-string v2, "duration"

    .line 403
    .line 404
    invoke-direct {v1, v2, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 405
    .line 406
    .line 407
    iget-object v0, v14, Lkr0/c;->a:Ljava/lang/String;

    .line 408
    .line 409
    new-instance v2, Llx0/l;

    .line 410
    .line 411
    const-string v14, "useCaseName"

    .line 412
    .line 413
    invoke-direct {v2, v14, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 414
    .line 415
    .line 416
    new-instance v0, Llx0/l;

    .line 417
    .line 418
    const-string v14, "useCaseResult"

    .line 419
    .line 420
    invoke-direct {v0, v14, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 421
    .line 422
    .line 423
    new-instance v4, Llx0/l;

    .line 424
    .line 425
    const-string v14, "traceId"

    .line 426
    .line 427
    move-object/from16 v42, v0

    .line 428
    .line 429
    move-object/from16 v0, v30

    .line 430
    .line 431
    invoke-direct {v4, v14, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    if-eqz v26, :cond_b

    .line 435
    .line 436
    invoke-virtual/range {v26 .. v26}, Ljava/lang/Boolean;->booleanValue()Z

    .line 437
    .line 438
    .line 439
    move-result v0

    .line 440
    invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    goto :goto_6

    .line 445
    :cond_b
    const/4 v0, 0x0

    .line 446
    :goto_6
    new-instance v14, Llx0/l;

    .line 447
    .line 448
    move-object/from16 v40, v1

    .line 449
    .line 450
    const-string v1, "visibleToUser"

    .line 451
    .line 452
    invoke-direct {v14, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    new-instance v0, Llx0/l;

    .line 456
    .line 457
    const-string v1, "mod"

    .line 458
    .line 459
    invoke-direct {v0, v1, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 460
    .line 461
    .line 462
    move-object/from16 v45, v0

    .line 463
    .line 464
    move-object/from16 v41, v2

    .line 465
    .line 466
    move-object/from16 v35, v3

    .line 467
    .line 468
    move-object/from16 v43, v4

    .line 469
    .line 470
    move-object/from16 v34, v8

    .line 471
    .line 472
    move-object/from16 v36, v9

    .line 473
    .line 474
    move-object/from16 v38, v11

    .line 475
    .line 476
    move-object/from16 v39, v12

    .line 477
    .line 478
    move-object/from16 v44, v14

    .line 479
    .line 480
    filled-new-array/range {v34 .. v45}, [Llx0/l;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    invoke-static {v0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    new-instance v1, Ljava/util/ArrayList;

    .line 489
    .line 490
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 491
    .line 492
    .line 493
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    :cond_c
    :goto_7
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 502
    .line 503
    .line 504
    move-result v2

    .line 505
    if-eqz v2, :cond_e

    .line 506
    .line 507
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v2

    .line 511
    check-cast v2, Ljava/util/Map$Entry;

    .line 512
    .line 513
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v3

    .line 517
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v2

    .line 521
    if-eqz v2, :cond_d

    .line 522
    .line 523
    new-instance v13, Llx0/l;

    .line 524
    .line 525
    invoke-direct {v13, v3, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 526
    .line 527
    .line 528
    goto :goto_8

    .line 529
    :cond_d
    const/4 v13, 0x0

    .line 530
    :goto_8
    if-eqz v13, :cond_c

    .line 531
    .line 532
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 533
    .line 534
    .line 535
    goto :goto_7

    .line 536
    :cond_e
    invoke-static {v1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 537
    .line 538
    .line 539
    move-result-object v2

    .line 540
    if-eqz v23, :cond_f

    .line 541
    .line 542
    new-instance v28, Lgz0/w;

    .line 543
    .line 544
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getYear()I

    .line 545
    .line 546
    .line 547
    move-result v29

    .line 548
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getMonth()Ljava/time/Month;

    .line 549
    .line 550
    .line 551
    move-result-object v0

    .line 552
    const-string v1, "getMonth(...)"

    .line 553
    .line 554
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    invoke-static {v0}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 558
    .line 559
    .line 560
    move-result-object v30

    .line 561
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getDayOfMonth()I

    .line 562
    .line 563
    .line 564
    move-result v31

    .line 565
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getHour()I

    .line 566
    .line 567
    .line 568
    move-result v32

    .line 569
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getMinute()I

    .line 570
    .line 571
    .line 572
    move-result v33

    .line 573
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getSecond()I

    .line 574
    .line 575
    .line 576
    move-result v34

    .line 577
    invoke-virtual/range {v23 .. v23}, Ljava/time/OffsetDateTime;->getNano()I

    .line 578
    .line 579
    .line 580
    move-result v35

    .line 581
    invoke-direct/range {v28 .. v35}, Lgz0/w;-><init>(ILgz0/z;IIIII)V

    .line 582
    .line 583
    .line 584
    move-object/from16 v4, v28

    .line 585
    .line 586
    goto :goto_9

    .line 587
    :cond_f
    const/4 v4, 0x0

    .line 588
    :goto_9
    sget-object v0, Lhr0/b;->a:[I

    .line 589
    .line 590
    iget-object v1, v10, Lkr0/b;->c:Lkr0/a;

    .line 591
    .line 592
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 593
    .line 594
    .line 595
    move-result v1

    .line 596
    aget v0, v0, v1

    .line 597
    .line 598
    const/4 v1, 0x1

    .line 599
    if-ne v0, v1, :cond_10

    .line 600
    .line 601
    sget-object v0, Lz51/c;->d:Lz51/c;

    .line 602
    .line 603
    :goto_a
    move-object v3, v0

    .line 604
    move-object v1, v15

    .line 605
    move-object/from16 v0, v16

    .line 606
    .line 607
    goto :goto_b

    .line 608
    :cond_10
    sget-object v0, Lz51/c;->e:Lz51/c;

    .line 609
    .line 610
    goto :goto_a

    .line 611
    :goto_b
    invoke-virtual/range {v0 .. v5}, Lz51/b;->a(Ljava/lang/String;Ljava/util/Map;Lz51/c;Lgz0/w;Lrx0/c;)Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v0

    .line 615
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 616
    .line 617
    if-ne v0, v1, :cond_11

    .line 618
    .line 619
    goto :goto_c

    .line 620
    :cond_11
    move-object v0, v7

    .line 621
    :goto_c
    if-ne v0, v6, :cond_12

    .line 622
    .line 623
    :goto_d
    return-object v6

    .line 624
    :cond_12
    return-object v7
.end method
