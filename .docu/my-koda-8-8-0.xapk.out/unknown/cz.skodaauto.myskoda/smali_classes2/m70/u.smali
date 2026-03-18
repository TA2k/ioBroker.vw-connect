.class public final Lm70/u;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lk70/h0;

.field public final i:Lcs0/l;

.field public final j:Lk70/c0;

.field public final k:Lk70/g1;

.field public final l:Ltr0/b;

.field public final m:Lk70/a;

.field public final n:Lal0/m1;

.field public final o:Lk70/u0;

.field public final p:Lij0/a;


# direct methods
.method public constructor <init>(Lk70/h0;Lcs0/l;Lk70/c0;Lk70/g1;Ltr0/b;Lk70/a;Lal0/m1;Lk70/u0;Lij0/a;)V
    .locals 6

    .line 1
    new-instance v0, Lm70/s;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    sget-object v4, Lxj0/j;->d:Lxj0/j;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Lm70/s;-><init>(Lm70/p;ZZLxj0/j;Lm70/r;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lm70/u;->h:Lk70/h0;

    .line 16
    .line 17
    iput-object p2, p0, Lm70/u;->i:Lcs0/l;

    .line 18
    .line 19
    iput-object p3, p0, Lm70/u;->j:Lk70/c0;

    .line 20
    .line 21
    iput-object p4, p0, Lm70/u;->k:Lk70/g1;

    .line 22
    .line 23
    iput-object p5, p0, Lm70/u;->l:Ltr0/b;

    .line 24
    .line 25
    iput-object p6, p0, Lm70/u;->m:Lk70/a;

    .line 26
    .line 27
    iput-object p7, p0, Lm70/u;->n:Lal0/m1;

    .line 28
    .line 29
    iput-object p8, p0, Lm70/u;->o:Lk70/u0;

    .line 30
    .line 31
    iput-object p9, p0, Lm70/u;->p:Lij0/a;

    .line 32
    .line 33
    new-instance p1, Lm70/o;

    .line 34
    .line 35
    const/4 p2, 0x0

    .line 36
    const/4 p3, 0x0

    .line 37
    invoke-direct {p1, p0, p3, p2}, Lm70/o;-><init>(Lm70/u;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 41
    .line 42
    .line 43
    new-instance p1, Lm70/o;

    .line 44
    .line 45
    const/4 p2, 0x1

    .line 46
    invoke-direct {p1, p0, p3, p2}, Lm70/o;-><init>(Lm70/u;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static final h(Lm70/u;Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    instance-of v3, v2, Lm70/t;

    .line 11
    .line 12
    if-eqz v3, :cond_0

    .line 13
    .line 14
    move-object v3, v2

    .line 15
    check-cast v3, Lm70/t;

    .line 16
    .line 17
    iget v4, v3, Lm70/t;->g:I

    .line 18
    .line 19
    const/high16 v5, -0x80000000

    .line 20
    .line 21
    and-int v6, v4, v5

    .line 22
    .line 23
    if-eqz v6, :cond_0

    .line 24
    .line 25
    sub-int/2addr v4, v5

    .line 26
    iput v4, v3, Lm70/t;->g:I

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance v3, Lm70/t;

    .line 30
    .line 31
    invoke-direct {v3, v0, v2}, Lm70/t;-><init>(Lm70/u;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget-object v2, v3, Lm70/t;->e:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v5, v3, Lm70/t;->g:I

    .line 39
    .line 40
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    const/4 v7, 0x1

    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    if-ne v5, v7, :cond_1

    .line 46
    .line 47
    iget-object v1, v3, Lm70/t;->d:Lne0/e;

    .line 48
    .line 49
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    instance-of v2, v1, Lne0/c;

    .line 65
    .line 66
    if-eqz v2, :cond_3

    .line 67
    .line 68
    invoke-virtual {v0}, Lm70/u;->j()V

    .line 69
    .line 70
    .line 71
    return-object v6

    .line 72
    :cond_3
    instance-of v2, v1, Lne0/e;

    .line 73
    .line 74
    if-eqz v2, :cond_2d

    .line 75
    .line 76
    iget-object v2, v0, Lm70/u;->i:Lcs0/l;

    .line 77
    .line 78
    move-object v5, v1

    .line 79
    check-cast v5, Lne0/e;

    .line 80
    .line 81
    iput-object v5, v3, Lm70/t;->d:Lne0/e;

    .line 82
    .line 83
    iput v7, v3, Lm70/t;->g:I

    .line 84
    .line 85
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v2, v3}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-ne v2, v4, :cond_4

    .line 93
    .line 94
    return-object v4

    .line 95
    :cond_4
    :goto_1
    check-cast v2, Lqr0/s;

    .line 96
    .line 97
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    move-object v8, v3

    .line 102
    check-cast v8, Lm70/s;

    .line 103
    .line 104
    check-cast v1, Lne0/e;

    .line 105
    .line 106
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v1, Ll70/i;

    .line 109
    .line 110
    iget-object v3, v0, Lm70/u;->p:Lij0/a;

    .line 111
    .line 112
    const-string v4, "<this>"

    .line 113
    .line 114
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string v4, "trip"

    .line 118
    .line 119
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object v4, v1, Ll70/i;->v:Ll70/o;

    .line 123
    .line 124
    const-string v5, "unitsType"

    .line 125
    .line 126
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string v5, "stringResource"

    .line 130
    .line 131
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    new-instance v5, Lh50/q0;

    .line 135
    .line 136
    const/16 v9, 0x1d

    .line 137
    .line 138
    invoke-direct {v5, v3, v9}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 139
    .line 140
    .line 141
    invoke-static {v5}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    new-instance v9, Lm70/p;

    .line 146
    .line 147
    iget-object v10, v1, Ll70/i;->b:Ljava/time/LocalDate;

    .line 148
    .line 149
    invoke-static {v10}, Lu7/b;->d(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v10

    .line 153
    sget-object v11, Lm70/s0;->a:Ljava/time/format/DateTimeFormatter;

    .line 154
    .line 155
    iget-object v11, v1, Ll70/i;->c:Ljava/lang/String;

    .line 156
    .line 157
    const/4 v12, 0x0

    .line 158
    const v13, 0x7f121468

    .line 159
    .line 160
    .line 161
    if-nez v11, :cond_5

    .line 162
    .line 163
    new-array v11, v12, [Ljava/lang/Object;

    .line 164
    .line 165
    move-object v14, v3

    .line 166
    check-cast v14, Ljj0/f;

    .line 167
    .line 168
    invoke-virtual {v14, v13, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v11

    .line 172
    :cond_5
    iget-object v14, v1, Ll70/i;->d:Ljava/lang/String;

    .line 173
    .line 174
    if-nez v14, :cond_6

    .line 175
    .line 176
    new-array v14, v12, [Ljava/lang/Object;

    .line 177
    .line 178
    move-object v15, v3

    .line 179
    check-cast v15, Ljj0/f;

    .line 180
    .line 181
    invoke-virtual {v15, v13, v14}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v14

    .line 185
    :cond_6
    const-string v15, " - "

    .line 186
    .line 187
    invoke-static {v11, v15, v14}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v11

    .line 191
    iget-wide v14, v1, Ll70/i;->j:J

    .line 192
    .line 193
    const/4 v13, 0x6

    .line 194
    invoke-static {v14, v15, v3, v12, v13}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v14

    .line 198
    move-object/from16 v21, v8

    .line 199
    .line 200
    iget-wide v7, v1, Ll70/i;->i:D

    .line 201
    .line 202
    sget-object v15, Lqr0/e;->e:Lqr0/e;

    .line 203
    .line 204
    invoke-static {v7, v8, v2, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v7

    .line 208
    const-string v8, " ("

    .line 209
    .line 210
    const-string v13, ")"

    .line 211
    .line 212
    invoke-static {v14, v8, v7, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    invoke-virtual {v5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v8

    .line 220
    check-cast v8, Ljava/lang/String;

    .line 221
    .line 222
    iget-object v13, v1, Ll70/i;->o:Lqr0/h;

    .line 223
    .line 224
    const/16 v17, 0x0

    .line 225
    .line 226
    const-string v14, "~ "

    .line 227
    .line 228
    if-eqz v13, :cond_8

    .line 229
    .line 230
    iget v13, v13, Lqr0/h;->a:I

    .line 231
    .line 232
    invoke-static {v13}, Lkp/h6;->a(I)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v13

    .line 236
    invoke-static {v14, v13}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v13

    .line 240
    instance-of v12, v4, Ll70/n;

    .line 241
    .line 242
    if-nez v12, :cond_7

    .line 243
    .line 244
    goto :goto_2

    .line 245
    :cond_7
    move-object/from16 v13, v17

    .line 246
    .line 247
    :goto_2
    if-nez v13, :cond_9

    .line 248
    .line 249
    :cond_8
    move-object v13, v8

    .line 250
    :cond_9
    invoke-virtual {v5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v8

    .line 254
    check-cast v8, Ljava/lang/String;

    .line 255
    .line 256
    iget-object v12, v1, Ll70/i;->p:Lqr0/g;

    .line 257
    .line 258
    move-object/from16 v19, v5

    .line 259
    .line 260
    move-object/from16 v22, v6

    .line 261
    .line 262
    if-eqz v12, :cond_c

    .line 263
    .line 264
    iget-wide v5, v12, Lqr0/g;->a:D

    .line 265
    .line 266
    invoke-static {v5, v6, v2}, Lkp/g6;->b(DLqr0/s;)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v5

    .line 270
    invoke-static {v14, v5}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    instance-of v6, v4, Ll70/n;

    .line 275
    .line 276
    if-nez v6, :cond_a

    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_a
    move-object/from16 v5, v17

    .line 280
    .line 281
    :goto_3
    if-nez v5, :cond_b

    .line 282
    .line 283
    goto :goto_4

    .line 284
    :cond_b
    move-object v8, v5

    .line 285
    :cond_c
    :goto_4
    invoke-virtual/range {v19 .. v19}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v5

    .line 289
    check-cast v5, Ljava/lang/String;

    .line 290
    .line 291
    iget-object v6, v1, Ll70/i;->m:Lqr0/p;

    .line 292
    .line 293
    move-object v12, v5

    .line 294
    if-eqz v6, :cond_e

    .line 295
    .line 296
    iget-wide v5, v6, Lqr0/p;->a:D

    .line 297
    .line 298
    invoke-static {v5, v6, v2}, Lkp/o6;->a(DLqr0/s;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v5

    .line 302
    invoke-static {v14, v5}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v5

    .line 306
    instance-of v6, v4, Ll70/n;

    .line 307
    .line 308
    if-nez v6, :cond_d

    .line 309
    .line 310
    goto :goto_5

    .line 311
    :cond_d
    move-object/from16 v5, v17

    .line 312
    .line 313
    :goto_5
    if-nez v5, :cond_f

    .line 314
    .line 315
    :cond_e
    move-object v5, v12

    .line 316
    :cond_f
    instance-of v6, v4, Ll70/n;

    .line 317
    .line 318
    if-eqz v6, :cond_10

    .line 319
    .line 320
    const v12, 0x7f121453

    .line 321
    .line 322
    .line 323
    :goto_6
    move-object/from16 v20, v4

    .line 324
    .line 325
    const/4 v14, 0x0

    .line 326
    goto :goto_7

    .line 327
    :cond_10
    const v12, 0x7f121451

    .line 328
    .line 329
    .line 330
    goto :goto_6

    .line 331
    :goto_7
    new-array v4, v14, [Ljava/lang/Object;

    .line 332
    .line 333
    move-object v14, v3

    .line 334
    check-cast v14, Ljj0/f;

    .line 335
    .line 336
    invoke-virtual {v14, v12, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    if-eqz v6, :cond_14

    .line 341
    .line 342
    move-object/from16 v6, v20

    .line 343
    .line 344
    check-cast v6, Ll70/n;

    .line 345
    .line 346
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 347
    .line 348
    .line 349
    move-result v12

    .line 350
    if-eqz v12, :cond_13

    .line 351
    .line 352
    move-object/from16 v20, v4

    .line 353
    .line 354
    const/4 v4, 0x1

    .line 355
    if-eq v12, v4, :cond_11

    .line 356
    .line 357
    const/4 v4, 0x2

    .line 358
    if-ne v12, v4, :cond_12

    .line 359
    .line 360
    :cond_11
    move-object v12, v5

    .line 361
    goto :goto_8

    .line 362
    :cond_12
    new-instance v0, La8/r0;

    .line 363
    .line 364
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 365
    .line 366
    .line 367
    throw v0

    .line 368
    :goto_8
    iget-wide v4, v6, Ll70/n;->b:D

    .line 369
    .line 370
    invoke-static {v4, v5, v2, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 371
    .line 372
    .line 373
    move-result-object v4

    .line 374
    goto :goto_9

    .line 375
    :cond_13
    move-object/from16 v20, v4

    .line 376
    .line 377
    move-object v12, v5

    .line 378
    iget-wide v4, v6, Ll70/n;->a:D

    .line 379
    .line 380
    invoke-static {v4, v5, v2, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v4

    .line 384
    :goto_9
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v4

    .line 388
    const v5, 0x7f121452

    .line 389
    .line 390
    .line 391
    invoke-virtual {v14, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 392
    .line 393
    .line 394
    move-result-object v4

    .line 395
    goto :goto_a

    .line 396
    :cond_14
    move-object/from16 v20, v4

    .line 397
    .line 398
    move-object v12, v5

    .line 399
    const v4, 0x7f121450

    .line 400
    .line 401
    .line 402
    const/4 v5, 0x0

    .line 403
    new-array v6, v5, [Ljava/lang/Object;

    .line 404
    .line 405
    invoke-virtual {v14, v4, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 406
    .line 407
    .line 408
    move-result-object v4

    .line 409
    :goto_a
    invoke-virtual/range {v19 .. v19}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 410
    .line 411
    .line 412
    move-result-object v5

    .line 413
    check-cast v5, Ljava/lang/String;

    .line 414
    .line 415
    iget-object v6, v1, Ll70/i;->k:Lqr0/l;

    .line 416
    .line 417
    if-eqz v6, :cond_15

    .line 418
    .line 419
    invoke-static {v6}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v6

    .line 423
    :goto_b
    move-object/from16 v23, v4

    .line 424
    .line 425
    goto :goto_c

    .line 426
    :cond_15
    move-object v6, v5

    .line 427
    goto :goto_b

    .line 428
    :goto_c
    iget-object v4, v1, Ll70/i;->l:Lqr0/l;

    .line 429
    .line 430
    if-eqz v4, :cond_16

    .line 431
    .line 432
    invoke-static {v4}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 433
    .line 434
    .line 435
    move-result-object v5

    .line 436
    :cond_16
    new-instance v4, Llx0/l;

    .line 437
    .line 438
    invoke-direct {v4, v6, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 439
    .line 440
    .line 441
    invoke-virtual/range {v19 .. v19}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v5

    .line 445
    check-cast v5, Ljava/lang/String;

    .line 446
    .line 447
    iget-object v6, v1, Ll70/i;->g:Lqr0/d;

    .line 448
    .line 449
    move-object/from16 v19, v4

    .line 450
    .line 451
    move-object/from16 v24, v5

    .line 452
    .line 453
    if-eqz v6, :cond_17

    .line 454
    .line 455
    iget-wide v4, v6, Lqr0/d;->a:D

    .line 456
    .line 457
    invoke-static {v4, v5, v2, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 458
    .line 459
    .line 460
    move-result-object v4

    .line 461
    if-nez v4, :cond_18

    .line 462
    .line 463
    :cond_17
    move-object/from16 v4, v24

    .line 464
    .line 465
    :cond_18
    iget-object v5, v1, Ll70/i;->h:Lqr0/d;

    .line 466
    .line 467
    if-eqz v5, :cond_19

    .line 468
    .line 469
    iget-wide v5, v5, Lqr0/d;->a:D

    .line 470
    .line 471
    invoke-static {v5, v6, v2, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 472
    .line 473
    .line 474
    move-result-object v5

    .line 475
    if-nez v5, :cond_1a

    .line 476
    .line 477
    :cond_19
    move-object/from16 v5, v24

    .line 478
    .line 479
    :cond_1a
    new-instance v6, Llx0/l;

    .line 480
    .line 481
    invoke-direct {v6, v4, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 482
    .line 483
    .line 484
    iget-object v1, v1, Ll70/i;->u:Ljava/util/List;

    .line 485
    .line 486
    if-eqz v1, :cond_2c

    .line 487
    .line 488
    check-cast v1, Ljava/lang/Iterable;

    .line 489
    .line 490
    new-instance v4, Ljava/util/ArrayList;

    .line 491
    .line 492
    const/16 v5, 0xa

    .line 493
    .line 494
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 495
    .line 496
    .line 497
    move-result v5

    .line 498
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 499
    .line 500
    .line 501
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    const/4 v5, 0x0

    .line 506
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 507
    .line 508
    .line 509
    move-result v15

    .line 510
    if-eqz v15, :cond_2b

    .line 511
    .line 512
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v15

    .line 516
    add-int/lit8 v24, v5, 0x1

    .line 517
    .line 518
    if-ltz v5, :cond_2a

    .line 519
    .line 520
    check-cast v15, Ll70/l;

    .line 521
    .line 522
    move-object/from16 v25, v1

    .line 523
    .line 524
    const/16 v1, 0x19

    .line 525
    .line 526
    if-gt v5, v1, :cond_1b

    .line 527
    .line 528
    add-int/lit8 v5, v5, 0x41

    .line 529
    .line 530
    int-to-char v1, v5

    .line 531
    move/from16 v27, v1

    .line 532
    .line 533
    const/4 v5, 0x0

    .line 534
    goto :goto_f

    .line 535
    :cond_1b
    const/16 v1, 0x22

    .line 536
    .line 537
    if-gt v5, v1, :cond_1c

    .line 538
    .line 539
    add-int/lit8 v5, v5, -0x19

    .line 540
    .line 541
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 542
    .line 543
    .line 544
    move-result-object v1

    .line 545
    const/4 v5, 0x0

    .line 546
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 547
    .line 548
    .line 549
    move-result v1

    .line 550
    :goto_e
    move/from16 v27, v1

    .line 551
    .line 552
    goto :goto_f

    .line 553
    :cond_1c
    const/4 v5, 0x0

    .line 554
    const/16 v1, 0x2e

    .line 555
    .line 556
    goto :goto_e

    .line 557
    :goto_f
    iget-object v1, v15, Ll70/l;->a:Lxj0/f;

    .line 558
    .line 559
    iget-object v5, v15, Ll70/l;->h:Lqr0/l;

    .line 560
    .line 561
    move-object/from16 v29, v1

    .line 562
    .line 563
    iget-object v1, v15, Ll70/l;->g:Lqr0/l;

    .line 564
    .line 565
    move-object/from16 v26, v5

    .line 566
    .line 567
    iget-object v5, v15, Ll70/l;->b:Ljava/lang/String;

    .line 568
    .line 569
    if-nez v5, :cond_1d

    .line 570
    .line 571
    move-object/from16 v36, v6

    .line 572
    .line 573
    const/4 v5, 0x0

    .line 574
    new-array v6, v5, [Ljava/lang/Object;

    .line 575
    .line 576
    const v5, 0x7f121468

    .line 577
    .line 578
    .line 579
    invoke-virtual {v14, v5, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 580
    .line 581
    .line 582
    move-result-object v6

    .line 583
    move-object/from16 v28, v6

    .line 584
    .line 585
    goto :goto_10

    .line 586
    :cond_1d
    move-object/from16 v28, v5

    .line 587
    .line 588
    move-object/from16 v36, v6

    .line 589
    .line 590
    const v5, 0x7f121468

    .line 591
    .line 592
    .line 593
    :goto_10
    iget-object v6, v15, Ll70/l;->c:Ljava/lang/String;

    .line 594
    .line 595
    iget-boolean v5, v15, Ll70/l;->d:Z

    .line 596
    .line 597
    move/from16 v31, v5

    .line 598
    .line 599
    iget-object v5, v15, Ll70/l;->i:Lqr0/d;

    .line 600
    .line 601
    move-object/from16 v30, v6

    .line 602
    .line 603
    if-eqz v5, :cond_1e

    .line 604
    .line 605
    iget-wide v5, v5, Lqr0/d;->a:D

    .line 606
    .line 607
    move-object/from16 v37, v7

    .line 608
    .line 609
    sget-object v7, Lqr0/e;->e:Lqr0/e;

    .line 610
    .line 611
    invoke-static {v5, v6, v2, v7}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 612
    .line 613
    .line 614
    move-result-object v5

    .line 615
    goto :goto_11

    .line 616
    :cond_1e
    move-object/from16 v37, v7

    .line 617
    .line 618
    move-object/from16 v5, v17

    .line 619
    .line 620
    :goto_11
    iget-object v6, v15, Ll70/l;->j:Lmy0/c;

    .line 621
    .line 622
    if-eqz v6, :cond_1f

    .line 623
    .line 624
    iget-wide v6, v6, Lmy0/c;->d:J

    .line 625
    .line 626
    move-object/from16 v38, v2

    .line 627
    .line 628
    move-object/from16 v16, v8

    .line 629
    .line 630
    const/4 v2, 0x0

    .line 631
    const/4 v8, 0x6

    .line 632
    invoke-static {v6, v7, v3, v2, v8}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 633
    .line 634
    .line 635
    move-result-object v6

    .line 636
    goto :goto_12

    .line 637
    :cond_1f
    move-object/from16 v38, v2

    .line 638
    .line 639
    move-object/from16 v16, v8

    .line 640
    .line 641
    const/4 v2, 0x0

    .line 642
    const/4 v8, 0x6

    .line 643
    move-object/from16 v6, v17

    .line 644
    .line 645
    :goto_12
    filled-new-array {v5, v6}, [Ljava/lang/String;

    .line 646
    .line 647
    .line 648
    move-result-object v5

    .line 649
    invoke-static {v5}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 650
    .line 651
    .line 652
    move-result-object v5

    .line 653
    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    .line 654
    .line 655
    .line 656
    move-result v6

    .line 657
    if-nez v6, :cond_20

    .line 658
    .line 659
    move-object/from16 v39, v5

    .line 660
    .line 661
    goto :goto_13

    .line 662
    :cond_20
    move-object/from16 v39, v17

    .line 663
    .line 664
    :goto_13
    if-eqz v39, :cond_21

    .line 665
    .line 666
    const/16 v43, 0x0

    .line 667
    .line 668
    const/16 v44, 0x3e

    .line 669
    .line 670
    const-string v40, " \u2014 "

    .line 671
    .line 672
    const/16 v41, 0x0

    .line 673
    .line 674
    const/16 v42, 0x0

    .line 675
    .line 676
    invoke-static/range {v39 .. v44}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 677
    .line 678
    .line 679
    move-result-object v5

    .line 680
    move-object/from16 v34, v5

    .line 681
    .line 682
    goto :goto_14

    .line 683
    :cond_21
    move-object/from16 v34, v17

    .line 684
    .line 685
    :goto_14
    iget-object v5, v15, Ll70/l;->e:Ljava/time/OffsetDateTime;

    .line 686
    .line 687
    if-eqz v5, :cond_22

    .line 688
    .line 689
    invoke-static {v5}, Lvo/a;->k(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 690
    .line 691
    .line 692
    move-result-object v5

    .line 693
    move-object/from16 v32, v5

    .line 694
    .line 695
    goto :goto_15

    .line 696
    :cond_22
    move-object/from16 v32, v17

    .line 697
    .line 698
    :goto_15
    iget-object v5, v15, Ll70/l;->f:Ljava/time/OffsetDateTime;

    .line 699
    .line 700
    if-eqz v5, :cond_23

    .line 701
    .line 702
    invoke-static {v5}, Lvo/a;->k(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 703
    .line 704
    .line 705
    move-result-object v5

    .line 706
    move-object/from16 v33, v5

    .line 707
    .line 708
    goto :goto_16

    .line 709
    :cond_23
    move-object/from16 v33, v17

    .line 710
    .line 711
    :goto_16
    if-eqz v1, :cond_24

    .line 712
    .line 713
    iget v5, v1, Lqr0/l;->d:I

    .line 714
    .line 715
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 716
    .line 717
    .line 718
    move-result-object v5

    .line 719
    goto :goto_17

    .line 720
    :cond_24
    move-object/from16 v5, v17

    .line 721
    .line 722
    :goto_17
    if-eqz v1, :cond_25

    .line 723
    .line 724
    invoke-static {v1}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 725
    .line 726
    .line 727
    move-result-object v6

    .line 728
    goto :goto_18

    .line 729
    :cond_25
    invoke-static {v3}, Lkp/l6;->c(Lij0/a;)Ljava/lang/String;

    .line 730
    .line 731
    .line 732
    move-result-object v6

    .line 733
    :goto_18
    if-eqz v26, :cond_26

    .line 734
    .line 735
    invoke-static/range {v26 .. v26}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 736
    .line 737
    .line 738
    move-result-object v7

    .line 739
    goto :goto_19

    .line 740
    :cond_26
    invoke-static {v3}, Lkp/l6;->c(Lij0/a;)Ljava/lang/String;

    .line 741
    .line 742
    .line 743
    move-result-object v7

    .line 744
    :goto_19
    iget-boolean v15, v15, Ll70/l;->d:Z

    .line 745
    .line 746
    if-eqz v15, :cond_27

    .line 747
    .line 748
    goto :goto_1a

    .line 749
    :cond_27
    move-object/from16 v7, v17

    .line 750
    .line 751
    :goto_1a
    if-nez v1, :cond_29

    .line 752
    .line 753
    if-eqz v26, :cond_28

    .line 754
    .line 755
    if-eqz v15, :cond_28

    .line 756
    .line 757
    goto :goto_1b

    .line 758
    :cond_28
    move v1, v2

    .line 759
    goto :goto_1c

    .line 760
    :cond_29
    :goto_1b
    const/4 v1, 0x1

    .line 761
    :goto_1c
    new-instance v15, Lm70/q;

    .line 762
    .line 763
    invoke-direct {v15, v5, v6, v7, v1}, Lm70/q;-><init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 764
    .line 765
    .line 766
    new-instance v26, Lm70/r;

    .line 767
    .line 768
    move-object/from16 v35, v15

    .line 769
    .line 770
    invoke-direct/range {v26 .. v35}, Lm70/r;-><init>(CLjava/lang/String;Lxj0/f;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lm70/q;)V

    .line 771
    .line 772
    .line 773
    move-object/from16 v1, v26

    .line 774
    .line 775
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 776
    .line 777
    .line 778
    move-object/from16 v8, v16

    .line 779
    .line 780
    move/from16 v5, v24

    .line 781
    .line 782
    move-object/from16 v1, v25

    .line 783
    .line 784
    move-object/from16 v6, v36

    .line 785
    .line 786
    move-object/from16 v7, v37

    .line 787
    .line 788
    move-object/from16 v2, v38

    .line 789
    .line 790
    goto/16 :goto_d

    .line 791
    .line 792
    :cond_2a
    invoke-static {}, Ljp/k1;->r()V

    .line 793
    .line 794
    .line 795
    throw v17

    .line 796
    :cond_2b
    move-object v14, v8

    .line 797
    move-object v15, v12

    .line 798
    move-object/from16 v18, v19

    .line 799
    .line 800
    move-object/from16 v19, v6

    .line 801
    .line 802
    move-object v12, v7

    .line 803
    :goto_1d
    move-object/from16 v16, v20

    .line 804
    .line 805
    move-object/from16 v17, v23

    .line 806
    .line 807
    move-object/from16 v20, v4

    .line 808
    .line 809
    goto :goto_1e

    .line 810
    :cond_2c
    move-object/from16 v36, v6

    .line 811
    .line 812
    move-object/from16 v37, v7

    .line 813
    .line 814
    move-object/from16 v16, v8

    .line 815
    .line 816
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 817
    .line 818
    move-object v15, v12

    .line 819
    move-object/from16 v14, v16

    .line 820
    .line 821
    move-object/from16 v18, v19

    .line 822
    .line 823
    move-object/from16 v19, v36

    .line 824
    .line 825
    move-object/from16 v12, v37

    .line 826
    .line 827
    goto :goto_1d

    .line 828
    :goto_1e
    invoke-direct/range {v9 .. v20}, Lm70/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llx0/l;Llx0/l;Ljava/util/List;)V

    .line 829
    .line 830
    .line 831
    const/4 v13, 0x0

    .line 832
    const/16 v14, 0x1e

    .line 833
    .line 834
    const/4 v10, 0x0

    .line 835
    const/4 v11, 0x0

    .line 836
    const/4 v12, 0x0

    .line 837
    move-object/from16 v8, v21

    .line 838
    .line 839
    invoke-static/range {v8 .. v14}, Lm70/s;->a(Lm70/s;Lm70/p;ZZLxj0/j;Lm70/r;I)Lm70/s;

    .line 840
    .line 841
    .line 842
    move-result-object v1

    .line 843
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 844
    .line 845
    .line 846
    return-object v22

    .line 847
    :cond_2d
    new-instance v0, La8/r0;

    .line 848
    .line 849
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 850
    .line 851
    .line 852
    throw v0
.end method


# virtual methods
.method public final j()V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lm70/s;

    .line 6
    .line 7
    iget-object v0, v0, Lm70/s;->e:Lm70/r;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    move-object v1, v0

    .line 16
    check-cast v1, Lm70/s;

    .line 17
    .line 18
    const/4 v5, 0x0

    .line 19
    const/16 v7, 0xf

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v6, 0x0

    .line 25
    invoke-static/range {v1 .. v7}, Lm70/s;->a(Lm70/s;Lm70/p;ZZLxj0/j;Lm70/r;I)Lm70/s;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    iget-object v0, p0, Lm70/u;->m:Lk70/a;

    .line 34
    .line 35
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lm70/u;->l:Ltr0/b;

    .line 39
    .line 40
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    return-void
.end method
