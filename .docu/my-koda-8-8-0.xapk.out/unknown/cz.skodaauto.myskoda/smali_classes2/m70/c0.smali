.class public final Lm70/c0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Lm70/d0;

.field public final synthetic f:Z

.field public final synthetic g:Ll70/w;

.field public final synthetic h:I

.field public final synthetic i:Lne0/s;

.field public final synthetic j:Ll70/q;

.field public final synthetic k:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Lm70/d0;ZLl70/w;ILne0/s;Ll70/q;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm70/c0;->e:Lm70/d0;

    .line 2
    .line 3
    iput-boolean p2, p0, Lm70/c0;->f:Z

    .line 4
    .line 5
    iput-object p3, p0, Lm70/c0;->g:Ll70/w;

    .line 6
    .line 7
    iput p4, p0, Lm70/c0;->h:I

    .line 8
    .line 9
    iput-object p5, p0, Lm70/c0;->i:Lne0/s;

    .line 10
    .line 11
    iput-object p6, p0, Lm70/c0;->j:Ll70/q;

    .line 12
    .line 13
    iput-object p7, p0, Lm70/c0;->k:Ljava/lang/Integer;

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1, p8}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    new-instance v0, Lm70/c0;

    .line 2
    .line 3
    iget-object v6, p0, Lm70/c0;->j:Ll70/q;

    .line 4
    .line 5
    iget-object v7, p0, Lm70/c0;->k:Ljava/lang/Integer;

    .line 6
    .line 7
    iget-object v1, p0, Lm70/c0;->e:Lm70/d0;

    .line 8
    .line 9
    iget-boolean v2, p0, Lm70/c0;->f:Z

    .line 10
    .line 11
    iget-object v3, p0, Lm70/c0;->g:Ll70/w;

    .line 12
    .line 13
    iget v4, p0, Lm70/c0;->h:I

    .line 14
    .line 15
    iget-object v5, p0, Lm70/c0;->i:Lne0/s;

    .line 16
    .line 17
    move-object v8, p2

    .line 18
    invoke-direct/range {v0 .. v8}, Lm70/c0;-><init>(Lm70/d0;ZLl70/w;ILne0/s;Ll70/q;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    return-object v0
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
    invoke-virtual {p0, p1, p2}, Lm70/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lm70/c0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lm70/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v2

    .line 8
    iget-object v3, v0, Lm70/c0;->e:Lm70/d0;

    .line 9
    .line 10
    iget-object v4, v3, Lm70/d0;->i:Lij0/a;

    .line 11
    .line 12
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v6, v0, Lm70/c0;->d:I

    .line 15
    .line 16
    const/4 v7, 0x1

    .line 17
    if-eqz v6, :cond_1

    .line 18
    .line 19
    if-ne v6, v7, :cond_0

    .line 20
    .line 21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    move-object/from16 v6, p1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v6, v3, Lm70/d0;->h:Lcs0/l;

    .line 39
    .line 40
    iput v7, v0, Lm70/c0;->d:I

    .line 41
    .line 42
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v6, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    if-ne v6, v5, :cond_2

    .line 50
    .line 51
    return-object v5

    .line 52
    :cond_2
    :goto_0
    check-cast v6, Lqr0/s;

    .line 53
    .line 54
    iget-boolean v5, v0, Lm70/c0;->f:Z

    .line 55
    .line 56
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    if-nez v5, :cond_2d

    .line 59
    .line 60
    const-string v5, "interval"

    .line 61
    .line 62
    iget-object v9, v0, Lm70/c0;->g:Ll70/w;

    .line 63
    .line 64
    invoke-static {v9, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget-object v5, v0, Lm70/c0;->i:Lne0/s;

    .line 68
    .line 69
    instance-of v10, v5, Lne0/c;

    .line 70
    .line 71
    const-string v11, "getDefault(...)"

    .line 72
    .line 73
    sget-object v29, Lmx0/s;->d:Lmx0/s;

    .line 74
    .line 75
    move-object/from16 p1, v8

    .line 76
    .line 77
    const-string v15, "selectedDataType"

    .line 78
    .line 79
    const-string v13, "unitsType"

    .line 80
    .line 81
    const-string v12, "stringResource"

    .line 82
    .line 83
    const-string v14, ""

    .line 84
    .line 85
    iget-object v7, v0, Lm70/c0;->j:Ll70/q;

    .line 86
    .line 87
    const-string v8, "<this>"

    .line 88
    .line 89
    if-eqz v10, :cond_c

    .line 90
    .line 91
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    check-cast v0, Lm70/b0;

    .line 96
    .line 97
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-static {v4, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    new-instance v15, Ll70/p;

    .line 110
    .line 111
    int-to-double v12, v1

    .line 112
    const-wide v18, 0x408f400000000000L    # 1000.0

    .line 113
    .line 114
    .line 115
    .line 116
    .line 117
    mul-double v12, v12, v18

    .line 118
    .line 119
    new-instance v5, Lqr0/i;

    .line 120
    .line 121
    move-object/from16 v30, v2

    .line 122
    .line 123
    const-wide/16 v1, 0x0

    .line 124
    .line 125
    invoke-direct {v5, v1, v2}, Lqr0/i;-><init>(D)V

    .line 126
    .line 127
    .line 128
    new-instance v8, Lqr0/g;

    .line 129
    .line 130
    invoke-direct {v8, v1, v2}, Lqr0/g;-><init>(D)V

    .line 131
    .line 132
    .line 133
    new-instance v10, Lqr0/j;

    .line 134
    .line 135
    invoke-direct {v10, v1, v2}, Lqr0/j;-><init>(D)V

    .line 136
    .line 137
    .line 138
    const-wide/16 v26, 0x0

    .line 139
    .line 140
    sget-object v28, Ll70/a0;->h:Ll70/a0;

    .line 141
    .line 142
    const/16 v16, 0x0

    .line 143
    .line 144
    const/16 v19, 0x0

    .line 145
    .line 146
    const/16 v22, 0x0

    .line 147
    .line 148
    move-wide/from16 v20, v12

    .line 149
    .line 150
    move-object/from16 v23, v5

    .line 151
    .line 152
    move-object/from16 v24, v8

    .line 153
    .line 154
    move-object/from16 v25, v10

    .line 155
    .line 156
    move-wide/from16 v17, v12

    .line 157
    .line 158
    invoke-direct/range {v15 .. v29}, Ll70/p;-><init>(Ll70/u;DIDILqr0/i;Lqr0/g;Lqr0/j;DLl70/a0;Ljava/util/List;)V

    .line 159
    .line 160
    .line 161
    const/4 v1, 0x0

    .line 162
    invoke-static {v4, v6, v15, v1, v7}, Lim/g;->b(Lij0/a;Lqr0/s;Ll70/p;Ljava/lang/Integer;Ll70/q;)Ljava/util/List;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-static {v15, v7, v6}, Ljb0/b;->d(Ll70/p;Ll70/q;Lqr0/s;)Ljava/lang/Number;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    invoke-static {v2}, Lim/g;->c(Ljava/lang/Number;)I

    .line 171
    .line 172
    .line 173
    move-result v19

    .line 174
    invoke-static/range {v19 .. v19}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    div-int/lit8 v5, v19, 0x2

    .line 179
    .line 180
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    move-object/from16 v8, v30

    .line 185
    .line 186
    filled-new-array {v2, v5, v8}, [Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    check-cast v2, Ljava/lang/Iterable;

    .line 195
    .line 196
    new-instance v5, Ljava/util/ArrayList;

    .line 197
    .line 198
    const/16 v10, 0xa

    .line 199
    .line 200
    invoke-static {v2, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 201
    .line 202
    .line 203
    move-result v12

    .line 204
    invoke-direct {v5, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 205
    .line 206
    .line 207
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 208
    .line 209
    .line 210
    move-result-object v2

    .line 211
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 212
    .line 213
    .line 214
    move-result v10

    .line 215
    if-eqz v10, :cond_3

    .line 216
    .line 217
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v10

    .line 221
    check-cast v10, Ljava/lang/Number;

    .line 222
    .line 223
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 224
    .line 225
    .line 226
    move-result v10

    .line 227
    invoke-static {v10}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v10

    .line 231
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    goto :goto_1

    .line 235
    :cond_3
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    if-eqz v2, :cond_6

    .line 240
    .line 241
    const/4 v10, 0x1

    .line 242
    if-eq v2, v10, :cond_5

    .line 243
    .line 244
    const/4 v10, 0x2

    .line 245
    if-ne v2, v10, :cond_4

    .line 246
    .line 247
    new-instance v2, Ljava/util/ArrayList;

    .line 248
    .line 249
    const/16 v10, 0xc

    .line 250
    .line 251
    invoke-direct {v2, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 252
    .line 253
    .line 254
    const/4 v12, 0x0

    .line 255
    :goto_2
    if-ge v12, v10, :cond_7

    .line 256
    .line 257
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    add-int/lit8 v12, v12, 0x1

    .line 261
    .line 262
    goto :goto_2

    .line 263
    :cond_4
    new-instance v0, La8/r0;

    .line 264
    .line 265
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 266
    .line 267
    .line 268
    throw v0

    .line 269
    :cond_5
    new-instance v2, Ljava/util/ArrayList;

    .line 270
    .line 271
    const/16 v10, 0x1e

    .line 272
    .line 273
    invoke-direct {v2, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 274
    .line 275
    .line 276
    const/4 v12, 0x0

    .line 277
    :goto_3
    if-ge v12, v10, :cond_7

    .line 278
    .line 279
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    add-int/lit8 v12, v12, 0x1

    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_6
    new-instance v2, Ljava/util/ArrayList;

    .line 286
    .line 287
    const/4 v10, 0x7

    .line 288
    invoke-direct {v2, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 289
    .line 290
    .line 291
    const/4 v12, 0x0

    .line 292
    :goto_4
    if-ge v12, v10, :cond_7

    .line 293
    .line 294
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    add-int/lit8 v12, v12, 0x1

    .line 298
    .line 299
    goto :goto_4

    .line 300
    :cond_7
    check-cast v1, Ljava/lang/Iterable;

    .line 301
    .line 302
    new-instance v8, Ljava/util/ArrayList;

    .line 303
    .line 304
    const/16 v10, 0xa

    .line 305
    .line 306
    invoke-static {v1, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 307
    .line 308
    .line 309
    move-result v12

    .line 310
    invoke-direct {v8, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 311
    .line 312
    .line 313
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 318
    .line 319
    .line 320
    move-result v10

    .line 321
    const v12, 0x7f1201aa

    .line 322
    .line 323
    .line 324
    if-eqz v10, :cond_8

    .line 325
    .line 326
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v10

    .line 330
    move-object v13, v10

    .line 331
    check-cast v13, Lm70/y;

    .line 332
    .line 333
    move-object/from16 p0, v0

    .line 334
    .line 335
    const/4 v10, 0x0

    .line 336
    new-array v0, v10, [Ljava/lang/Object;

    .line 337
    .line 338
    move-object v10, v4

    .line 339
    check-cast v10, Ljj0/f;

    .line 340
    .line 341
    invoke-virtual {v10, v12, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    new-instance v10, Llx0/l;

    .line 346
    .line 347
    invoke-direct {v10, v0, v14}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    invoke-static {v10}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    iget-object v10, v13, Lm70/y;->a:Ljava/lang/String;

    .line 355
    .line 356
    const-string v12, "title"

    .line 357
    .line 358
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    new-instance v12, Lm70/y;

    .line 362
    .line 363
    invoke-direct {v12, v10, v0}, Lm70/y;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 364
    .line 365
    .line 366
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 367
    .line 368
    .line 369
    move-object/from16 v0, p0

    .line 370
    .line 371
    goto :goto_5

    .line 372
    :cond_8
    move-object/from16 p0, v0

    .line 373
    .line 374
    new-instance v0, Lm70/z;

    .line 375
    .line 376
    const/4 v10, 0x0

    .line 377
    new-array v1, v10, [Ljava/lang/Object;

    .line 378
    .line 379
    move-object v13, v4

    .line 380
    check-cast v13, Ljj0/f;

    .line 381
    .line 382
    invoke-virtual {v13, v12, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v1

    .line 386
    invoke-direct {v0, v1, v10}, Lm70/z;-><init>(Ljava/lang/String;Z)V

    .line 387
    .line 388
    .line 389
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    new-instance v1, Lm70/a0;

    .line 394
    .line 395
    const/4 v12, 0x4

    .line 396
    invoke-direct {v1, v8, v0, v12}, Lm70/a0;-><init>(Ljava/util/ArrayList;Ljava/util/List;I)V

    .line 397
    .line 398
    .line 399
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 400
    .line 401
    .line 402
    move-result-object v0

    .line 403
    invoke-virtual {v0, v10}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 404
    .line 405
    .line 406
    move-result-object v0

    .line 407
    if-nez v0, :cond_9

    .line 408
    .line 409
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 410
    .line 411
    .line 412
    move-result-object v0

    .line 413
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    :cond_9
    iget-object v8, v15, Ll70/p;->k:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast v8, Ljava/util/Collection;

    .line 419
    .line 420
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 421
    .line 422
    .line 423
    move-result v8

    .line 424
    invoke-static {v9, v0, v8}, Ljp/q0;->f(Ll70/w;Ljava/util/Locale;I)Ljava/util/ArrayList;

    .line 425
    .line 426
    .line 427
    move-result-object v17

    .line 428
    new-instance v0, Ljava/util/ArrayList;

    .line 429
    .line 430
    const/16 v10, 0xa

    .line 431
    .line 432
    invoke-static {v2, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 433
    .line 434
    .line 435
    move-result v8

    .line 436
    invoke-direct {v0, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 437
    .line 438
    .line 439
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 444
    .line 445
    .line 446
    move-result v8

    .line 447
    if-eqz v8, :cond_a

    .line 448
    .line 449
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v8

    .line 453
    check-cast v8, Ljava/lang/Number;

    .line 454
    .line 455
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 456
    .line 457
    .line 458
    move-result v8

    .line 459
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 460
    .line 461
    .line 462
    move-result-object v8

    .line 463
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 464
    .line 465
    .line 466
    move-result-object v8

    .line 467
    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    goto :goto_6

    .line 471
    :cond_a
    invoke-static {v9}, Ljp/q0;->e(Ll70/w;)F

    .line 472
    .line 473
    .line 474
    move-result v22

    .line 475
    new-instance v16, Lvf0/a;

    .line 476
    .line 477
    const/16 v20, 0x0

    .line 478
    .line 479
    move-object/from16 v21, v0

    .line 480
    .line 481
    move-object/from16 v18, v5

    .line 482
    .line 483
    invoke-direct/range {v16 .. v22}, Lvf0/a;-><init>(Ljava/util/List;Ljava/util/List;ILjava/lang/Number;Ljava/util/List;F)V

    .line 484
    .line 485
    .line 486
    invoke-static {v15, v4, v7, v6}, Ljb0/b;->f(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    if-nez v0, :cond_b

    .line 491
    .line 492
    move-object/from16 v21, v14

    .line 493
    .line 494
    goto :goto_7

    .line 495
    :cond_b
    move-object/from16 v21, v0

    .line 496
    .line 497
    :goto_7
    const/16 v22, 0x0

    .line 498
    .line 499
    const/16 v23, 0x4

    .line 500
    .line 501
    move-object/from16 v18, p0

    .line 502
    .line 503
    move-object/from16 v19, v1

    .line 504
    .line 505
    move-object/from16 v20, v16

    .line 506
    .line 507
    invoke-static/range {v18 .. v23}, Lm70/b0;->a(Lm70/b0;Lm70/a0;Lvf0/a;Ljava/lang/String;ZI)Lm70/b0;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    goto/16 :goto_20

    .line 512
    .line 513
    :cond_c
    instance-of v1, v5, Lne0/e;

    .line 514
    .line 515
    if-eqz v1, :cond_2a

    .line 516
    .line 517
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 518
    .line 519
    .line 520
    move-result-object v1

    .line 521
    check-cast v1, Lm70/b0;

    .line 522
    .line 523
    check-cast v5, Lne0/e;

    .line 524
    .line 525
    iget-object v5, v5, Lne0/e;->a:Ljava/lang/Object;

    .line 526
    .line 527
    check-cast v5, Ll70/p;

    .line 528
    .line 529
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 530
    .line 531
    .line 532
    invoke-static {v4, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 536
    .line 537
    .line 538
    const-string v8, "tripStatistics"

    .line 539
    .line 540
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 541
    .line 542
    .line 543
    iget-object v8, v5, Ll70/p;->k:Ljava/lang/Object;

    .line 544
    .line 545
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 546
    .line 547
    .line 548
    invoke-static {v5, v7, v6}, Ljb0/b;->c(Ll70/p;Ll70/q;Lqr0/s;)Ljava/util/ArrayList;

    .line 549
    .line 550
    .line 551
    move-result-object v12

    .line 552
    invoke-static {v5, v7, v6}, Ljb0/b;->d(Ll70/p;Ll70/q;Lqr0/s;)Ljava/lang/Number;

    .line 553
    .line 554
    .line 555
    move-result-object v13

    .line 556
    invoke-virtual {v13}, Ljava/lang/Number;->doubleValue()D

    .line 557
    .line 558
    .line 559
    move-result-wide v18

    .line 560
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 561
    .line 562
    .line 563
    move-result v13

    .line 564
    packed-switch v13, :pswitch_data_0

    .line 565
    .line 566
    .line 567
    new-instance v0, La8/r0;

    .line 568
    .line 569
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 570
    .line 571
    .line 572
    throw v0

    .line 573
    :pswitch_0
    move-object v15, v11

    .line 574
    iget-wide v10, v5, Ll70/p;->i:D

    .line 575
    .line 576
    invoke-static {v10, v11, v6}, Lkp/o6;->c(DLqr0/s;)I

    .line 577
    .line 578
    .line 579
    move-result v10

    .line 580
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 581
    .line 582
    .line 583
    move-result-object v10

    .line 584
    goto :goto_8

    .line 585
    :pswitch_1
    move-object v15, v11

    .line 586
    iget v10, v5, Ll70/p;->e:I

    .line 587
    .line 588
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 589
    .line 590
    .line 591
    move-result-object v10

    .line 592
    goto :goto_8

    .line 593
    :pswitch_2
    move-object v15, v11

    .line 594
    iget-wide v10, v5, Ll70/p;->d:D

    .line 595
    .line 596
    invoke-static {v10, v11, v6}, Lkp/f6;->b(DLqr0/s;)D

    .line 597
    .line 598
    .line 599
    move-result-wide v10

    .line 600
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 601
    .line 602
    .line 603
    move-result-object v10

    .line 604
    goto :goto_8

    .line 605
    :pswitch_3
    move-object v15, v11

    .line 606
    iget-object v10, v5, Ll70/p;->g:Lqr0/g;

    .line 607
    .line 608
    iget-wide v10, v10, Lqr0/g;->a:D

    .line 609
    .line 610
    invoke-static {v10, v11, v6}, Lkp/g6;->d(DLqr0/s;)D

    .line 611
    .line 612
    .line 613
    move-result-wide v10

    .line 614
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 615
    .line 616
    .line 617
    move-result-object v10

    .line 618
    goto :goto_8

    .line 619
    :pswitch_4
    move-object v15, v11

    .line 620
    iget-object v10, v5, Ll70/p;->f:Lqr0/i;

    .line 621
    .line 622
    iget-wide v10, v10, Lqr0/i;->a:D

    .line 623
    .line 624
    invoke-static {v10, v11, v6}, Lkp/i6;->d(DLqr0/s;)D

    .line 625
    .line 626
    .line 627
    move-result-wide v10

    .line 628
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 629
    .line 630
    .line 631
    move-result-object v10

    .line 632
    goto :goto_8

    .line 633
    :pswitch_5
    move-object v15, v11

    .line 634
    iget-object v10, v5, Ll70/p;->h:Lqr0/j;

    .line 635
    .line 636
    iget-wide v10, v10, Lqr0/j;->a:D

    .line 637
    .line 638
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 639
    .line 640
    .line 641
    move-result-object v10

    .line 642
    goto :goto_8

    .line 643
    :pswitch_6
    move-object v15, v11

    .line 644
    const/4 v10, 0x0

    .line 645
    :goto_8
    if-eqz v10, :cond_d

    .line 646
    .line 647
    invoke-virtual {v10}, Ljava/lang/Number;->doubleValue()D

    .line 648
    .line 649
    .line 650
    move-result-wide v10

    .line 651
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 652
    .line 653
    .line 654
    move-result-object v20

    .line 655
    const-wide/16 v16, 0x0

    .line 656
    .line 657
    cmpl-double v16, v10, v16

    .line 658
    .line 659
    if-lez v16, :cond_d

    .line 660
    .line 661
    cmpg-double v10, v10, v18

    .line 662
    .line 663
    if-gtz v10, :cond_d

    .line 664
    .line 665
    goto :goto_9

    .line 666
    :cond_d
    const/16 v20, 0x0

    .line 667
    .line 668
    :goto_9
    invoke-static {v5, v4, v7, v6}, Ljb0/b;->f(Ll70/p;Lij0/a;Ll70/q;Lqr0/s;)Ljava/lang/String;

    .line 669
    .line 670
    .line 671
    move-result-object v10

    .line 672
    if-nez v10, :cond_e

    .line 673
    .line 674
    move-object v11, v14

    .line 675
    goto :goto_a

    .line 676
    :cond_e
    move-object v11, v10

    .line 677
    :goto_a
    sget-object v10, Ll70/q;->l:Ll70/q;

    .line 678
    .line 679
    if-ne v7, v10, :cond_12

    .line 680
    .line 681
    const-wide/high16 v16, 0x404e000000000000L    # 60.0

    .line 682
    .line 683
    cmpl-double v10, v18, v16

    .line 684
    .line 685
    if-lez v10, :cond_12

    .line 686
    .line 687
    const/4 v10, 0x0

    .line 688
    new-array v11, v10, [Ljava/lang/Object;

    .line 689
    .line 690
    move-object v13, v4

    .line 691
    check-cast v13, Ljj0/f;

    .line 692
    .line 693
    const v10, 0x7f1203c7

    .line 694
    .line 695
    .line 696
    invoke-virtual {v13, v10, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 697
    .line 698
    .line 699
    move-result-object v11

    .line 700
    div-double v18, v18, v16

    .line 701
    .line 702
    if-eqz v20, :cond_f

    .line 703
    .line 704
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Number;->doubleValue()D

    .line 705
    .line 706
    .line 707
    move-result-wide v22

    .line 708
    div-double v22, v22, v16

    .line 709
    .line 710
    invoke-static/range {v22 .. v23}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 711
    .line 712
    .line 713
    move-result-object v20

    .line 714
    :cond_f
    new-instance v10, Ljava/util/ArrayList;

    .line 715
    .line 716
    move-object/from16 v22, v1

    .line 717
    .line 718
    const/16 v13, 0xa

    .line 719
    .line 720
    invoke-static {v12, v13}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 721
    .line 722
    .line 723
    move-result v1

    .line 724
    invoke-direct {v10, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 725
    .line 726
    .line 727
    invoke-virtual {v12}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 728
    .line 729
    .line 730
    move-result-object v1

    .line 731
    :goto_b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 732
    .line 733
    .line 734
    move-result v12

    .line 735
    if-eqz v12, :cond_11

    .line 736
    .line 737
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 738
    .line 739
    .line 740
    move-result-object v12

    .line 741
    check-cast v12, Ljava/util/List;

    .line 742
    .line 743
    check-cast v12, Ljava/lang/Iterable;

    .line 744
    .line 745
    move-object/from16 v23, v1

    .line 746
    .line 747
    new-instance v1, Ljava/util/ArrayList;

    .line 748
    .line 749
    move-object/from16 v24, v11

    .line 750
    .line 751
    invoke-static {v12, v13}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 752
    .line 753
    .line 754
    move-result v11

    .line 755
    invoke-direct {v1, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 756
    .line 757
    .line 758
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 759
    .line 760
    .line 761
    move-result-object v11

    .line 762
    :goto_c
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 763
    .line 764
    .line 765
    move-result v12

    .line 766
    if-eqz v12, :cond_10

    .line 767
    .line 768
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 769
    .line 770
    .line 771
    move-result-object v12

    .line 772
    check-cast v12, Ljava/lang/Number;

    .line 773
    .line 774
    invoke-virtual {v12}, Ljava/lang/Number;->doubleValue()D

    .line 775
    .line 776
    .line 777
    move-result-wide v12

    .line 778
    div-double v12, v12, v16

    .line 779
    .line 780
    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 781
    .line 782
    .line 783
    move-result-object v12

    .line 784
    invoke-virtual {v1, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 785
    .line 786
    .line 787
    goto :goto_c

    .line 788
    :cond_10
    invoke-virtual {v10, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 789
    .line 790
    .line 791
    move-object/from16 v1, v23

    .line 792
    .line 793
    move-object/from16 v11, v24

    .line 794
    .line 795
    const/16 v13, 0xa

    .line 796
    .line 797
    goto :goto_b

    .line 798
    :cond_11
    move-object/from16 v24, v11

    .line 799
    .line 800
    move-object/from16 v35, v10

    .line 801
    .line 802
    :goto_d
    move-object/from16 v34, v20

    .line 803
    .line 804
    goto :goto_e

    .line 805
    :cond_12
    move-object/from16 v22, v1

    .line 806
    .line 807
    move-object/from16 v35, v12

    .line 808
    .line 809
    goto :goto_d

    .line 810
    :goto_e
    invoke-static/range {v18 .. v19}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 811
    .line 812
    .line 813
    move-result-object v1

    .line 814
    invoke-static {v1}, Lim/g;->c(Ljava/lang/Number;)I

    .line 815
    .line 816
    .line 817
    move-result v33

    .line 818
    invoke-static/range {v33 .. v33}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 819
    .line 820
    .line 821
    move-result-object v1

    .line 822
    div-int/lit8 v10, v33, 0x2

    .line 823
    .line 824
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 825
    .line 826
    .line 827
    move-result-object v10

    .line 828
    filled-new-array {v1, v10, v2}, [Ljava/lang/Integer;

    .line 829
    .line 830
    .line 831
    move-result-object v1

    .line 832
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 833
    .line 834
    .line 835
    move-result-object v1

    .line 836
    check-cast v1, Ljava/lang/Iterable;

    .line 837
    .line 838
    new-instance v2, Ljava/util/ArrayList;

    .line 839
    .line 840
    const/16 v10, 0xa

    .line 841
    .line 842
    invoke-static {v1, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 843
    .line 844
    .line 845
    move-result v12

    .line 846
    invoke-direct {v2, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 847
    .line 848
    .line 849
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 850
    .line 851
    .line 852
    move-result-object v1

    .line 853
    :goto_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 854
    .line 855
    .line 856
    move-result v10

    .line 857
    if-eqz v10, :cond_13

    .line 858
    .line 859
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 860
    .line 861
    .line 862
    move-result-object v10

    .line 863
    check-cast v10, Ljava/lang/Number;

    .line 864
    .line 865
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 866
    .line 867
    .line 868
    move-result v10

    .line 869
    invoke-static {v10}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 870
    .line 871
    .line 872
    move-result-object v10

    .line 873
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 874
    .line 875
    .line 876
    goto :goto_f

    .line 877
    :cond_13
    new-instance v1, Lm70/a0;

    .line 878
    .line 879
    iget-object v0, v0, Lm70/c0;->k:Ljava/lang/Integer;

    .line 880
    .line 881
    invoke-static {v4, v6, v5, v0, v7}, Lim/g;->b(Lij0/a;Lqr0/s;Ll70/p;Ljava/lang/Integer;Ll70/q;)Ljava/util/List;

    .line 882
    .line 883
    .line 884
    move-result-object v12

    .line 885
    new-instance v13, Ljava/util/ArrayList;

    .line 886
    .line 887
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 888
    .line 889
    .line 890
    if-eqz v0, :cond_15

    .line 891
    .line 892
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 893
    .line 894
    .line 895
    move-result v10

    .line 896
    invoke-static {v10, v8}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 897
    .line 898
    .line 899
    move-result-object v10

    .line 900
    check-cast v10, Ll70/r;

    .line 901
    .line 902
    if-eqz v10, :cond_14

    .line 903
    .line 904
    iget-object v10, v10, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 905
    .line 906
    invoke-virtual {v10}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 907
    .line 908
    .line 909
    move-result-object v10

    .line 910
    if-eqz v10, :cond_14

    .line 911
    .line 912
    invoke-static {v10, v9}, Lim/g;->f(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;

    .line 913
    .line 914
    .line 915
    move-result-object v10

    .line 916
    goto :goto_10

    .line 917
    :cond_14
    const/4 v10, 0x0

    .line 918
    goto :goto_10

    .line 919
    :cond_15
    invoke-static {v8}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object v10

    .line 923
    check-cast v10, Ll70/r;

    .line 924
    .line 925
    if-eqz v10, :cond_14

    .line 926
    .line 927
    iget-object v10, v10, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 928
    .line 929
    invoke-virtual {v10}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 930
    .line 931
    .line 932
    move-result-object v10

    .line 933
    if-eqz v10, :cond_14

    .line 934
    .line 935
    invoke-static {v10, v9}, Lim/g;->g(Ljava/time/LocalDate;Ll70/w;)Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v10

    .line 939
    :goto_10
    if-eqz v0, :cond_17

    .line 940
    .line 941
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 942
    .line 943
    .line 944
    move-result v0

    .line 945
    invoke-static {v0, v8}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 946
    .line 947
    .line 948
    move-result-object v0

    .line 949
    check-cast v0, Ll70/r;

    .line 950
    .line 951
    if-eqz v0, :cond_16

    .line 952
    .line 953
    iget-object v0, v0, Ll70/r;->i:Ll70/u;

    .line 954
    .line 955
    goto :goto_11

    .line 956
    :cond_16
    const/4 v0, 0x0

    .line 957
    goto :goto_11

    .line 958
    :cond_17
    iget-object v0, v5, Ll70/p;->a:Ll70/u;

    .line 959
    .line 960
    :goto_11
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 961
    .line 962
    .line 963
    move-result v5

    .line 964
    if-eqz v5, :cond_20

    .line 965
    .line 966
    move-object/from16 v32, v2

    .line 967
    .line 968
    const/4 v2, 0x1

    .line 969
    if-eq v5, v2, :cond_1d

    .line 970
    .line 971
    const/4 v2, 0x2

    .line 972
    if-eq v5, v2, :cond_1a

    .line 973
    .line 974
    const/4 v2, 0x3

    .line 975
    if-eq v5, v2, :cond_18

    .line 976
    .line 977
    const/4 v0, 0x0

    .line 978
    goto/16 :goto_18

    .line 979
    .line 980
    :cond_18
    if-eqz v0, :cond_19

    .line 981
    .line 982
    iget-object v0, v0, Ll70/u;->e:Ll70/t;

    .line 983
    .line 984
    if-eqz v0, :cond_19

    .line 985
    .line 986
    sget-object v2, Ll70/h;->e:Ll70/h;

    .line 987
    .line 988
    invoke-static {v0, v6, v2}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 989
    .line 990
    .line 991
    move-result-object v0

    .line 992
    goto :goto_12

    .line 993
    :cond_19
    const/4 v0, 0x0

    .line 994
    :goto_12
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    goto :goto_18

    .line 999
    :cond_1a
    if-eqz v0, :cond_1b

    .line 1000
    .line 1001
    iget-object v2, v0, Ll70/u;->d:Ll70/t;

    .line 1002
    .line 1003
    if-eqz v2, :cond_1b

    .line 1004
    .line 1005
    sget-object v5, Ll70/h;->f:Ll70/h;

    .line 1006
    .line 1007
    invoke-static {v2, v6, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v2

    .line 1011
    goto :goto_13

    .line 1012
    :cond_1b
    const/4 v2, 0x0

    .line 1013
    :goto_13
    if-eqz v0, :cond_1c

    .line 1014
    .line 1015
    iget-object v0, v0, Ll70/u;->c:Ll70/t;

    .line 1016
    .line 1017
    if-eqz v0, :cond_1c

    .line 1018
    .line 1019
    sget-object v5, Ll70/h;->d:Ll70/h;

    .line 1020
    .line 1021
    invoke-static {v0, v6, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v0

    .line 1025
    goto :goto_14

    .line 1026
    :cond_1c
    const/4 v0, 0x0

    .line 1027
    :goto_14
    filled-new-array {v2, v0}, [Ljava/lang/String;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v0

    .line 1031
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v0

    .line 1035
    goto :goto_18

    .line 1036
    :cond_1d
    if-eqz v0, :cond_1e

    .line 1037
    .line 1038
    iget-object v2, v0, Ll70/u;->c:Ll70/t;

    .line 1039
    .line 1040
    if-eqz v2, :cond_1e

    .line 1041
    .line 1042
    sget-object v5, Ll70/h;->d:Ll70/h;

    .line 1043
    .line 1044
    invoke-static {v2, v6, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v2

    .line 1048
    goto :goto_15

    .line 1049
    :cond_1e
    const/4 v2, 0x0

    .line 1050
    :goto_15
    if-eqz v0, :cond_1f

    .line 1051
    .line 1052
    iget-object v0, v0, Ll70/u;->e:Ll70/t;

    .line 1053
    .line 1054
    if-eqz v0, :cond_1f

    .line 1055
    .line 1056
    sget-object v5, Ll70/h;->e:Ll70/h;

    .line 1057
    .line 1058
    invoke-static {v0, v6, v5}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v0

    .line 1062
    goto :goto_16

    .line 1063
    :cond_1f
    const/4 v0, 0x0

    .line 1064
    :goto_16
    filled-new-array {v2, v0}, [Ljava/lang/String;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v0

    .line 1068
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v0

    .line 1072
    goto :goto_18

    .line 1073
    :cond_20
    move-object/from16 v32, v2

    .line 1074
    .line 1075
    if-eqz v0, :cond_21

    .line 1076
    .line 1077
    iget-object v0, v0, Ll70/u;->c:Ll70/t;

    .line 1078
    .line 1079
    if-eqz v0, :cond_21

    .line 1080
    .line 1081
    sget-object v2, Ll70/h;->d:Ll70/h;

    .line 1082
    .line 1083
    invoke-static {v0, v6, v2}, Ljp/p0;->g(Ll70/t;Lqr0/s;Ll70/h;)Ljava/lang/String;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v0

    .line 1087
    goto :goto_17

    .line 1088
    :cond_21
    const/4 v0, 0x0

    .line 1089
    :goto_17
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v0

    .line 1093
    :goto_18
    if-eqz v0, :cond_22

    .line 1094
    .line 1095
    check-cast v0, Ljava/lang/Iterable;

    .line 1096
    .line 1097
    invoke-static {v0}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v0

    .line 1101
    goto :goto_19

    .line 1102
    :cond_22
    const/4 v0, 0x0

    .line 1103
    :goto_19
    new-instance v2, Lm70/z;

    .line 1104
    .line 1105
    if-nez v10, :cond_23

    .line 1106
    .line 1107
    :goto_1a
    const/4 v10, 0x0

    .line 1108
    goto :goto_1b

    .line 1109
    :cond_23
    move-object v14, v10

    .line 1110
    goto :goto_1a

    .line 1111
    :goto_1b
    invoke-direct {v2, v14, v10}, Lm70/z;-><init>(Ljava/lang/String;Z)V

    .line 1112
    .line 1113
    .line 1114
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1115
    .line 1116
    .line 1117
    if-eqz v0, :cond_25

    .line 1118
    .line 1119
    new-instance v2, Ljava/util/ArrayList;

    .line 1120
    .line 1121
    const/16 v5, 0xa

    .line 1122
    .line 1123
    invoke-static {v0, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1124
    .line 1125
    .line 1126
    move-result v5

    .line 1127
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 1128
    .line 1129
    .line 1130
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v0

    .line 1134
    :goto_1c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1135
    .line 1136
    .line 1137
    move-result v5

    .line 1138
    if-eqz v5, :cond_24

    .line 1139
    .line 1140
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v5

    .line 1144
    check-cast v5, Ljava/lang/String;

    .line 1145
    .line 1146
    new-instance v6, Lm70/z;

    .line 1147
    .line 1148
    const/4 v14, 0x1

    .line 1149
    invoke-direct {v6, v5, v14}, Lm70/z;-><init>(Ljava/lang/String;Z)V

    .line 1150
    .line 1151
    .line 1152
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1153
    .line 1154
    .line 1155
    goto :goto_1c

    .line 1156
    :cond_24
    const/4 v14, 0x1

    .line 1157
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1158
    .line 1159
    .line 1160
    goto :goto_1d

    .line 1161
    :cond_25
    const/4 v14, 0x1

    .line 1162
    :goto_1d
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 1163
    .line 1164
    .line 1165
    move-result v0

    .line 1166
    const v2, 0x7f120238

    .line 1167
    .line 1168
    .line 1169
    if-eq v0, v14, :cond_27

    .line 1170
    .line 1171
    const/4 v5, 0x2

    .line 1172
    if-eq v0, v5, :cond_26

    .line 1173
    .line 1174
    const/4 v14, 0x0

    .line 1175
    goto :goto_1e

    .line 1176
    :cond_26
    new-instance v0, Lm70/x;

    .line 1177
    .line 1178
    const/4 v10, 0x0

    .line 1179
    new-array v5, v10, [Ljava/lang/Object;

    .line 1180
    .line 1181
    check-cast v4, Ljj0/f;

    .line 1182
    .line 1183
    const v6, 0x7f120236

    .line 1184
    .line 1185
    .line 1186
    invoke-virtual {v4, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v5

    .line 1190
    invoke-direct {v0, v5}, Lm70/x;-><init>(Ljava/lang/String;)V

    .line 1191
    .line 1192
    .line 1193
    new-instance v5, Lm70/x;

    .line 1194
    .line 1195
    new-array v6, v10, [Ljava/lang/Object;

    .line 1196
    .line 1197
    invoke-virtual {v4, v2, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v2

    .line 1201
    invoke-direct {v5, v2}, Lm70/x;-><init>(Ljava/lang/String;)V

    .line 1202
    .line 1203
    .line 1204
    filled-new-array {v0, v5}, [Lm70/x;

    .line 1205
    .line 1206
    .line 1207
    move-result-object v0

    .line 1208
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v14

    .line 1212
    goto :goto_1e

    .line 1213
    :cond_27
    const/4 v10, 0x0

    .line 1214
    new-instance v0, Lm70/x;

    .line 1215
    .line 1216
    new-array v5, v10, [Ljava/lang/Object;

    .line 1217
    .line 1218
    check-cast v4, Ljj0/f;

    .line 1219
    .line 1220
    invoke-virtual {v4, v2, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v2

    .line 1224
    invoke-direct {v0, v2}, Lm70/x;-><init>(Ljava/lang/String;)V

    .line 1225
    .line 1226
    .line 1227
    new-instance v2, Lm70/x;

    .line 1228
    .line 1229
    const v5, 0x7f120234

    .line 1230
    .line 1231
    .line 1232
    new-array v6, v10, [Ljava/lang/Object;

    .line 1233
    .line 1234
    invoke-virtual {v4, v5, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v4

    .line 1238
    invoke-direct {v2, v4}, Lm70/x;-><init>(Ljava/lang/String;)V

    .line 1239
    .line 1240
    .line 1241
    filled-new-array {v0, v2}, [Lm70/x;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v0

    .line 1245
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v14

    .line 1249
    :goto_1e
    if-nez v14, :cond_28

    .line 1250
    .line 1251
    move-object/from16 v14, v29

    .line 1252
    .line 1253
    :cond_28
    invoke-direct {v1, v12, v13, v14}, Lm70/a0;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 1254
    .line 1255
    .line 1256
    new-instance v30, Lvf0/a;

    .line 1257
    .line 1258
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v0

    .line 1262
    const/4 v10, 0x0

    .line 1263
    invoke-virtual {v0, v10}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v0

    .line 1267
    if-nez v0, :cond_29

    .line 1268
    .line 1269
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v0

    .line 1273
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1274
    .line 1275
    .line 1276
    :cond_29
    check-cast v8, Ljava/util/Collection;

    .line 1277
    .line 1278
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 1279
    .line 1280
    .line 1281
    move-result v2

    .line 1282
    invoke-static {v9, v0, v2}, Ljp/q0;->f(Ll70/w;Ljava/util/Locale;I)Ljava/util/ArrayList;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v31

    .line 1286
    invoke-static {v9}, Ljp/q0;->e(Ll70/w;)F

    .line 1287
    .line 1288
    .line 1289
    move-result v36

    .line 1290
    invoke-direct/range {v30 .. v36}, Lvf0/a;-><init>(Ljava/util/List;Ljava/util/List;ILjava/lang/Number;Ljava/util/List;F)V

    .line 1291
    .line 1292
    .line 1293
    move-object/from16 v18, v22

    .line 1294
    .line 1295
    const/16 v22, 0x0

    .line 1296
    .line 1297
    const/16 v23, 0x4

    .line 1298
    .line 1299
    move-object/from16 v19, v1

    .line 1300
    .line 1301
    move-object/from16 v21, v11

    .line 1302
    .line 1303
    move-object/from16 v20, v30

    .line 1304
    .line 1305
    invoke-static/range {v18 .. v23}, Lm70/b0;->a(Lm70/b0;Lm70/a0;Lvf0/a;Ljava/lang/String;ZI)Lm70/b0;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v0

    .line 1309
    goto :goto_20

    .line 1310
    :cond_2a
    if-eqz v5, :cond_2c

    .line 1311
    .line 1312
    sget-object v0, Lne0/d;->a:Lne0/d;

    .line 1313
    .line 1314
    invoke-virtual {v5, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1315
    .line 1316
    .line 1317
    move-result v0

    .line 1318
    if-eqz v0, :cond_2b

    .line 1319
    .line 1320
    goto :goto_1f

    .line 1321
    :cond_2b
    new-instance v0, La8/r0;

    .line 1322
    .line 1323
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1324
    .line 1325
    .line 1326
    throw v0

    .line 1327
    :cond_2c
    :goto_1f
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 1328
    .line 1329
    .line 1330
    move-result-object v0

    .line 1331
    move-object v9, v0

    .line 1332
    check-cast v9, Lm70/b0;

    .line 1333
    .line 1334
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1335
    .line 1336
    .line 1337
    const/4 v13, 0x1

    .line 1338
    const/16 v14, 0xf

    .line 1339
    .line 1340
    const/4 v10, 0x0

    .line 1341
    const/4 v11, 0x0

    .line 1342
    const/4 v12, 0x0

    .line 1343
    invoke-static/range {v9 .. v14}, Lm70/b0;->a(Lm70/b0;Lm70/a0;Lvf0/a;Ljava/lang/String;ZI)Lm70/b0;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v0

    .line 1347
    :goto_20
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 1348
    .line 1349
    .line 1350
    return-object p1

    .line 1351
    :cond_2d
    move-object/from16 p1, v8

    .line 1352
    .line 1353
    return-object p1

    .line 1354
    nop

    .line 1355
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
