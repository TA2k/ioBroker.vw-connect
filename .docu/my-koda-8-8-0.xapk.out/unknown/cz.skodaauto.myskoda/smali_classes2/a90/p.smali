.class public final La90/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:La90/t;

.field public final b:La90/m;

.field public final c:La90/l;

.field public final d:La90/k;

.field public final e:La90/n;

.field public final f:La90/h;


# direct methods
.method public constructor <init>(La90/t;La90/m;La90/l;La90/k;La90/n;La90/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/p;->a:La90/t;

    .line 5
    .line 6
    iput-object p2, p0, La90/p;->b:La90/m;

    .line 7
    .line 8
    iput-object p3, p0, La90/p;->c:La90/l;

    .line 9
    .line 10
    iput-object p4, p0, La90/p;->d:La90/k;

    .line 11
    .line 12
    iput-object p5, p0, La90/p;->e:La90/n;

    .line 13
    .line 14
    iput-object p6, p0, La90/p;->f:La90/h;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, La90/p;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, La90/o;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, La90/o;

    .line 11
    .line 12
    iget v3, v2, La90/o;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, La90/o;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, La90/o;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, La90/o;-><init>(La90/p;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, La90/o;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, La90/o;->g:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    if-eqz v4, :cond_3

    .line 38
    .line 39
    if-eq v4, v6, :cond_2

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    iget-object v2, v2, La90/o;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

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
    iget-object v4, v2, La90/o;->d:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object/from16 v19, v4

    .line 63
    .line 64
    move-object v4, v1

    .line 65
    move-object/from16 v1, v19

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    move-object/from16 v1, p1

    .line 72
    .line 73
    iput-object v1, v2, La90/o;->d:Ljava/lang/String;

    .line 74
    .line 75
    iput v6, v2, La90/o;->g:I

    .line 76
    .line 77
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    iget-object v6, v0, La90/p;->a:La90/t;

    .line 80
    .line 81
    invoke-virtual {v6, v4, v2}, La90/t;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    if-ne v4, v3, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_1
    check-cast v4, Lyy0/i;

    .line 89
    .line 90
    iput-object v1, v2, La90/o;->d:Ljava/lang/String;

    .line 91
    .line 92
    iput v5, v2, La90/o;->g:I

    .line 93
    .line 94
    invoke-static {v4, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    if-ne v2, v3, :cond_5

    .line 99
    .line 100
    :goto_2
    return-object v3

    .line 101
    :cond_5
    move-object/from16 v19, v2

    .line 102
    .line 103
    move-object v2, v1

    .line 104
    move-object/from16 v1, v19

    .line 105
    .line 106
    :goto_3
    instance-of v3, v1, Lne0/e;

    .line 107
    .line 108
    const/4 v4, 0x0

    .line 109
    if-eqz v3, :cond_6

    .line 110
    .line 111
    check-cast v1, Lne0/e;

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_6
    move-object v1, v4

    .line 115
    :goto_4
    if-nez v1, :cond_7

    .line 116
    .line 117
    new-instance v5, Lne0/c;

    .line 118
    .line 119
    new-instance v6, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string v0, "Form definition is null"

    .line 122
    .line 123
    invoke-direct {v6, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const/4 v9, 0x0

    .line 127
    const/16 v10, 0x1e

    .line 128
    .line 129
    const/4 v7, 0x0

    .line 130
    const/4 v8, 0x0

    .line 131
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 132
    .line 133
    .line 134
    return-object v5

    .line 135
    :cond_7
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v1, Lb90/f;

    .line 138
    .line 139
    iget-object v3, v0, La90/p;->b:La90/m;

    .line 140
    .line 141
    invoke-virtual {v3}, La90/m;->invoke()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    check-cast v3, Lb90/s;

    .line 146
    .line 147
    iget-object v5, v1, Lb90/f;->b:Ljava/util/ArrayList;

    .line 148
    .line 149
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 150
    .line 151
    .line 152
    move-result-object v5

    .line 153
    :cond_8
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    if-eqz v6, :cond_9

    .line 158
    .line 159
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    move-object v7, v6

    .line 164
    check-cast v7, Lb90/p;

    .line 165
    .line 166
    iget-object v7, v7, Lb90/p;->b:Lb90/q;

    .line 167
    .line 168
    sget-object v8, Lb90/q;->v:Lb90/q;

    .line 169
    .line 170
    if-ne v7, v8, :cond_8

    .line 171
    .line 172
    goto :goto_5

    .line 173
    :cond_9
    move-object v6, v4

    .line 174
    :goto_5
    check-cast v6, Lb90/p;

    .line 175
    .line 176
    if-eqz v6, :cond_a

    .line 177
    .line 178
    iget-object v5, v6, Lb90/p;->a:Ljava/lang/String;

    .line 179
    .line 180
    move-object v7, v5

    .line 181
    goto :goto_6

    .line 182
    :cond_a
    move-object v7, v4

    .line 183
    :goto_6
    if-eqz v3, :cond_b

    .line 184
    .line 185
    if-eqz v7, :cond_b

    .line 186
    .line 187
    new-instance v5, Lb90/j;

    .line 188
    .line 189
    new-instance v6, Lb90/p;

    .line 190
    .line 191
    sget-object v8, Lb90/q;->v:Lb90/q;

    .line 192
    .line 193
    const/4 v11, 0x0

    .line 194
    const/4 v10, 0x0

    .line 195
    const/4 v9, 0x1

    .line 196
    invoke-direct/range {v6 .. v11}, Lb90/p;-><init>(Ljava/lang/String;Lb90/q;ZLjava/lang/String;Ljava/util/ArrayList;)V

    .line 197
    .line 198
    .line 199
    iget-object v3, v3, Lb90/s;->a:Ljava/lang/String;

    .line 200
    .line 201
    invoke-direct {v5, v6, v3}, Lb90/j;-><init>(Lb90/p;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    move-object v8, v5

    .line 205
    goto :goto_7

    .line 206
    :cond_b
    move-object v8, v4

    .line 207
    :goto_7
    iget-object v3, v0, La90/p;->c:La90/l;

    .line 208
    .line 209
    invoke-virtual {v3}, La90/l;->invoke()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v3

    .line 213
    check-cast v3, Lb90/m;

    .line 214
    .line 215
    iget-object v5, v1, Lb90/f;->b:Ljava/util/ArrayList;

    .line 216
    .line 217
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 218
    .line 219
    .line 220
    move-result-object v5

    .line 221
    :cond_c
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    if-eqz v6, :cond_d

    .line 226
    .line 227
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v6

    .line 231
    move-object v7, v6

    .line 232
    check-cast v7, Lb90/p;

    .line 233
    .line 234
    iget-object v7, v7, Lb90/p;->b:Lb90/q;

    .line 235
    .line 236
    sget-object v9, Lb90/q;->t:Lb90/q;

    .line 237
    .line 238
    if-ne v7, v9, :cond_c

    .line 239
    .line 240
    goto :goto_8

    .line 241
    :cond_d
    move-object v6, v4

    .line 242
    :goto_8
    check-cast v6, Lb90/p;

    .line 243
    .line 244
    if-eqz v6, :cond_e

    .line 245
    .line 246
    iget-object v5, v6, Lb90/p;->a:Ljava/lang/String;

    .line 247
    .line 248
    move-object v10, v5

    .line 249
    goto :goto_9

    .line 250
    :cond_e
    move-object v10, v4

    .line 251
    :goto_9
    if-eqz v3, :cond_f

    .line 252
    .line 253
    if-eqz v10, :cond_f

    .line 254
    .line 255
    new-instance v5, Lb90/j;

    .line 256
    .line 257
    new-instance v9, Lb90/p;

    .line 258
    .line 259
    sget-object v11, Lb90/q;->t:Lb90/q;

    .line 260
    .line 261
    const/4 v14, 0x0

    .line 262
    const/4 v13, 0x0

    .line 263
    const/4 v12, 0x1

    .line 264
    invoke-direct/range {v9 .. v14}, Lb90/p;-><init>(Ljava/lang/String;Lb90/q;ZLjava/lang/String;Ljava/util/ArrayList;)V

    .line 265
    .line 266
    .line 267
    iget-object v3, v3, Lb90/m;->a:Ljava/lang/String;

    .line 268
    .line 269
    invoke-direct {v5, v9, v3}, Lb90/j;-><init>(Lb90/p;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    move-object v9, v5

    .line 273
    goto :goto_a

    .line 274
    :cond_f
    move-object v9, v4

    .line 275
    :goto_a
    iget-object v3, v0, La90/p;->d:La90/k;

    .line 276
    .line 277
    invoke-virtual {v3}, La90/k;->invoke()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v3

    .line 281
    check-cast v3, Ljava/time/LocalDate;

    .line 282
    .line 283
    iget-object v5, v1, Lb90/f;->b:Ljava/util/ArrayList;

    .line 284
    .line 285
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 286
    .line 287
    .line 288
    move-result-object v5

    .line 289
    :cond_10
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 290
    .line 291
    .line 292
    move-result v6

    .line 293
    if-eqz v6, :cond_11

    .line 294
    .line 295
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    move-object v7, v6

    .line 300
    check-cast v7, Lb90/p;

    .line 301
    .line 302
    iget-object v7, v7, Lb90/p;->b:Lb90/q;

    .line 303
    .line 304
    sget-object v10, Lb90/q;->r:Lb90/q;

    .line 305
    .line 306
    if-ne v7, v10, :cond_10

    .line 307
    .line 308
    goto :goto_b

    .line 309
    :cond_11
    move-object v6, v4

    .line 310
    :goto_b
    check-cast v6, Lb90/p;

    .line 311
    .line 312
    if-eqz v6, :cond_12

    .line 313
    .line 314
    iget-object v5, v6, Lb90/p;->a:Ljava/lang/String;

    .line 315
    .line 316
    move-object v11, v5

    .line 317
    goto :goto_c

    .line 318
    :cond_12
    move-object v11, v4

    .line 319
    :goto_c
    const-string v5, "format(...)"

    .line 320
    .line 321
    if-eqz v3, :cond_13

    .line 322
    .line 323
    if-eqz v11, :cond_13

    .line 324
    .line 325
    new-instance v6, Lb90/j;

    .line 326
    .line 327
    new-instance v10, Lb90/p;

    .line 328
    .line 329
    sget-object v12, Lb90/q;->r:Lb90/q;

    .line 330
    .line 331
    const/4 v15, 0x0

    .line 332
    const/4 v14, 0x0

    .line 333
    const/4 v13, 0x0

    .line 334
    invoke-direct/range {v10 .. v15}, Lb90/p;-><init>(Ljava/lang/String;Lb90/q;ZLjava/lang/String;Ljava/util/ArrayList;)V

    .line 335
    .line 336
    .line 337
    sget-object v7, Ljava/time/format/DateTimeFormatter;->ISO_LOCAL_DATE:Ljava/time/format/DateTimeFormatter;

    .line 338
    .line 339
    invoke-virtual {v3, v7}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v3

    .line 343
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    invoke-direct {v6, v10, v3}, Lb90/j;-><init>(Lb90/p;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    move-object v10, v6

    .line 350
    goto :goto_d

    .line 351
    :cond_13
    move-object v10, v4

    .line 352
    :goto_d
    iget-object v3, v0, La90/p;->e:La90/n;

    .line 353
    .line 354
    invoke-virtual {v3}, La90/n;->invoke()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v3

    .line 358
    check-cast v3, Ljava/time/LocalTime;

    .line 359
    .line 360
    iget-object v6, v1, Lb90/f;->b:Ljava/util/ArrayList;

    .line 361
    .line 362
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 363
    .line 364
    .line 365
    move-result-object v6

    .line 366
    :cond_14
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 367
    .line 368
    .line 369
    move-result v7

    .line 370
    if-eqz v7, :cond_15

    .line 371
    .line 372
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v7

    .line 376
    move-object v11, v7

    .line 377
    check-cast v11, Lb90/p;

    .line 378
    .line 379
    iget-object v11, v11, Lb90/p;->b:Lb90/q;

    .line 380
    .line 381
    sget-object v12, Lb90/q;->s:Lb90/q;

    .line 382
    .line 383
    if-ne v11, v12, :cond_14

    .line 384
    .line 385
    goto :goto_e

    .line 386
    :cond_15
    move-object v7, v4

    .line 387
    :goto_e
    check-cast v7, Lb90/p;

    .line 388
    .line 389
    if-eqz v7, :cond_16

    .line 390
    .line 391
    iget-object v6, v7, Lb90/p;->a:Ljava/lang/String;

    .line 392
    .line 393
    move-object v12, v6

    .line 394
    goto :goto_f

    .line 395
    :cond_16
    move-object v12, v4

    .line 396
    :goto_f
    if-eqz v3, :cond_17

    .line 397
    .line 398
    if-eqz v12, :cond_17

    .line 399
    .line 400
    new-instance v6, Lb90/j;

    .line 401
    .line 402
    new-instance v11, Lb90/p;

    .line 403
    .line 404
    sget-object v13, Lb90/q;->s:Lb90/q;

    .line 405
    .line 406
    const/16 v16, 0x0

    .line 407
    .line 408
    const/4 v15, 0x0

    .line 409
    const/4 v14, 0x0

    .line 410
    invoke-direct/range {v11 .. v16}, Lb90/p;-><init>(Ljava/lang/String;Lb90/q;ZLjava/lang/String;Ljava/util/ArrayList;)V

    .line 411
    .line 412
    .line 413
    const-string v7, "HH:mm"

    .line 414
    .line 415
    invoke-static {v7}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 416
    .line 417
    .line 418
    move-result-object v7

    .line 419
    invoke-virtual {v3, v7}, Ljava/time/LocalTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v3

    .line 423
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    invoke-direct {v6, v11, v3}, Lb90/j;-><init>(Lb90/p;Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    move-object v11, v6

    .line 430
    goto :goto_10

    .line 431
    :cond_17
    move-object v11, v4

    .line 432
    :goto_10
    iget-object v0, v0, La90/p;->f:La90/h;

    .line 433
    .line 434
    invoke-virtual {v0}, La90/h;->invoke()Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    move-object v12, v0

    .line 439
    check-cast v12, Lb90/a;

    .line 440
    .line 441
    iget-object v0, v1, Lb90/f;->b:Ljava/util/ArrayList;

    .line 442
    .line 443
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 444
    .line 445
    .line 446
    move-result-object v0

    .line 447
    :cond_18
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 448
    .line 449
    .line 450
    move-result v1

    .line 451
    if-eqz v1, :cond_19

    .line 452
    .line 453
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    move-object v3, v1

    .line 458
    check-cast v3, Lb90/p;

    .line 459
    .line 460
    iget-object v3, v3, Lb90/p;->b:Lb90/q;

    .line 461
    .line 462
    sget-object v5, Lb90/q;->q:Lb90/q;

    .line 463
    .line 464
    if-ne v3, v5, :cond_18

    .line 465
    .line 466
    goto :goto_11

    .line 467
    :cond_19
    move-object v1, v4

    .line 468
    :goto_11
    check-cast v1, Lb90/p;

    .line 469
    .line 470
    if-eqz v1, :cond_1a

    .line 471
    .line 472
    iget-object v0, v1, Lb90/p;->a:Ljava/lang/String;

    .line 473
    .line 474
    move-object v14, v0

    .line 475
    goto :goto_12

    .line 476
    :cond_1a
    move-object v14, v4

    .line 477
    :goto_12
    if-eqz v2, :cond_1c

    .line 478
    .line 479
    invoke-static {v2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 480
    .line 481
    .line 482
    move-result v0

    .line 483
    if-eqz v0, :cond_1b

    .line 484
    .line 485
    goto :goto_13

    .line 486
    :cond_1b
    if-eqz v14, :cond_1c

    .line 487
    .line 488
    new-instance v4, Lb90/j;

    .line 489
    .line 490
    new-instance v13, Lb90/p;

    .line 491
    .line 492
    sget-object v15, Lb90/q;->q:Lb90/q;

    .line 493
    .line 494
    const/16 v18, 0x0

    .line 495
    .line 496
    const/16 v17, 0x0

    .line 497
    .line 498
    const/16 v16, 0x0

    .line 499
    .line 500
    invoke-direct/range {v13 .. v18}, Lb90/p;-><init>(Ljava/lang/String;Lb90/q;ZLjava/lang/String;Ljava/util/ArrayList;)V

    .line 501
    .line 502
    .line 503
    invoke-direct {v4, v13, v2}, Lb90/j;-><init>(Lb90/p;Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    :cond_1c
    :goto_13
    move-object v13, v4

    .line 507
    new-instance v0, Lne0/e;

    .line 508
    .line 509
    new-instance v7, Lb90/r;

    .line 510
    .line 511
    invoke-direct/range {v7 .. v13}, Lb90/r;-><init>(Lb90/j;Lb90/j;Lb90/j;Lb90/j;Lb90/a;Lb90/j;)V

    .line 512
    .line 513
    .line 514
    invoke-direct {v0, v7}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    return-object v0
.end method
