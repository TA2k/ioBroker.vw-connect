.class public final Lf50/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/m0;

.field public final b:Lbh0/f;

.field public final c:Lf50/r;


# direct methods
.method public constructor <init>(Lpp0/m0;Lbh0/f;Lf50/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/t;->a:Lpp0/m0;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/t;->b:Lbh0/f;

    .line 7
    .line 8
    iput-object p3, p0, Lf50/t;->c:Lf50/r;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ldh0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lf50/t;->b(Ldh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ldh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lf50/s;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lf50/s;

    .line 11
    .line 12
    iget v3, v2, Lf50/s;->g:I

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
    iput v3, v2, Lf50/s;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lf50/s;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lf50/s;-><init>(Lf50/t;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lf50/s;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lf50/s;->g:I

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x1

    .line 37
    const/4 v7, 0x2

    .line 38
    if-eqz v4, :cond_4

    .line 39
    .line 40
    if-eq v4, v6, :cond_3

    .line 41
    .line 42
    if-eq v4, v7, :cond_2

    .line 43
    .line 44
    if-ne v4, v5, :cond_1

    .line 45
    .line 46
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v1

    .line 50
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_2
    iget-object v4, v2, Lf50/s;->d:Ldh0/a;

    .line 59
    .line 60
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_4

    .line 64
    .line 65
    :cond_3
    iget-object v4, v2, Lf50/s;->d:Ldh0/a;

    .line 66
    .line 67
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-object v1, v0, Lf50/t;->a:Lpp0/m0;

    .line 75
    .line 76
    invoke-virtual {v1}, Lpp0/m0;->invoke()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    check-cast v1, Lyy0/i;

    .line 81
    .line 82
    move-object/from16 v4, p1

    .line 83
    .line 84
    iput-object v4, v2, Lf50/s;->d:Ldh0/a;

    .line 85
    .line 86
    iput v6, v2, Lf50/s;->g:I

    .line 87
    .line 88
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-ne v1, v3, :cond_5

    .line 93
    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :cond_5
    :goto_1
    check-cast v1, Lqp0/o;

    .line 97
    .line 98
    if-eqz v1, :cond_7

    .line 99
    .line 100
    iget-object v1, v1, Lqp0/o;->a:Ljava/util/List;

    .line 101
    .line 102
    if-eqz v1, :cond_7

    .line 103
    .line 104
    check-cast v1, Ljava/lang/Iterable;

    .line 105
    .line 106
    new-instance v9, Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 109
    .line 110
    .line 111
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    :cond_6
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 116
    .line 117
    .line 118
    move-result v10

    .line 119
    if-eqz v10, :cond_8

    .line 120
    .line 121
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    check-cast v10, Lqp0/b0;

    .line 126
    .line 127
    iget-object v10, v10, Lqp0/b0;->d:Lxj0/f;

    .line 128
    .line 129
    if-eqz v10, :cond_6

    .line 130
    .line 131
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_7
    const/4 v9, 0x0

    .line 136
    :cond_8
    if-eqz v9, :cond_12

    .line 137
    .line 138
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-ge v1, v7, :cond_9

    .line 143
    .line 144
    goto/16 :goto_6

    .line 145
    .line 146
    :cond_9
    iput-object v4, v2, Lf50/s;->d:Ldh0/a;

    .line 147
    .line 148
    iput v7, v2, Lf50/s;->g:I

    .line 149
    .line 150
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    const/4 v10, 0x4

    .line 155
    if-eq v1, v5, :cond_c

    .line 156
    .line 157
    if-eq v1, v10, :cond_b

    .line 158
    .line 159
    const/4 v6, 0x5

    .line 160
    if-eq v1, v6, :cond_a

    .line 161
    .line 162
    new-instance v10, Lne0/c;

    .line 163
    .line 164
    new-instance v11, Ljava/lang/IllegalArgumentException;

    .line 165
    .line 166
    new-instance v1, Ljava/lang/StringBuilder;

    .line 167
    .line 168
    const-string v6, "Unsupported app for route sharing "

    .line 169
    .line 170
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    invoke-direct {v11, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    const/4 v14, 0x0

    .line 184
    const/16 v15, 0x1e

    .line 185
    .line 186
    const/4 v12, 0x0

    .line 187
    const/4 v13, 0x0

    .line 188
    invoke-direct/range {v10 .. v15}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 189
    .line 190
    .line 191
    move-object v1, v10

    .line 192
    goto/16 :goto_3

    .line 193
    .line 194
    :cond_a
    new-instance v1, Lne0/e;

    .line 195
    .line 196
    invoke-static {v9}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    check-cast v6, Lxj0/f;

    .line 201
    .line 202
    iget-wide v10, v6, Lxj0/f;->a:D

    .line 203
    .line 204
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    invoke-static {v9}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v9

    .line 212
    check-cast v9, Lxj0/f;

    .line 213
    .line 214
    iget-wide v9, v9, Lxj0/f;->b:D

    .line 215
    .line 216
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 217
    .line 218
    .line 219
    move-result-object v9

    .line 220
    filled-new-array {v6, v9}, [Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v6

    .line 224
    invoke-static {v6, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v6

    .line 228
    const-string v7, "https://waze.com/ul?ll=%s,%s&navigate=yes"

    .line 229
    .line 230
    invoke-static {v7, v6}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v6

    .line 234
    invoke-direct {v1, v6}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    goto/16 :goto_3

    .line 238
    .line 239
    :cond_b
    iget-object v1, v0, Lf50/t;->c:Lf50/r;

    .line 240
    .line 241
    check-cast v1, Ld50/a;

    .line 242
    .line 243
    iget-object v6, v1, Ld50/a;->a:Lyy0/q1;

    .line 244
    .line 245
    invoke-virtual {v6, v9}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    iget-object v1, v1, Ld50/a;->c:Lyy0/q1;

    .line 249
    .line 250
    invoke-static {v1, v2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    goto :goto_3

    .line 255
    :cond_c
    new-instance v1, Lne0/e;

    .line 256
    .line 257
    new-instance v11, Ljava/lang/StringBuilder;

    .line 258
    .line 259
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 260
    .line 261
    .line 262
    invoke-static {v9}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v12

    .line 266
    check-cast v12, Lxj0/f;

    .line 267
    .line 268
    invoke-static {v9}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v13

    .line 272
    check-cast v13, Lxj0/f;

    .line 273
    .line 274
    iget-wide v14, v12, Lxj0/f;->a:D

    .line 275
    .line 276
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v14

    .line 280
    move v15, v6

    .line 281
    iget-wide v5, v12, Lxj0/f;->b:D

    .line 282
    .line 283
    invoke-static {v5, v6}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v5

    .line 287
    move-object/from16 p1, v9

    .line 288
    .line 289
    iget-wide v8, v13, Lxj0/f;->a:D

    .line 290
    .line 291
    invoke-static {v8, v9}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v8

    .line 295
    iget-wide v12, v13, Lxj0/f;->b:D

    .line 296
    .line 297
    invoke-static {v12, v13}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v9

    .line 301
    filled-new-array {v14, v5, v8, v9}, [Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v5

    .line 305
    invoke-static {v5, v10}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    const-string v8, "https://www.google.com/maps/dir/?api=1&origin=%s,%s&destination=%s,%s"

    .line 310
    .line 311
    invoke-static {v8, v5}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v5

    .line 315
    invoke-virtual {v11, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-interface/range {p1 .. p1}, Ljava/util/List;->size()I

    .line 319
    .line 320
    .line 321
    move-result v5

    .line 322
    if-le v5, v7, :cond_d

    .line 323
    .line 324
    invoke-interface/range {p1 .. p1}, Ljava/util/List;->size()I

    .line 325
    .line 326
    .line 327
    move-result v5

    .line 328
    sub-int/2addr v5, v15

    .line 329
    move-object/from16 v8, p1

    .line 330
    .line 331
    invoke-interface {v8, v15, v5}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 332
    .line 333
    .line 334
    move-result-object v5

    .line 335
    move-object v12, v5

    .line 336
    check-cast v12, Ljava/lang/Iterable;

    .line 337
    .line 338
    new-instance v5, Lf31/n;

    .line 339
    .line 340
    const/4 v7, 0x1

    .line 341
    invoke-direct {v5, v7}, Lf31/n;-><init>(I)V

    .line 342
    .line 343
    .line 344
    const/16 v17, 0x1c

    .line 345
    .line 346
    const-string v13, "|"

    .line 347
    .line 348
    const-string v14, "&waypoints="

    .line 349
    .line 350
    const/4 v15, 0x0

    .line 351
    move-object/from16 v16, v5

    .line 352
    .line 353
    invoke-static/range {v12 .. v17}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object v5

    .line 357
    invoke-virtual {v11, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    :cond_d
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v5

    .line 364
    invoke-direct {v1, v5}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 365
    .line 366
    .line 367
    :goto_3
    if-ne v1, v3, :cond_e

    .line 368
    .line 369
    goto :goto_5

    .line 370
    :cond_e
    :goto_4
    check-cast v1, Lne0/t;

    .line 371
    .line 372
    instance-of v5, v1, Lne0/c;

    .line 373
    .line 374
    if-eqz v5, :cond_f

    .line 375
    .line 376
    return-object v1

    .line 377
    :cond_f
    instance-of v5, v1, Lne0/e;

    .line 378
    .line 379
    if-eqz v5, :cond_11

    .line 380
    .line 381
    new-instance v5, Ldh0/b;

    .line 382
    .line 383
    check-cast v1, Lne0/e;

    .line 384
    .line 385
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 386
    .line 387
    check-cast v1, Ljava/lang/String;

    .line 388
    .line 389
    invoke-direct {v5, v4, v1}, Ldh0/b;-><init>(Ldh0/a;Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    const/4 v6, 0x0

    .line 393
    iput-object v6, v2, Lf50/s;->d:Ldh0/a;

    .line 394
    .line 395
    const/4 v1, 0x3

    .line 396
    iput v1, v2, Lf50/s;->g:I

    .line 397
    .line 398
    iget-object v0, v0, Lf50/t;->b:Lbh0/f;

    .line 399
    .line 400
    invoke-virtual {v0, v5, v2}, Lbh0/f;->b(Ldh0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    if-ne v0, v3, :cond_10

    .line 405
    .line 406
    :goto_5
    return-object v3

    .line 407
    :cond_10
    return-object v0

    .line 408
    :cond_11
    new-instance v0, La8/r0;

    .line 409
    .line 410
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 411
    .line 412
    .line 413
    throw v0

    .line 414
    :cond_12
    :goto_6
    new-instance v1, Lne0/c;

    .line 415
    .line 416
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 417
    .line 418
    const-string v0, "Invalid route"

    .line 419
    .line 420
    invoke-direct {v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    const/4 v5, 0x0

    .line 424
    const/16 v6, 0x1e

    .line 425
    .line 426
    const/4 v3, 0x0

    .line 427
    const/4 v4, 0x0

    .line 428
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 429
    .line 430
    .line 431
    return-object v1
.end method
