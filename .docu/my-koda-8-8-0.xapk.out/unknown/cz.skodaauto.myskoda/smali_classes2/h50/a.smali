.class public final Lh50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh50/d;


# direct methods
.method public synthetic constructor <init>(Lh50/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh50/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh50/a;->e:Lh50/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh50/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    instance-of v2, v1, Lne0/d;

    .line 13
    .line 14
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    iget-object v0, v0, Lh50/a;->e:Lh50/d;

    .line 17
    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v4, v1

    .line 25
    check-cast v4, Lh50/c;

    .line 26
    .line 27
    const/4 v9, 0x1

    .line 28
    const/16 v10, 0xf

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v7, 0x0

    .line 33
    const/4 v8, 0x0

    .line 34
    invoke-static/range {v4 .. v10}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    instance-of v2, v1, Lne0/e;

    .line 43
    .line 44
    if-eqz v2, :cond_1

    .line 45
    .line 46
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    move-object v4, v1

    .line 51
    check-cast v4, Lh50/c;

    .line 52
    .line 53
    const/4 v9, 0x0

    .line 54
    const/16 v10, 0xf

    .line 55
    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x0

    .line 58
    const/4 v7, 0x0

    .line 59
    const/4 v8, 0x0

    .line 60
    invoke-static/range {v4 .. v10}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    iget-object v0, v0, Lh50/d;->h:Ltr0/b;

    .line 68
    .line 69
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    instance-of v2, v1, Lne0/c;

    .line 74
    .line 75
    if-eqz v2, :cond_3

    .line 76
    .line 77
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    move-object v4, v2

    .line 82
    check-cast v4, Lh50/c;

    .line 83
    .line 84
    const/4 v9, 0x0

    .line 85
    const/16 v10, 0xf

    .line 86
    .line 87
    const/4 v5, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    const/4 v8, 0x0

    .line 91
    invoke-static/range {v4 .. v10}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 96
    .line 97
    .line 98
    iget-object v0, v0, Lh50/d;->l:Lrq0/d;

    .line 99
    .line 100
    new-instance v2, Lsq0/b;

    .line 101
    .line 102
    check-cast v1, Lne0/c;

    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    const/4 v5, 0x6

    .line 106
    invoke-direct {v2, v1, v4, v5}, Lsq0/b;-><init>(Lne0/c;Ljava/lang/String;I)V

    .line 107
    .line 108
    .line 109
    move-object/from16 v1, p2

    .line 110
    .line 111
    invoke-virtual {v0, v2, v1}, Lrq0/d;->b(Lsq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 116
    .line 117
    if-ne v0, v1, :cond_2

    .line 118
    .line 119
    move-object v3, v0

    .line 120
    :cond_2
    :goto_0
    return-object v3

    .line 121
    :cond_3
    new-instance v0, La8/r0;

    .line 122
    .line 123
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 124
    .line 125
    .line 126
    throw v0

    .line 127
    :pswitch_0
    move-object/from16 v1, p1

    .line 128
    .line 129
    check-cast v1, Lne0/s;

    .line 130
    .line 131
    instance-of v2, v1, Lne0/e;

    .line 132
    .line 133
    if-eqz v2, :cond_4

    .line 134
    .line 135
    check-cast v1, Lne0/e;

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_4
    const/4 v1, 0x0

    .line 139
    :goto_1
    if-eqz v1, :cond_f

    .line 140
    .line 141
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v1, Lqp0/m;

    .line 144
    .line 145
    if-eqz v1, :cond_f

    .line 146
    .line 147
    iget-object v2, v1, Lqp0/m;->b:Ljava/util/ArrayList;

    .line 148
    .line 149
    iget-object v0, v0, Lh50/a;->e:Lh50/d;

    .line 150
    .line 151
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    iget-object v5, v0, Lh50/d;->j:Lij0/a;

    .line 156
    .line 157
    move-object v6, v4

    .line 158
    check-cast v6, Lh50/c;

    .line 159
    .line 160
    iget-object v7, v1, Lqp0/m;->a:Ljava/util/UUID;

    .line 161
    .line 162
    const/4 v1, 0x0

    .line 163
    new-array v4, v1, [Ljava/lang/Object;

    .line 164
    .line 165
    move-object v8, v5

    .line 166
    check-cast v8, Ljj0/f;

    .line 167
    .line 168
    const v9, 0x7f1205d4

    .line 169
    .line 170
    .line 171
    invoke-virtual {v8, v9, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    new-instance v8, Lh50/v0;

    .line 176
    .line 177
    const/16 v9, 0x41

    .line 178
    .line 179
    invoke-direct {v8, v9}, Lh50/v0;-><init>(C)V

    .line 180
    .line 181
    .line 182
    new-instance v9, Lh50/i;

    .line 183
    .line 184
    const/4 v10, 0x1

    .line 185
    invoke-direct {v9, v4, v10, v8}, Lh50/i;-><init>(Ljava/lang/String;ZLh50/w0;)V

    .line 186
    .line 187
    .line 188
    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    check-cast v4, Ljava/util/Collection;

    .line 193
    .line 194
    new-instance v8, Ljava/util/ArrayList;

    .line 195
    .line 196
    const/16 v9, 0xa

    .line 197
    .line 198
    invoke-static {v2, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 199
    .line 200
    .line 201
    move-result v9

    .line 202
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 203
    .line 204
    .line 205
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 206
    .line 207
    .line 208
    move-result-object v9

    .line 209
    move v11, v1

    .line 210
    :goto_2
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 211
    .line 212
    .line 213
    move-result v12

    .line 214
    if-eqz v12, :cond_a

    .line 215
    .line 216
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v12

    .line 220
    add-int/lit8 v13, v11, 0x1

    .line 221
    .line 222
    if-ltz v11, :cond_9

    .line 223
    .line 224
    check-cast v12, Lqp0/i;

    .line 225
    .line 226
    const-string v11, "<this>"

    .line 227
    .line 228
    invoke-static {v12, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    iget-object v11, v12, Lqp0/i;->a:Lqp0/j;

    .line 232
    .line 233
    sget-object v14, Lh50/x0;->b:[I

    .line 234
    .line 235
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 236
    .line 237
    .line 238
    move-result v11

    .line 239
    aget v11, v14, v11

    .line 240
    .line 241
    if-ne v11, v10, :cond_5

    .line 242
    .line 243
    new-instance v11, Lh50/u0;

    .line 244
    .line 245
    const v14, 0x7f0802dc

    .line 246
    .line 247
    .line 248
    invoke-direct {v11, v14}, Lh50/u0;-><init>(I)V

    .line 249
    .line 250
    .line 251
    move/from16 p0, v10

    .line 252
    .line 253
    const/16 p1, 0x0

    .line 254
    .line 255
    goto :goto_4

    .line 256
    :cond_5
    invoke-static {v2, v13}, Lmx0/q;->q0(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 257
    .line 258
    .line 259
    move-result-object v11

    .line 260
    check-cast v11, Ljava/lang/Iterable;

    .line 261
    .line 262
    new-instance v14, Ljava/util/ArrayList;

    .line 263
    .line 264
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 265
    .line 266
    .line 267
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 268
    .line 269
    .line 270
    move-result-object v11

    .line 271
    :goto_3
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 272
    .line 273
    .line 274
    move-result v15

    .line 275
    if-eqz v15, :cond_7

    .line 276
    .line 277
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v15

    .line 281
    const/16 p1, 0x0

    .line 282
    .line 283
    move-object v3, v15

    .line 284
    check-cast v3, Lqp0/i;

    .line 285
    .line 286
    iget-object v3, v3, Lqp0/i;->a:Lqp0/j;

    .line 287
    .line 288
    move/from16 p0, v10

    .line 289
    .line 290
    sget-object v10, Lqp0/j;->e:Lqp0/j;

    .line 291
    .line 292
    if-eq v3, v10, :cond_6

    .line 293
    .line 294
    invoke-virtual {v14, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    :cond_6
    move/from16 v10, p0

    .line 298
    .line 299
    goto :goto_3

    .line 300
    :cond_7
    move/from16 p0, v10

    .line 301
    .line 302
    const/16 p1, 0x0

    .line 303
    .line 304
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 305
    .line 306
    .line 307
    move-result v3

    .line 308
    new-instance v11, Lh50/v0;

    .line 309
    .line 310
    add-int/lit8 v3, v3, 0x40

    .line 311
    .line 312
    int-to-char v3, v3

    .line 313
    add-int/lit8 v3, v3, 0x1

    .line 314
    .line 315
    int-to-char v3, v3

    .line 316
    invoke-direct {v11, v3}, Lh50/v0;-><init>(C)V

    .line 317
    .line 318
    .line 319
    :goto_4
    const-string v3, "stringResource"

    .line 320
    .line 321
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    new-instance v3, Lh50/i;

    .line 325
    .line 326
    iget-object v10, v12, Lqp0/i;->c:Ljava/lang/String;

    .line 327
    .line 328
    if-nez v10, :cond_8

    .line 329
    .line 330
    new-array v10, v1, [Ljava/lang/Object;

    .line 331
    .line 332
    move-object v14, v5

    .line 333
    check-cast v14, Ljj0/f;

    .line 334
    .line 335
    const v15, 0x7f1205da

    .line 336
    .line 337
    .line 338
    invoke-virtual {v14, v15, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v10

    .line 342
    :cond_8
    iget-boolean v12, v12, Lqp0/i;->b:Z

    .line 343
    .line 344
    invoke-direct {v3, v10, v12, v11}, Lh50/i;-><init>(Ljava/lang/String;ZLh50/w0;)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v8, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    move/from16 v10, p0

    .line 351
    .line 352
    move v11, v13

    .line 353
    goto/16 :goto_2

    .line 354
    .line 355
    :cond_9
    const/16 p1, 0x0

    .line 356
    .line 357
    invoke-static {}, Ljp/k1;->r()V

    .line 358
    .line 359
    .line 360
    throw p1

    .line 361
    :cond_a
    const/16 p1, 0x0

    .line 362
    .line 363
    invoke-static {v8, v4}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 364
    .line 365
    .line 366
    move-result-object v8

    .line 367
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 368
    .line 369
    .line 370
    move-result v3

    .line 371
    if-eqz v3, :cond_c

    .line 372
    .line 373
    :cond_b
    move v9, v1

    .line 374
    goto :goto_6

    .line 375
    :cond_c
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 376
    .line 377
    .line 378
    move-result-object v2

    .line 379
    :cond_d
    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 380
    .line 381
    .line 382
    move-result v3

    .line 383
    if-eqz v3, :cond_b

    .line 384
    .line 385
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    check-cast v3, Lqp0/i;

    .line 390
    .line 391
    iget-boolean v3, v3, Lqp0/i;->b:Z

    .line 392
    .line 393
    if-nez v3, :cond_d

    .line 394
    .line 395
    add-int/lit8 v1, v1, 0x1

    .line 396
    .line 397
    if-ltz v1, :cond_e

    .line 398
    .line 399
    goto :goto_5

    .line 400
    :cond_e
    invoke-static {}, Ljp/k1;->q()V

    .line 401
    .line 402
    .line 403
    throw p1

    .line 404
    :goto_6
    const/4 v11, 0x0

    .line 405
    const/16 v12, 0x18

    .line 406
    .line 407
    const/4 v10, 0x0

    .line 408
    invoke-static/range {v6 .. v12}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 409
    .line 410
    .line 411
    move-result-object v1

    .line 412
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 413
    .line 414
    .line 415
    :cond_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 416
    .line 417
    return-object v0

    .line 418
    nop

    .line 419
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
