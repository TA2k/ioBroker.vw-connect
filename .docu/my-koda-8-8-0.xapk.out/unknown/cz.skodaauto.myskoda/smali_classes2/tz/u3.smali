.class public final synthetic Ltz/u3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/m4;


# direct methods
.method public synthetic constructor <init>(Ltz/m4;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltz/u3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/u3;->e:Ltz/m4;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 10

    .line 1
    iget v0, p0, Ltz/u3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onCapabilities(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Ltz/m4;

    .line 13
    .line 14
    iget-object v5, p0, Ltz/u3;->e:Ltz/m4;

    .line 15
    .line 16
    const-string v6, "onCapabilities"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onCertificatesData(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Ltz/m4;

    .line 29
    .line 30
    iget-object v6, p0, Ltz/u3;->e:Ltz/m4;

    .line 31
    .line 32
    const-string v7, "onCertificatesData"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    :pswitch_1
    new-instance v3, Lkotlin/jvm/internal/a;

    .line 39
    .line 40
    const-string v9, "onUserConsent(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 41
    .line 42
    const/4 v5, 0x4

    .line 43
    const/4 v4, 0x2

    .line 44
    const-class v6, Ltz/m4;

    .line 45
    .line 46
    iget-object v7, p0, Ltz/u3;->e:Ltz/m4;

    .line 47
    .line 48
    const-string v8, "onUserConsent"

    .line 49
    .line 50
    invoke-direct/range {v3 .. v9}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object v3

    .line 54
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltz/u3;->d:I

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v6, 0x0

    .line 13
    iget-object v0, v0, Ltz/u3;->e:Ltz/m4;

    .line 14
    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    move-object/from16 v1, p1

    .line 19
    .line 20
    check-cast v1, Lne0/s;

    .line 21
    .line 22
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    move-object v8, v7

    .line 27
    check-cast v8, Ltz/k4;

    .line 28
    .line 29
    instance-of v7, v1, Lne0/e;

    .line 30
    .line 31
    if-eqz v7, :cond_0

    .line 32
    .line 33
    check-cast v1, Lne0/e;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object v1, v4

    .line 37
    :goto_0
    if-eqz v1, :cond_1

    .line 38
    .line 39
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lss0/b;

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move-object v1, v4

    .line 45
    :goto_1
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object v3, v8, Ltz/k4;->g:Ljava/util/List;

    .line 49
    .line 50
    check-cast v3, Ljava/lang/Iterable;

    .line 51
    .line 52
    new-instance v15, Ljava/util/ArrayList;

    .line 53
    .line 54
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-direct {v15, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_4

    .line 70
    .line 71
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    check-cast v3, Ltz/i4;

    .line 76
    .line 77
    instance-of v7, v3, Ltz/g4;

    .line 78
    .line 79
    if-eqz v7, :cond_3

    .line 80
    .line 81
    check-cast v3, Ltz/g4;

    .line 82
    .line 83
    if-eqz v1, :cond_2

    .line 84
    .line 85
    sget-object v7, Lss0/e;->w1:Lss0/e;

    .line 86
    .line 87
    invoke-static {v1, v7}, Llp/pf;->g(Lss0/b;Lss0/e;)Z

    .line 88
    .line 89
    .line 90
    move-result v7

    .line 91
    goto :goto_3

    .line 92
    :cond_2
    move v7, v6

    .line 93
    :goto_3
    const/4 v9, 0x5

    .line 94
    invoke-static {v3, v7, v4, v9}, Ltz/g4;->a(Ltz/g4;ZLjava/lang/String;I)Ltz/g4;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    :cond_3
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_4
    const/16 v16, 0x3f

    .line 103
    .line 104
    const/4 v9, 0x0

    .line 105
    const/4 v10, 0x0

    .line 106
    const/4 v11, 0x0

    .line 107
    const/4 v12, 0x0

    .line 108
    const/4 v13, 0x0

    .line 109
    const/4 v14, 0x0

    .line 110
    invoke-static/range {v8 .. v16}, Ltz/k4;->a(Ltz/k4;ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;I)Ltz/k4;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 115
    .line 116
    .line 117
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    return-object v5

    .line 120
    :pswitch_0
    move-object/from16 v1, p1

    .line 121
    .line 122
    check-cast v1, Lne0/s;

    .line 123
    .line 124
    iget-object v7, v0, Ltz/m4;->p:Lij0/a;

    .line 125
    .line 126
    instance-of v8, v1, Lne0/e;

    .line 127
    .line 128
    if-eqz v8, :cond_5

    .line 129
    .line 130
    check-cast v1, Lne0/e;

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_5
    move-object v1, v4

    .line 134
    :goto_4
    if-eqz v1, :cond_8

    .line 135
    .line 136
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v1, Ljava/util/List;

    .line 139
    .line 140
    if-eqz v1, :cond_8

    .line 141
    .line 142
    check-cast v1, Ljava/lang/Iterable;

    .line 143
    .line 144
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    :cond_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    if-eqz v8, :cond_7

    .line 153
    .line 154
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v8

    .line 158
    move-object v9, v8

    .line 159
    check-cast v9, Lrd0/d;

    .line 160
    .line 161
    iget-object v9, v9, Lrd0/d;->b:Lrd0/e;

    .line 162
    .line 163
    sget-object v10, Lrd0/e;->d:Lrd0/e;

    .line 164
    .line 165
    if-ne v9, v10, :cond_6

    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_7
    move-object v8, v4

    .line 169
    :goto_5
    check-cast v8, Lrd0/d;

    .line 170
    .line 171
    if-eqz v8, :cond_8

    .line 172
    .line 173
    iget-object v4, v8, Lrd0/d;->c:Lrd0/f;

    .line 174
    .line 175
    :cond_8
    const/4 v1, 0x3

    .line 176
    const v8, 0x7f1201aa

    .line 177
    .line 178
    .line 179
    const-string v9, "stringResource"

    .line 180
    .line 181
    if-eqz v4, :cond_b

    .line 182
    .line 183
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 184
    .line 185
    .line 186
    move-result-object v10

    .line 187
    move-object v11, v10

    .line 188
    check-cast v11, Ltz/k4;

    .line 189
    .line 190
    invoke-static {v11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    iget-object v3, v11, Ltz/k4;->g:Ljava/util/List;

    .line 197
    .line 198
    check-cast v3, Ljava/lang/Iterable;

    .line 199
    .line 200
    new-instance v9, Ljava/util/ArrayList;

    .line 201
    .line 202
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 203
    .line 204
    .line 205
    move-result v2

    .line 206
    invoke-direct {v9, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 207
    .line 208
    .line 209
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 214
    .line 215
    .line 216
    move-result v3

    .line 217
    if-eqz v3, :cond_a

    .line 218
    .line 219
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    check-cast v3, Ltz/i4;

    .line 224
    .line 225
    instance-of v10, v3, Ltz/g4;

    .line 226
    .line 227
    if-eqz v10, :cond_9

    .line 228
    .line 229
    check-cast v3, Ltz/g4;

    .line 230
    .line 231
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 232
    .line 233
    .line 234
    move-result v10

    .line 235
    packed-switch v10, :pswitch_data_1

    .line 236
    .line 237
    .line 238
    new-instance v0, La8/r0;

    .line 239
    .line 240
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 241
    .line 242
    .line 243
    throw v0

    .line 244
    :pswitch_1
    move v10, v8

    .line 245
    goto :goto_7

    .line 246
    :pswitch_2
    const v10, 0x7f12040b

    .line 247
    .line 248
    .line 249
    goto :goto_7

    .line 250
    :pswitch_3
    const v10, 0x7f12040c

    .line 251
    .line 252
    .line 253
    :goto_7
    new-array v12, v6, [Ljava/lang/Object;

    .line 254
    .line 255
    move-object v13, v7

    .line 256
    check-cast v13, Ljj0/f;

    .line 257
    .line 258
    invoke-virtual {v13, v10, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v10

    .line 262
    invoke-static {v3, v6, v10, v1}, Ltz/g4;->a(Ltz/g4;ZLjava/lang/String;I)Ltz/g4;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    :cond_9
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    goto :goto_6

    .line 270
    :cond_a
    const/16 v19, 0x3f

    .line 271
    .line 272
    const/4 v12, 0x0

    .line 273
    const/4 v13, 0x0

    .line 274
    const/4 v14, 0x0

    .line 275
    const/4 v15, 0x0

    .line 276
    const/16 v16, 0x0

    .line 277
    .line 278
    const/16 v17, 0x0

    .line 279
    .line 280
    move-object/from16 v18, v9

    .line 281
    .line 282
    invoke-static/range {v11 .. v19}, Ltz/k4;->a(Ltz/k4;ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;I)Ltz/k4;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    goto :goto_9

    .line 287
    :cond_b
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    move-object v10, v4

    .line 292
    check-cast v10, Ltz/k4;

    .line 293
    .line 294
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    iget-object v3, v10, Ltz/k4;->g:Ljava/util/List;

    .line 301
    .line 302
    check-cast v3, Ljava/lang/Iterable;

    .line 303
    .line 304
    new-instance v4, Ljava/util/ArrayList;

    .line 305
    .line 306
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 307
    .line 308
    .line 309
    move-result v2

    .line 310
    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 311
    .line 312
    .line 313
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 318
    .line 319
    .line 320
    move-result v3

    .line 321
    if-eqz v3, :cond_d

    .line 322
    .line 323
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v3

    .line 327
    check-cast v3, Ltz/i4;

    .line 328
    .line 329
    instance-of v9, v3, Ltz/g4;

    .line 330
    .line 331
    if-eqz v9, :cond_c

    .line 332
    .line 333
    check-cast v3, Ltz/g4;

    .line 334
    .line 335
    new-array v9, v6, [Ljava/lang/Object;

    .line 336
    .line 337
    move-object v11, v7

    .line 338
    check-cast v11, Ljj0/f;

    .line 339
    .line 340
    invoke-virtual {v11, v8, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v9

    .line 344
    invoke-static {v3, v6, v9, v1}, Ltz/g4;->a(Ltz/g4;ZLjava/lang/String;I)Ltz/g4;

    .line 345
    .line 346
    .line 347
    move-result-object v3

    .line 348
    :cond_c
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    goto :goto_8

    .line 352
    :cond_d
    const/16 v18, 0x3f

    .line 353
    .line 354
    const/4 v11, 0x0

    .line 355
    const/4 v12, 0x0

    .line 356
    const/4 v13, 0x0

    .line 357
    const/4 v14, 0x0

    .line 358
    const/4 v15, 0x0

    .line 359
    const/16 v16, 0x0

    .line 360
    .line 361
    move-object/from16 v17, v4

    .line 362
    .line 363
    invoke-static/range {v10 .. v18}, Ltz/k4;->a(Ltz/k4;ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;I)Ltz/k4;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    :goto_9
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 368
    .line 369
    .line 370
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 371
    .line 372
    return-object v5

    .line 373
    :pswitch_4
    move-object/from16 v1, p1

    .line 374
    .line 375
    check-cast v1, Lne0/s;

    .line 376
    .line 377
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 378
    .line 379
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 380
    .line 381
    .line 382
    move-result v2

    .line 383
    if-eqz v2, :cond_e

    .line 384
    .line 385
    goto :goto_b

    .line 386
    :cond_e
    instance-of v2, v1, Lne0/c;

    .line 387
    .line 388
    const/4 v3, 0x1

    .line 389
    if-eqz v2, :cond_f

    .line 390
    .line 391
    move v6, v3

    .line 392
    goto :goto_b

    .line 393
    :cond_f
    instance-of v2, v1, Lne0/e;

    .line 394
    .line 395
    if-eqz v2, :cond_12

    .line 396
    .line 397
    check-cast v1, Lne0/e;

    .line 398
    .line 399
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast v1, Lto0/u;

    .line 402
    .line 403
    iget-object v1, v1, Lto0/u;->a:Lto0/t;

    .line 404
    .line 405
    sget-object v2, Lto0/t;->f:Lto0/t;

    .line 406
    .line 407
    if-eq v1, v2, :cond_10

    .line 408
    .line 409
    move v8, v3

    .line 410
    goto :goto_a

    .line 411
    :cond_10
    move v8, v6

    .line 412
    :goto_a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    move-object v7, v1

    .line 417
    check-cast v7, Ltz/k4;

    .line 418
    .line 419
    const/4 v14, 0x0

    .line 420
    const/16 v15, 0x7e

    .line 421
    .line 422
    const/4 v9, 0x0

    .line 423
    const/4 v10, 0x0

    .line 424
    const/4 v11, 0x0

    .line 425
    const/4 v12, 0x0

    .line 426
    const/4 v13, 0x0

    .line 427
    invoke-static/range {v7 .. v15}, Ltz/k4;->a(Ltz/k4;ZZZZLtz/h4;Ljava/util/List;Ljava/util/List;I)Ltz/k4;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 432
    .line 433
    .line 434
    move v6, v8

    .line 435
    :goto_b
    if-eqz v6, :cond_11

    .line 436
    .line 437
    iget-object v0, v0, Ltz/m4;->i:Lrz/c0;

    .line 438
    .line 439
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    :cond_11
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 443
    .line 444
    return-object v5

    .line 445
    :cond_12
    new-instance v0, La8/r0;

    .line 446
    .line 447
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 448
    .line 449
    .line 450
    throw v0

    .line 451
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_0
    .end packed-switch

    .line 452
    .line 453
    .line 454
    .line 455
    .line 456
    .line 457
    .line 458
    .line 459
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Ltz/u3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    :pswitch_1
    instance-of v0, p1, Lyy0/j;

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 60
    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 68
    .line 69
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    :cond_2
    return v1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Ltz/u3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
