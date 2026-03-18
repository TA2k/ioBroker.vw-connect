.class public final synthetic Lh40/c3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/e3;


# direct methods
.method public synthetic constructor <init>(Lh40/e3;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/c3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/c3;->e:Lh40/e3;

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
    .locals 9

    .line 1
    iget v0, p0, Lh40/c3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    const-string v7, "onApplyPowerpassVoucherData(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Lh40/e3;

    .line 13
    .line 14
    iget-object v5, p0, Lh40/c3;->e:Lh40/e3;

    .line 15
    .line 16
    const-string v6, "onApplyPowerpassVoucherData"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onApplyWebshopVoucherData(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Lh40/e3;

    .line 29
    .line 30
    iget-object v6, p0, Lh40/c3;->e:Lh40/e3;

    .line 31
    .line 32
    const-string v7, "onApplyWebshopVoucherData"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/c3;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    iget-object v0, v0, Lh40/c3;->e:Lh40/e3;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    move-object/from16 v1, p1

    .line 15
    .line 16
    check-cast v1, Lne0/s;

    .line 17
    .line 18
    instance-of v5, v1, Lne0/d;

    .line 19
    .line 20
    if-eqz v5, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    move-object v4, v1

    .line 27
    check-cast v4, Lh40/a3;

    .line 28
    .line 29
    const/4 v12, 0x0

    .line 30
    const/16 v13, 0xfb

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x1

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const/4 v11, 0x0

    .line 39
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    instance-of v5, v1, Lne0/c;

    .line 48
    .line 49
    if-eqz v5, :cond_1

    .line 50
    .line 51
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    move-object v4, v2

    .line 56
    check-cast v4, Lh40/a3;

    .line 57
    .line 58
    check-cast v1, Lne0/c;

    .line 59
    .line 60
    iget-object v2, v0, Lh40/e3;->n:Lij0/a;

    .line 61
    .line 62
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 63
    .line 64
    .line 65
    move-result-object v8

    .line 66
    const/4 v12, 0x0

    .line 67
    const/16 v13, 0xf3

    .line 68
    .line 69
    const/4 v5, 0x0

    .line 70
    const/4 v6, 0x0

    .line 71
    const/4 v7, 0x0

    .line 72
    const/4 v9, 0x0

    .line 73
    const/4 v10, 0x0

    .line 74
    const/4 v11, 0x0

    .line 75
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    instance-of v5, v1, Lne0/e;

    .line 84
    .line 85
    if-eqz v5, :cond_9

    .line 86
    .line 87
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    move-object v6, v5

    .line 92
    check-cast v6, Lh40/a3;

    .line 93
    .line 94
    const/4 v14, 0x0

    .line 95
    const/16 v15, 0xfb

    .line 96
    .line 97
    const/4 v7, 0x0

    .line 98
    const/4 v8, 0x0

    .line 99
    const/4 v9, 0x0

    .line 100
    const/4 v10, 0x0

    .line 101
    const/4 v11, 0x0

    .line 102
    const/4 v12, 0x0

    .line 103
    const/4 v13, 0x0

    .line 104
    invoke-static/range {v6 .. v15}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    invoke-virtual {v0, v5}, Lql0/j;->g(Lql0/h;)V

    .line 109
    .line 110
    .line 111
    check-cast v1, Lne0/e;

    .line 112
    .line 113
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v1, Lg40/c;

    .line 116
    .line 117
    sget-object v5, Lh40/b3;->a:[I

    .line 118
    .line 119
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 120
    .line 121
    .line 122
    move-result v6

    .line 123
    aget v5, v5, v6

    .line 124
    .line 125
    if-ne v5, v4, :cond_3

    .line 126
    .line 127
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    move-object v4, v1

    .line 132
    check-cast v4, Lh40/a3;

    .line 133
    .line 134
    const/4 v12, 0x0

    .line 135
    const/16 v13, 0xef

    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    const/4 v6, 0x0

    .line 139
    const/4 v7, 0x0

    .line 140
    const/4 v8, 0x0

    .line 141
    const/4 v9, 0x1

    .line 142
    const/4 v10, 0x0

    .line 143
    const/4 v11, 0x0

    .line 144
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 149
    .line 150
    .line 151
    :cond_2
    :goto_0
    move-object v0, v3

    .line 152
    goto :goto_3

    .line 153
    :cond_3
    new-instance v5, La90/s;

    .line 154
    .line 155
    const/4 v6, 0x0

    .line 156
    const/16 v7, 0xb

    .line 157
    .line 158
    invoke-direct {v5, v0, v6, v7}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-eqz v1, :cond_7

    .line 166
    .line 167
    if-eq v1, v4, :cond_5

    .line 168
    .line 169
    if-eq v1, v2, :cond_4

    .line 170
    .line 171
    goto :goto_1

    .line 172
    :cond_4
    iget-object v0, v0, Lh40/e3;->q:Lf40/v2;

    .line 173
    .line 174
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    goto :goto_1

    .line 178
    :cond_5
    iget-object v0, v0, Lh40/e3;->p:Lf40/u2;

    .line 179
    .line 180
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    :cond_6
    :goto_1
    move-object v0, v3

    .line 184
    goto :goto_2

    .line 185
    :cond_7
    move-object/from16 v0, p2

    .line 186
    .line 187
    invoke-virtual {v5, v0}, La90/s;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    if-ne v0, v1, :cond_6

    .line 194
    .line 195
    :goto_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 196
    .line 197
    if-ne v0, v1, :cond_2

    .line 198
    .line 199
    :goto_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 200
    .line 201
    if-ne v0, v1, :cond_8

    .line 202
    .line 203
    move-object v3, v0

    .line 204
    :cond_8
    return-object v3

    .line 205
    :cond_9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    new-instance v0, La8/r0;

    .line 209
    .line 210
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 211
    .line 212
    .line 213
    throw v0

    .line 214
    :pswitch_0
    move-object/from16 v1, p1

    .line 215
    .line 216
    check-cast v1, Lne0/s;

    .line 217
    .line 218
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    const-string v5, "data"

    .line 222
    .line 223
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    instance-of v5, v1, Lne0/d;

    .line 227
    .line 228
    if-eqz v5, :cond_a

    .line 229
    .line 230
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    move-object v4, v1

    .line 235
    check-cast v4, Lh40/a3;

    .line 236
    .line 237
    const/4 v12, 0x0

    .line 238
    const/16 v13, 0xfb

    .line 239
    .line 240
    const/4 v5, 0x0

    .line 241
    const/4 v6, 0x0

    .line 242
    const/4 v7, 0x1

    .line 243
    const/4 v8, 0x0

    .line 244
    const/4 v9, 0x0

    .line 245
    const/4 v10, 0x0

    .line 246
    const/4 v11, 0x0

    .line 247
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_4

    .line 255
    .line 256
    :cond_a
    instance-of v5, v1, Lne0/c;

    .line 257
    .line 258
    if-eqz v5, :cond_b

    .line 259
    .line 260
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    move-object v4, v2

    .line 265
    check-cast v4, Lh40/a3;

    .line 266
    .line 267
    check-cast v1, Lne0/c;

    .line 268
    .line 269
    iget-object v2, v0, Lh40/e3;->n:Lij0/a;

    .line 270
    .line 271
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 272
    .line 273
    .line 274
    move-result-object v8

    .line 275
    const/4 v12, 0x0

    .line 276
    const/16 v13, 0xf3

    .line 277
    .line 278
    const/4 v5, 0x0

    .line 279
    const/4 v6, 0x0

    .line 280
    const/4 v7, 0x0

    .line 281
    const/4 v9, 0x0

    .line 282
    const/4 v10, 0x0

    .line 283
    const/4 v11, 0x0

    .line 284
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_4

    .line 292
    .line 293
    :cond_b
    instance-of v5, v1, Lne0/e;

    .line 294
    .line 295
    if-eqz v5, :cond_f

    .line 296
    .line 297
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    move-object v6, v5

    .line 302
    check-cast v6, Lh40/a3;

    .line 303
    .line 304
    const/4 v14, 0x0

    .line 305
    const/16 v15, 0xfb

    .line 306
    .line 307
    const/4 v7, 0x0

    .line 308
    const/4 v8, 0x0

    .line 309
    const/4 v9, 0x0

    .line 310
    const/4 v10, 0x0

    .line 311
    const/4 v11, 0x0

    .line 312
    const/4 v12, 0x0

    .line 313
    const/4 v13, 0x0

    .line 314
    invoke-static/range {v6 .. v15}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 315
    .line 316
    .line 317
    move-result-object v5

    .line 318
    invoke-virtual {v0, v5}, Lql0/j;->g(Lql0/h;)V

    .line 319
    .line 320
    .line 321
    check-cast v1, Lne0/e;

    .line 322
    .line 323
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast v1, Lg40/e;

    .line 326
    .line 327
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 328
    .line 329
    .line 330
    move-result v1

    .line 331
    if-eqz v1, :cond_e

    .line 332
    .line 333
    if-eq v1, v4, :cond_d

    .line 334
    .line 335
    if-ne v1, v2, :cond_c

    .line 336
    .line 337
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    move-object v4, v1

    .line 342
    check-cast v4, Lh40/a3;

    .line 343
    .line 344
    const/4 v12, 0x0

    .line 345
    const/16 v13, 0xdf

    .line 346
    .line 347
    const/4 v5, 0x0

    .line 348
    const/4 v6, 0x0

    .line 349
    const/4 v7, 0x0

    .line 350
    const/4 v8, 0x0

    .line 351
    const/4 v9, 0x0

    .line 352
    const/4 v10, 0x1

    .line 353
    const/4 v11, 0x0

    .line 354
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 355
    .line 356
    .line 357
    move-result-object v1

    .line 358
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 359
    .line 360
    .line 361
    goto :goto_4

    .line 362
    :cond_c
    new-instance v0, La8/r0;

    .line 363
    .line 364
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 365
    .line 366
    .line 367
    throw v0

    .line 368
    :cond_d
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    move-object v4, v1

    .line 373
    check-cast v4, Lh40/a3;

    .line 374
    .line 375
    const/4 v12, 0x1

    .line 376
    const/16 v13, 0x7f

    .line 377
    .line 378
    const/4 v5, 0x0

    .line 379
    const/4 v6, 0x0

    .line 380
    const/4 v7, 0x0

    .line 381
    const/4 v8, 0x0

    .line 382
    const/4 v9, 0x0

    .line 383
    const/4 v10, 0x0

    .line 384
    const/4 v11, 0x0

    .line 385
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 390
    .line 391
    .line 392
    goto :goto_4

    .line 393
    :cond_e
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    move-object v4, v1

    .line 398
    check-cast v4, Lh40/a3;

    .line 399
    .line 400
    const/4 v12, 0x0

    .line 401
    const/16 v13, 0xbf

    .line 402
    .line 403
    const/4 v5, 0x0

    .line 404
    const/4 v6, 0x0

    .line 405
    const/4 v7, 0x0

    .line 406
    const/4 v8, 0x0

    .line 407
    const/4 v9, 0x0

    .line 408
    const/4 v10, 0x0

    .line 409
    const/4 v11, 0x1

    .line 410
    invoke-static/range {v4 .. v13}, Lh40/a3;->a(Lh40/a3;Lg40/v;ZZLql0/g;ZZZZI)Lh40/a3;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 415
    .line 416
    .line 417
    :goto_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 418
    .line 419
    return-object v3

    .line 420
    :cond_f
    new-instance v0, La8/r0;

    .line 421
    .line 422
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 423
    .line 424
    .line 425
    throw v0

    .line 426
    nop

    .line 427
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lh40/c3;->d:I

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
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lh40/c3;->d:I

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
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
