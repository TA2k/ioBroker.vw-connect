.class public final Lvv/a0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# static fields
.field public static final g:Lvv/a0;

.field public static final h:Lvv/a0;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvv/a0;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lvv/a0;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvv/a0;->g:Lvv/a0;

    .line 9
    .line 10
    new-instance v0, Lvv/a0;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lvv/a0;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lvv/a0;->h:Lvv/a0;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lvv/a0;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lvv/a0;->f:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Lvv/d0;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v2, p3

    .line 17
    .line 18
    check-cast v2, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    const-string v2, "infoPanelType"

    .line 24
    .line 25
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast v1, Ll2/t;

    .line 29
    .line 30
    const v2, 0x30c92767

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 34
    .line 35
    .line 36
    const v2, -0x1d58f75c

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 47
    .line 48
    if-ne v2, v3, :cond_5

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    if-eq v0, v2, :cond_3

    .line 58
    .line 59
    const/4 v2, 0x2

    .line 60
    if-eq v0, v2, :cond_2

    .line 61
    .line 62
    const/4 v2, 0x3

    .line 63
    if-eq v0, v2, :cond_1

    .line 64
    .line 65
    const/4 v2, 0x4

    .line 66
    if-ne v0, v2, :cond_0

    .line 67
    .line 68
    const-wide v2, 0xff856404L

    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    :goto_0
    move-wide v5, v2

    .line 78
    goto :goto_1

    .line 79
    :cond_0
    new-instance v0, La8/r0;

    .line 80
    .line 81
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 82
    .line 83
    .line 84
    throw v0

    .line 85
    :cond_1
    const-wide v2, 0xff721c24L

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 91
    .line 92
    .line 93
    move-result-wide v2

    .line 94
    goto :goto_0

    .line 95
    :cond_2
    const-wide v2, 0xff155724L

    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 101
    .line 102
    .line 103
    move-result-wide v2

    .line 104
    goto :goto_0

    .line 105
    :cond_3
    const-wide v2, 0xff383d41L

    .line 106
    .line 107
    .line 108
    .line 109
    .line 110
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 111
    .line 112
    .line 113
    move-result-wide v2

    .line 114
    goto :goto_0

    .line 115
    :cond_4
    const-wide v2, 0xff004085L

    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 121
    .line 122
    .line 123
    move-result-wide v2

    .line 124
    goto :goto_0

    .line 125
    :goto_1
    new-instance v4, Lg4/p0;

    .line 126
    .line 127
    const-wide/16 v15, 0x0

    .line 128
    .line 129
    const v17, 0xfffffe

    .line 130
    .line 131
    .line 132
    const-wide/16 v7, 0x0

    .line 133
    .line 134
    const/4 v9, 0x0

    .line 135
    const/4 v10, 0x0

    .line 136
    const/4 v11, 0x0

    .line 137
    const-wide/16 v12, 0x0

    .line 138
    .line 139
    const/4 v14, 0x0

    .line 140
    invoke-direct/range {v4 .. v17}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    move-object v2, v4

    .line 147
    :cond_5
    const/4 v0, 0x0

    .line 148
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    check-cast v2, Lg4/p0;

    .line 152
    .line 153
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    return-object v2

    .line 157
    :pswitch_0
    move-object/from16 v0, p1

    .line 158
    .line 159
    check-cast v0, Lvv/d0;

    .line 160
    .line 161
    move-object/from16 v1, p2

    .line 162
    .line 163
    check-cast v1, Ll2/o;

    .line 164
    .line 165
    move-object/from16 v2, p3

    .line 166
    .line 167
    check-cast v2, Ljava/lang/Number;

    .line 168
    .line 169
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 170
    .line 171
    .line 172
    const-string v2, "infoPanelType"

    .line 173
    .line 174
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    check-cast v1, Ll2/t;

    .line 178
    .line 179
    const v2, -0x77223588

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 183
    .line 184
    .line 185
    const v2, -0x1d58f75c

    .line 186
    .line 187
    .line 188
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 196
    .line 197
    if-ne v2, v3, :cond_b

    .line 198
    .line 199
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 200
    .line 201
    .line 202
    move-result v0

    .line 203
    const/4 v2, 0x4

    .line 204
    const/4 v3, 0x1

    .line 205
    if-eqz v0, :cond_a

    .line 206
    .line 207
    if-eq v0, v3, :cond_9

    .line 208
    .line 209
    const/4 v4, 0x2

    .line 210
    if-eq v0, v4, :cond_8

    .line 211
    .line 212
    const/4 v4, 0x3

    .line 213
    if-eq v0, v4, :cond_7

    .line 214
    .line 215
    if-ne v0, v2, :cond_6

    .line 216
    .line 217
    const-wide v4, 0xffffeebaL

    .line 218
    .line 219
    .line 220
    .line 221
    .line 222
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 223
    .line 224
    .line 225
    move-result-wide v4

    .line 226
    new-instance v0, Le3/s;

    .line 227
    .line 228
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 229
    .line 230
    .line 231
    const-wide v4, 0xfffff3cdL

    .line 232
    .line 233
    .line 234
    .line 235
    .line 236
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 237
    .line 238
    .line 239
    move-result-wide v4

    .line 240
    new-instance v6, Le3/s;

    .line 241
    .line 242
    invoke-direct {v6, v4, v5}, Le3/s;-><init>(J)V

    .line 243
    .line 244
    .line 245
    new-instance v4, Llx0/l;

    .line 246
    .line 247
    invoke-direct {v4, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    goto/16 :goto_2

    .line 251
    .line 252
    :cond_6
    new-instance v0, La8/r0;

    .line 253
    .line 254
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 255
    .line 256
    .line 257
    throw v0

    .line 258
    :cond_7
    const-wide v4, 0xfff5c6cbL

    .line 259
    .line 260
    .line 261
    .line 262
    .line 263
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 264
    .line 265
    .line 266
    move-result-wide v4

    .line 267
    new-instance v0, Le3/s;

    .line 268
    .line 269
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 270
    .line 271
    .line 272
    const-wide v4, 0xfff8d7daL

    .line 273
    .line 274
    .line 275
    .line 276
    .line 277
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 278
    .line 279
    .line 280
    move-result-wide v4

    .line 281
    new-instance v6, Le3/s;

    .line 282
    .line 283
    invoke-direct {v6, v4, v5}, Le3/s;-><init>(J)V

    .line 284
    .line 285
    .line 286
    new-instance v4, Llx0/l;

    .line 287
    .line 288
    invoke-direct {v4, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    goto :goto_2

    .line 292
    :cond_8
    const-wide v4, 0xffc3e6cbL

    .line 293
    .line 294
    .line 295
    .line 296
    .line 297
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 298
    .line 299
    .line 300
    move-result-wide v4

    .line 301
    new-instance v0, Le3/s;

    .line 302
    .line 303
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 304
    .line 305
    .line 306
    const-wide v4, 0xffd4eddaL

    .line 307
    .line 308
    .line 309
    .line 310
    .line 311
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 312
    .line 313
    .line 314
    move-result-wide v4

    .line 315
    new-instance v6, Le3/s;

    .line 316
    .line 317
    invoke-direct {v6, v4, v5}, Le3/s;-><init>(J)V

    .line 318
    .line 319
    .line 320
    new-instance v4, Llx0/l;

    .line 321
    .line 322
    invoke-direct {v4, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    goto :goto_2

    .line 326
    :cond_9
    const-wide v4, 0xffd6d8dbL

    .line 327
    .line 328
    .line 329
    .line 330
    .line 331
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 332
    .line 333
    .line 334
    move-result-wide v4

    .line 335
    new-instance v0, Le3/s;

    .line 336
    .line 337
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 338
    .line 339
    .line 340
    const-wide v4, 0xffe2e3e5L

    .line 341
    .line 342
    .line 343
    .line 344
    .line 345
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 346
    .line 347
    .line 348
    move-result-wide v4

    .line 349
    new-instance v6, Le3/s;

    .line 350
    .line 351
    invoke-direct {v6, v4, v5}, Le3/s;-><init>(J)V

    .line 352
    .line 353
    .line 354
    new-instance v4, Llx0/l;

    .line 355
    .line 356
    invoke-direct {v4, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 357
    .line 358
    .line 359
    goto :goto_2

    .line 360
    :cond_a
    const-wide v4, 0xffb8daffL

    .line 361
    .line 362
    .line 363
    .line 364
    .line 365
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 366
    .line 367
    .line 368
    move-result-wide v4

    .line 369
    new-instance v0, Le3/s;

    .line 370
    .line 371
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 372
    .line 373
    .line 374
    const-wide v4, 0xffcce5ffL

    .line 375
    .line 376
    .line 377
    .line 378
    .line 379
    invoke-static {v4, v5}, Le3/j0;->e(J)J

    .line 380
    .line 381
    .line 382
    move-result-wide v4

    .line 383
    new-instance v6, Le3/s;

    .line 384
    .line 385
    invoke-direct {v6, v4, v5}, Le3/s;-><init>(J)V

    .line 386
    .line 387
    .line 388
    new-instance v4, Llx0/l;

    .line 389
    .line 390
    invoke-direct {v4, v0, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 391
    .line 392
    .line 393
    :goto_2
    iget-object v0, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 394
    .line 395
    check-cast v0, Le3/s;

    .line 396
    .line 397
    iget-wide v5, v0, Le3/s;->a:J

    .line 398
    .line 399
    iget-object v0, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast v0, Le3/s;

    .line 402
    .line 403
    iget-wide v7, v0, Le3/s;->a:J

    .line 404
    .line 405
    int-to-float v0, v3

    .line 406
    int-to-float v2, v2

    .line 407
    invoke-static {v2}, Ls1/f;->b(F)Ls1/e;

    .line 408
    .line 409
    .line 410
    move-result-object v3

    .line 411
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 412
    .line 413
    invoke-static {v0, v5, v6, v3, v4}, Lkp/g;->a(FJLe3/n0;Lx2/s;)Lx2/s;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    invoke-static {v2}, Ls1/f;->b(F)Ls1/e;

    .line 418
    .line 419
    .line 420
    move-result-object v2

    .line 421
    invoke-static {v0, v7, v8, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 422
    .line 423
    .line 424
    move-result-object v2

    .line 425
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 426
    .line 427
    .line 428
    :cond_b
    const/4 v0, 0x0

    .line 429
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 430
    .line 431
    .line 432
    check-cast v2, Lx2/s;

    .line 433
    .line 434
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 435
    .line 436
    .line 437
    return-object v2

    .line 438
    nop

    .line 439
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
