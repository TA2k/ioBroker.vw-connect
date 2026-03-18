.class public final synthetic Ltj/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Ltj/i;->d:I

    iput-object p3, p0, Ltj/i;->e:Ljava/lang/Object;

    iput-object p4, p0, Ltj/i;->g:Ljava/lang/Object;

    iput p1, p0, Ltj/i;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILay0/a;Ll2/t2;)V
    .locals 1

    .line 2
    const/16 v0, 0x15

    iput v0, p0, Ltj/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ltj/i;->f:I

    iput-object p2, p0, Ltj/i;->e:Ljava/lang/Object;

    iput-object p3, p0, Ltj/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ll2/b1;I)V
    .locals 1

    .line 3
    const/16 v0, 0x16

    iput v0, p0, Ltj/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltj/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Ltj/i;->g:Ljava/lang/Object;

    iput p3, p0, Ltj/i;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lql0/h;Llx0/e;III)V
    .locals 0

    .line 4
    iput p5, p0, Ltj/i;->d:I

    iput-object p1, p0, Ltj/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Ltj/i;->g:Ljava/lang/Object;

    iput p4, p0, Ltj/i;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltj/i;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lwk0/t0;

    .line 11
    .line 12
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lay0/k;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v4, p2

    .line 21
    .line 22
    check-cast v4, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    iget v0, v0, Ltj/i;->f:I

    .line 28
    .line 29
    or-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-static {v1, v2, v3, v0}, Lxk0/h;->n0(Lwk0/t0;Lay0/k;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object v0

    .line 41
    :pswitch_0
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Ljava/util/Map;

    .line 44
    .line 45
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v2, Lx2/s;

    .line 48
    .line 49
    move-object/from16 v3, p1

    .line 50
    .line 51
    check-cast v3, Ll2/o;

    .line 52
    .line 53
    move-object/from16 v4, p2

    .line 54
    .line 55
    check-cast v4, Ljava/lang/Integer;

    .line 56
    .line 57
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    iget v0, v0, Ltj/i;->f:I

    .line 61
    .line 62
    or-int/lit8 v0, v0, 0x1

    .line 63
    .line 64
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    invoke-static {v1, v2, v3, v0}, Lxk0/h;->X(Ljava/util/Map;Lx2/s;Ll2/o;I)V

    .line 69
    .line 70
    .line 71
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object v0

    .line 74
    :pswitch_1
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Lk1/k0;

    .line 77
    .line 78
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v2, Lwk0/h;

    .line 81
    .line 82
    move-object/from16 v3, p1

    .line 83
    .line 84
    check-cast v3, Ll2/o;

    .line 85
    .line 86
    move-object/from16 v4, p2

    .line 87
    .line 88
    check-cast v4, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    iget v0, v0, Ltj/i;->f:I

    .line 94
    .line 95
    or-int/lit8 v0, v0, 0x1

    .line 96
    .line 97
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    invoke-static {v1, v2, v3, v0}, Lxk0/h;->k(Lk1/k0;Lwk0/h;Ll2/o;I)V

    .line 102
    .line 103
    .line 104
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object v0

    .line 107
    :pswitch_2
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v1, Lyj/b;

    .line 110
    .line 111
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v2, Lyj/b;

    .line 114
    .line 115
    move-object/from16 v3, p1

    .line 116
    .line 117
    check-cast v3, Ll2/o;

    .line 118
    .line 119
    move-object/from16 v4, p2

    .line 120
    .line 121
    check-cast v4, Ljava/lang/Integer;

    .line 122
    .line 123
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    iget v0, v0, Ltj/i;->f:I

    .line 127
    .line 128
    or-int/lit8 v0, v0, 0x1

    .line 129
    .line 130
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    invoke-static {v1, v2, v3, v0}, Lxj/f;->k(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 135
    .line 136
    .line 137
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    return-object v0

    .line 140
    :pswitch_3
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Lzc/h;

    .line 143
    .line 144
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v2, Lay0/k;

    .line 147
    .line 148
    move-object/from16 v3, p1

    .line 149
    .line 150
    check-cast v3, Ll2/o;

    .line 151
    .line 152
    move-object/from16 v4, p2

    .line 153
    .line 154
    check-cast v4, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    iget v0, v0, Ltj/i;->f:I

    .line 160
    .line 161
    or-int/lit8 v0, v0, 0x1

    .line 162
    .line 163
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    invoke-static {v1, v2, v3, v0}, Lxj/k;->d(Lzc/h;Lay0/k;Ll2/o;I)V

    .line 168
    .line 169
    .line 170
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_4
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v1, Lzb/r0;

    .line 176
    .line 177
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v2, Ljava/lang/String;

    .line 180
    .line 181
    move-object/from16 v3, p1

    .line 182
    .line 183
    check-cast v3, Ll2/o;

    .line 184
    .line 185
    move-object/from16 v4, p2

    .line 186
    .line 187
    check-cast v4, Ljava/lang/Integer;

    .line 188
    .line 189
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 190
    .line 191
    .line 192
    iget v0, v0, Ltj/i;->f:I

    .line 193
    .line 194
    or-int/lit8 v0, v0, 0x1

    .line 195
    .line 196
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    invoke-static {v1, v2, v3, v0}, Lxj/f;->h(Lzb/r0;Ljava/lang/String;Ll2/o;I)V

    .line 201
    .line 202
    .line 203
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object v0

    .line 206
    :pswitch_5
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v1, Ljava/util/List;

    .line 209
    .line 210
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v2, Lv2/o;

    .line 213
    .line 214
    move-object/from16 v3, p1

    .line 215
    .line 216
    check-cast v3, Ll2/o;

    .line 217
    .line 218
    move-object/from16 v4, p2

    .line 219
    .line 220
    check-cast v4, Ljava/lang/Integer;

    .line 221
    .line 222
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 223
    .line 224
    .line 225
    iget v0, v0, Ltj/i;->f:I

    .line 226
    .line 227
    or-int/lit8 v0, v0, 0x1

    .line 228
    .line 229
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 230
    .line 231
    .line 232
    move-result v0

    .line 233
    invoke-static {v1, v2, v3, v0}, Lxf0/z2;->c(Ljava/util/List;Lv2/o;Ll2/o;I)V

    .line 234
    .line 235
    .line 236
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object v0

    .line 239
    :pswitch_6
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v1, Ljava/util/List;

    .line 242
    .line 243
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 244
    .line 245
    check-cast v2, Ll2/b1;

    .line 246
    .line 247
    move-object/from16 v3, p1

    .line 248
    .line 249
    check-cast v3, Ll2/o;

    .line 250
    .line 251
    move-object/from16 v4, p2

    .line 252
    .line 253
    check-cast v4, Ljava/lang/Integer;

    .line 254
    .line 255
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 256
    .line 257
    .line 258
    iget v0, v0, Ltj/i;->f:I

    .line 259
    .line 260
    or-int/lit8 v0, v0, 0x1

    .line 261
    .line 262
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 263
    .line 264
    .line 265
    move-result v0

    .line 266
    invoke-static {v1, v2, v3, v0}, Lxf0/r2;->c(Ljava/util/List;Ll2/b1;Ll2/o;I)V

    .line 267
    .line 268
    .line 269
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 270
    .line 271
    return-object v0

    .line 272
    :pswitch_7
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 273
    .line 274
    move-object v6, v1

    .line 275
    check-cast v6, Lay0/a;

    .line 276
    .line 277
    iget-object v1, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v1, Ll2/t2;

    .line 280
    .line 281
    move-object/from16 v2, p1

    .line 282
    .line 283
    check-cast v2, Ll2/o;

    .line 284
    .line 285
    move-object/from16 v3, p2

    .line 286
    .line 287
    check-cast v3, Ljava/lang/Integer;

    .line 288
    .line 289
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 290
    .line 291
    .line 292
    move-result v3

    .line 293
    and-int/lit8 v4, v3, 0x3

    .line 294
    .line 295
    const/4 v5, 0x2

    .line 296
    const/4 v8, 0x1

    .line 297
    if-eq v4, v5, :cond_0

    .line 298
    .line 299
    move v4, v8

    .line 300
    goto :goto_0

    .line 301
    :cond_0
    const/4 v4, 0x0

    .line 302
    :goto_0
    and-int/2addr v3, v8

    .line 303
    move-object v9, v2

    .line 304
    check-cast v9, Ll2/t;

    .line 305
    .line 306
    invoke-virtual {v9, v3, v4}, Ll2/t;->O(IZ)Z

    .line 307
    .line 308
    .line 309
    move-result v2

    .line 310
    if-eqz v2, :cond_5

    .line 311
    .line 312
    sget-object v10, Lx2/c;->n:Lx2/i;

    .line 313
    .line 314
    sget-object v11, Lk1/j;->e:Lk1/f;

    .line 315
    .line 316
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 317
    .line 318
    iget v0, v0, Ltj/i;->f:I

    .line 319
    .line 320
    invoke-static {v2, v0}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 321
    .line 322
    .line 323
    move-result-object v2

    .line 324
    if-eqz v6, :cond_1

    .line 325
    .line 326
    const/4 v5, 0x0

    .line 327
    const/16 v7, 0xe

    .line 328
    .line 329
    const/4 v3, 0x1

    .line 330
    const/4 v4, 0x0

    .line 331
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 332
    .line 333
    .line 334
    move-result-object v2

    .line 335
    :cond_1
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 336
    .line 337
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v4

    .line 341
    check-cast v4, Lj91/c;

    .line 342
    .line 343
    iget v4, v4, Lj91/c;->d:F

    .line 344
    .line 345
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v5

    .line 349
    check-cast v5, Lj91/c;

    .line 350
    .line 351
    iget v5, v5, Lj91/c;->d:F

    .line 352
    .line 353
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v6

    .line 357
    check-cast v6, Lj91/c;

    .line 358
    .line 359
    iget v6, v6, Lj91/c;->b:F

    .line 360
    .line 361
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    check-cast v3, Lj91/c;

    .line 366
    .line 367
    iget v3, v3, Lj91/c;->b:F

    .line 368
    .line 369
    invoke-static {v2, v4, v6, v5, v3}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    const/16 v3, 0x36

    .line 374
    .line 375
    invoke-static {v11, v10, v9, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 376
    .line 377
    .line 378
    move-result-object v3

    .line 379
    iget-wide v4, v9, Ll2/t;->T:J

    .line 380
    .line 381
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 382
    .line 383
    .line 384
    move-result v4

    .line 385
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 386
    .line 387
    .line 388
    move-result-object v5

    .line 389
    invoke-static {v9, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 390
    .line 391
    .line 392
    move-result-object v2

    .line 393
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 394
    .line 395
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 396
    .line 397
    .line 398
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 399
    .line 400
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 401
    .line 402
    .line 403
    iget-boolean v7, v9, Ll2/t;->S:Z

    .line 404
    .line 405
    if-eqz v7, :cond_2

    .line 406
    .line 407
    invoke-virtual {v9, v6}, Ll2/t;->l(Lay0/a;)V

    .line 408
    .line 409
    .line 410
    goto :goto_1

    .line 411
    :cond_2
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 412
    .line 413
    .line 414
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 415
    .line 416
    invoke-static {v6, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 417
    .line 418
    .line 419
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 420
    .line 421
    invoke-static {v3, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 422
    .line 423
    .line 424
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 425
    .line 426
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 427
    .line 428
    if-nez v5, :cond_3

    .line 429
    .line 430
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v5

    .line 434
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 435
    .line 436
    .line 437
    move-result-object v6

    .line 438
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v5

    .line 442
    if-nez v5, :cond_4

    .line 443
    .line 444
    :cond_3
    invoke-static {v4, v9, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 445
    .line 446
    .line 447
    :cond_4
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 448
    .line 449
    invoke-static {v3, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 450
    .line 451
    .line 452
    invoke-static {v9, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v0

    .line 456
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 457
    .line 458
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v2

    .line 462
    check-cast v2, Lj91/f;

    .line 463
    .line 464
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 465
    .line 466
    .line 467
    move-result-object v10

    .line 468
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v1

    .line 472
    check-cast v1, Le3/s;

    .line 473
    .line 474
    iget-wide v12, v1, Le3/s;->a:J

    .line 475
    .line 476
    const/16 v29, 0x6180

    .line 477
    .line 478
    const v30, 0xaff4

    .line 479
    .line 480
    .line 481
    const/4 v11, 0x0

    .line 482
    const-wide/16 v14, 0x0

    .line 483
    .line 484
    const/16 v16, 0x0

    .line 485
    .line 486
    const-wide/16 v17, 0x0

    .line 487
    .line 488
    const/16 v19, 0x0

    .line 489
    .line 490
    const/16 v20, 0x0

    .line 491
    .line 492
    const-wide/16 v21, 0x0

    .line 493
    .line 494
    const/16 v23, 0x2

    .line 495
    .line 496
    const/16 v24, 0x0

    .line 497
    .line 498
    const/16 v25, 0x1

    .line 499
    .line 500
    const/16 v26, 0x0

    .line 501
    .line 502
    const/16 v28, 0x0

    .line 503
    .line 504
    move-object/from16 v27, v9

    .line 505
    .line 506
    move-object v9, v0

    .line 507
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 508
    .line 509
    .line 510
    move-object/from16 v2, v27

    .line 511
    .line 512
    invoke-virtual {v2, v8}, Ll2/t;->q(Z)V

    .line 513
    .line 514
    .line 515
    goto :goto_2

    .line 516
    :cond_5
    move-object v2, v9

    .line 517
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 518
    .line 519
    .line 520
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 521
    .line 522
    return-object v0

    .line 523
    :pswitch_8
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 524
    .line 525
    check-cast v1, Lw80/h;

    .line 526
    .line 527
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 528
    .line 529
    check-cast v2, Lay0/k;

    .line 530
    .line 531
    move-object/from16 v3, p1

    .line 532
    .line 533
    check-cast v3, Ll2/o;

    .line 534
    .line 535
    move-object/from16 v4, p2

    .line 536
    .line 537
    check-cast v4, Ljava/lang/Integer;

    .line 538
    .line 539
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 540
    .line 541
    .line 542
    const/4 v4, 0x1

    .line 543
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 544
    .line 545
    .line 546
    move-result v4

    .line 547
    iget v0, v0, Ltj/i;->f:I

    .line 548
    .line 549
    invoke-static {v1, v2, v3, v4, v0}, Lx80/a;->e(Lw80/h;Lay0/k;Ll2/o;II)V

    .line 550
    .line 551
    .line 552
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 553
    .line 554
    return-object v0

    .line 555
    :pswitch_9
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast v1, Lw40/n;

    .line 558
    .line 559
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 560
    .line 561
    check-cast v2, Lay0/a;

    .line 562
    .line 563
    move-object/from16 v3, p1

    .line 564
    .line 565
    check-cast v3, Ll2/o;

    .line 566
    .line 567
    move-object/from16 v4, p2

    .line 568
    .line 569
    check-cast v4, Ljava/lang/Integer;

    .line 570
    .line 571
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 572
    .line 573
    .line 574
    iget v0, v0, Ltj/i;->f:I

    .line 575
    .line 576
    or-int/lit8 v0, v0, 0x1

    .line 577
    .line 578
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 579
    .line 580
    .line 581
    move-result v0

    .line 582
    invoke-static {v1, v2, v3, v0}, Lx40/a;->B(Lw40/n;Lay0/a;Ll2/o;I)V

    .line 583
    .line 584
    .line 585
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 586
    .line 587
    return-object v0

    .line 588
    :pswitch_a
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 589
    .line 590
    check-cast v1, Lzh/j;

    .line 591
    .line 592
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 593
    .line 594
    check-cast v2, Lay0/k;

    .line 595
    .line 596
    move-object/from16 v3, p1

    .line 597
    .line 598
    check-cast v3, Ll2/o;

    .line 599
    .line 600
    move-object/from16 v4, p2

    .line 601
    .line 602
    check-cast v4, Ljava/lang/Integer;

    .line 603
    .line 604
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 605
    .line 606
    .line 607
    iget v0, v0, Ltj/i;->f:I

    .line 608
    .line 609
    or-int/lit8 v0, v0, 0x1

    .line 610
    .line 611
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 612
    .line 613
    .line 614
    move-result v0

    .line 615
    invoke-static {v1, v2, v3, v0}, Lwk/a;->h(Lzh/j;Lay0/k;Ll2/o;I)V

    .line 616
    .line 617
    .line 618
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 619
    .line 620
    return-object v0

    .line 621
    :pswitch_b
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 622
    .line 623
    check-cast v1, Lhh/e;

    .line 624
    .line 625
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 626
    .line 627
    check-cast v2, Lay0/k;

    .line 628
    .line 629
    move-object/from16 v3, p1

    .line 630
    .line 631
    check-cast v3, Ll2/o;

    .line 632
    .line 633
    move-object/from16 v4, p2

    .line 634
    .line 635
    check-cast v4, Ljava/lang/Integer;

    .line 636
    .line 637
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 638
    .line 639
    .line 640
    iget v0, v0, Ltj/i;->f:I

    .line 641
    .line 642
    or-int/lit8 v0, v0, 0x1

    .line 643
    .line 644
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 645
    .line 646
    .line 647
    move-result v0

    .line 648
    invoke-static {v1, v2, v3, v0}, Lwk/a;->l(Lhh/e;Lay0/k;Ll2/o;I)V

    .line 649
    .line 650
    .line 651
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 652
    .line 653
    return-object v0

    .line 654
    :pswitch_c
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 655
    .line 656
    check-cast v1, Lwe/d;

    .line 657
    .line 658
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 659
    .line 660
    check-cast v2, Lay0/a;

    .line 661
    .line 662
    move-object/from16 v3, p1

    .line 663
    .line 664
    check-cast v3, Ll2/o;

    .line 665
    .line 666
    move-object/from16 v4, p2

    .line 667
    .line 668
    check-cast v4, Ljava/lang/Integer;

    .line 669
    .line 670
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 671
    .line 672
    .line 673
    iget v0, v0, Ltj/i;->f:I

    .line 674
    .line 675
    or-int/lit8 v0, v0, 0x1

    .line 676
    .line 677
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 678
    .line 679
    .line 680
    move-result v0

    .line 681
    invoke-static {v1, v2, v3, v0}, Llp/hd;->a(Lwe/d;Lay0/a;Ll2/o;I)V

    .line 682
    .line 683
    .line 684
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 685
    .line 686
    return-object v0

    .line 687
    :pswitch_d
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 688
    .line 689
    check-cast v1, Lx11/a;

    .line 690
    .line 691
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 692
    .line 693
    check-cast v2, Lt2/b;

    .line 694
    .line 695
    move-object/from16 v3, p1

    .line 696
    .line 697
    check-cast v3, Ll2/o;

    .line 698
    .line 699
    move-object/from16 v4, p2

    .line 700
    .line 701
    check-cast v4, Ljava/lang/Integer;

    .line 702
    .line 703
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 704
    .line 705
    .line 706
    iget v0, v0, Ltj/i;->f:I

    .line 707
    .line 708
    or-int/lit8 v0, v0, 0x1

    .line 709
    .line 710
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 711
    .line 712
    .line 713
    move-result v0

    .line 714
    invoke-static {v1, v2, v3, v0}, Lw11/c;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 715
    .line 716
    .line 717
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 718
    .line 719
    return-object v0

    .line 720
    :pswitch_e
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast v1, Lv00/h;

    .line 723
    .line 724
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 725
    .line 726
    check-cast v2, Lay0/k;

    .line 727
    .line 728
    move-object/from16 v3, p1

    .line 729
    .line 730
    check-cast v3, Ll2/o;

    .line 731
    .line 732
    move-object/from16 v4, p2

    .line 733
    .line 734
    check-cast v4, Ljava/lang/Integer;

    .line 735
    .line 736
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 737
    .line 738
    .line 739
    iget v0, v0, Ltj/i;->f:I

    .line 740
    .line 741
    or-int/lit8 v0, v0, 0x1

    .line 742
    .line 743
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 744
    .line 745
    .line 746
    move-result v0

    .line 747
    invoke-static {v1, v2, v3, v0}, Lw00/a;->j(Lv00/h;Lay0/k;Ll2/o;I)V

    .line 748
    .line 749
    .line 750
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 751
    .line 752
    return-object v0

    .line 753
    :pswitch_f
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 754
    .line 755
    check-cast v1, Ltu0/b;

    .line 756
    .line 757
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 758
    .line 759
    check-cast v2, Lx2/s;

    .line 760
    .line 761
    move-object/from16 v3, p1

    .line 762
    .line 763
    check-cast v3, Ll2/o;

    .line 764
    .line 765
    move-object/from16 v4, p2

    .line 766
    .line 767
    check-cast v4, Ljava/lang/Integer;

    .line 768
    .line 769
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 770
    .line 771
    .line 772
    iget v0, v0, Ltj/i;->f:I

    .line 773
    .line 774
    or-int/lit8 v0, v0, 0x1

    .line 775
    .line 776
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 777
    .line 778
    .line 779
    move-result v0

    .line 780
    invoke-static {v1, v2, v3, v0}, Lvu0/g;->k(Ltu0/b;Lx2/s;Ll2/o;I)V

    .line 781
    .line 782
    .line 783
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 784
    .line 785
    return-object v0

    .line 786
    :pswitch_10
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 787
    .line 788
    check-cast v1, Luu0/r;

    .line 789
    .line 790
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 791
    .line 792
    check-cast v2, Lay0/a;

    .line 793
    .line 794
    move-object/from16 v3, p1

    .line 795
    .line 796
    check-cast v3, Ll2/o;

    .line 797
    .line 798
    move-object/from16 v4, p2

    .line 799
    .line 800
    check-cast v4, Ljava/lang/Integer;

    .line 801
    .line 802
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 803
    .line 804
    .line 805
    iget v0, v0, Ltj/i;->f:I

    .line 806
    .line 807
    or-int/lit8 v0, v0, 0x1

    .line 808
    .line 809
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 810
    .line 811
    .line 812
    move-result v0

    .line 813
    invoke-static {v1, v2, v3, v0}, Lvu0/g;->f(Luu0/r;Lay0/a;Ll2/o;I)V

    .line 814
    .line 815
    .line 816
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 817
    .line 818
    return-object v0

    .line 819
    :pswitch_11
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 820
    .line 821
    check-cast v1, Luu0/r;

    .line 822
    .line 823
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 824
    .line 825
    check-cast v2, Lx2/s;

    .line 826
    .line 827
    move-object/from16 v3, p1

    .line 828
    .line 829
    check-cast v3, Ll2/o;

    .line 830
    .line 831
    move-object/from16 v4, p2

    .line 832
    .line 833
    check-cast v4, Ljava/lang/Integer;

    .line 834
    .line 835
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 836
    .line 837
    .line 838
    iget v0, v0, Ltj/i;->f:I

    .line 839
    .line 840
    or-int/lit8 v0, v0, 0x1

    .line 841
    .line 842
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 843
    .line 844
    .line 845
    move-result v0

    .line 846
    invoke-static {v1, v2, v3, v0}, Lvu0/g;->e(Luu0/r;Lx2/s;Ll2/o;I)V

    .line 847
    .line 848
    .line 849
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 850
    .line 851
    return-object v0

    .line 852
    :pswitch_12
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 853
    .line 854
    check-cast v1, Lut0/a;

    .line 855
    .line 856
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 857
    .line 858
    check-cast v2, Lx2/s;

    .line 859
    .line 860
    move-object/from16 v3, p1

    .line 861
    .line 862
    check-cast v3, Ll2/o;

    .line 863
    .line 864
    move-object/from16 v4, p2

    .line 865
    .line 866
    check-cast v4, Ljava/lang/Integer;

    .line 867
    .line 868
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 869
    .line 870
    .line 871
    iget v0, v0, Ltj/i;->f:I

    .line 872
    .line 873
    or-int/lit8 v0, v0, 0x1

    .line 874
    .line 875
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 876
    .line 877
    .line 878
    move-result v0

    .line 879
    invoke-static {v1, v2, v3, v0}, Llp/bc;->b(Lut0/a;Lx2/s;Ll2/o;I)V

    .line 880
    .line 881
    .line 882
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 883
    .line 884
    return-object v0

    .line 885
    :pswitch_13
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 886
    .line 887
    check-cast v1, Ltg/a;

    .line 888
    .line 889
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 890
    .line 891
    check-cast v2, Ly1/i;

    .line 892
    .line 893
    move-object/from16 v3, p1

    .line 894
    .line 895
    check-cast v3, Ll2/o;

    .line 896
    .line 897
    move-object/from16 v4, p2

    .line 898
    .line 899
    check-cast v4, Ljava/lang/Integer;

    .line 900
    .line 901
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 902
    .line 903
    .line 904
    iget v0, v0, Ltj/i;->f:I

    .line 905
    .line 906
    or-int/lit8 v0, v0, 0x1

    .line 907
    .line 908
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 909
    .line 910
    .line 911
    move-result v0

    .line 912
    invoke-static {v1, v2, v3, v0}, Llp/pb;->e(Ltg/a;Ly1/i;Ll2/o;I)V

    .line 913
    .line 914
    .line 915
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 916
    .line 917
    return-object v0

    .line 918
    :pswitch_14
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 919
    .line 920
    check-cast v1, Lay0/k;

    .line 921
    .line 922
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 923
    .line 924
    check-cast v2, Lwc/f;

    .line 925
    .line 926
    move-object/from16 v3, p1

    .line 927
    .line 928
    check-cast v3, Ll2/o;

    .line 929
    .line 930
    move-object/from16 v4, p2

    .line 931
    .line 932
    check-cast v4, Ljava/lang/Integer;

    .line 933
    .line 934
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 935
    .line 936
    .line 937
    iget v0, v0, Ltj/i;->f:I

    .line 938
    .line 939
    or-int/lit8 v0, v0, 0x1

    .line 940
    .line 941
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 942
    .line 943
    .line 944
    move-result v0

    .line 945
    invoke-static {v0, v1, v3, v2}, Lvj/c;->b(ILay0/k;Ll2/o;Lwc/f;)V

    .line 946
    .line 947
    .line 948
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 949
    .line 950
    return-object v0

    .line 951
    :pswitch_15
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 952
    .line 953
    check-cast v1, Lu50/x;

    .line 954
    .line 955
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 956
    .line 957
    check-cast v2, Lk1/z0;

    .line 958
    .line 959
    move-object/from16 v3, p1

    .line 960
    .line 961
    check-cast v3, Ll2/o;

    .line 962
    .line 963
    move-object/from16 v4, p2

    .line 964
    .line 965
    check-cast v4, Ljava/lang/Integer;

    .line 966
    .line 967
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 968
    .line 969
    .line 970
    iget v0, v0, Ltj/i;->f:I

    .line 971
    .line 972
    or-int/lit8 v0, v0, 0x1

    .line 973
    .line 974
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 975
    .line 976
    .line 977
    move-result v0

    .line 978
    invoke-static {v1, v2, v3, v0}, Lv50/a;->g0(Lu50/x;Lk1/z0;Ll2/o;I)V

    .line 979
    .line 980
    .line 981
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 982
    .line 983
    return-object v0

    .line 984
    :pswitch_16
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 985
    .line 986
    check-cast v1, Ljava/util/ArrayList;

    .line 987
    .line 988
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 989
    .line 990
    check-cast v2, Lx2/s;

    .line 991
    .line 992
    move-object/from16 v3, p1

    .line 993
    .line 994
    check-cast v3, Ll2/o;

    .line 995
    .line 996
    move-object/from16 v4, p2

    .line 997
    .line 998
    check-cast v4, Ljava/lang/Integer;

    .line 999
    .line 1000
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1001
    .line 1002
    .line 1003
    iget v0, v0, Ltj/i;->f:I

    .line 1004
    .line 1005
    or-int/lit8 v0, v0, 0x1

    .line 1006
    .line 1007
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1008
    .line 1009
    .line 1010
    move-result v0

    .line 1011
    invoke-static {v1, v2, v3, v0}, Luz/t;->t(Ljava/util/ArrayList;Lx2/s;Ll2/o;I)V

    .line 1012
    .line 1013
    .line 1014
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1015
    .line 1016
    return-object v0

    .line 1017
    :pswitch_17
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1018
    .line 1019
    check-cast v1, Ltz/h;

    .line 1020
    .line 1021
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1022
    .line 1023
    check-cast v2, Ltz/i;

    .line 1024
    .line 1025
    move-object/from16 v3, p1

    .line 1026
    .line 1027
    check-cast v3, Ll2/o;

    .line 1028
    .line 1029
    move-object/from16 v4, p2

    .line 1030
    .line 1031
    check-cast v4, Ljava/lang/Integer;

    .line 1032
    .line 1033
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 1034
    .line 1035
    .line 1036
    iget v0, v0, Ltj/i;->f:I

    .line 1037
    .line 1038
    or-int/lit8 v0, v0, 0x1

    .line 1039
    .line 1040
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1041
    .line 1042
    .line 1043
    move-result v0

    .line 1044
    invoke-static {v1, v2, v3, v0}, Luz/g;->i(Ltz/h;Ltz/i;Ll2/o;I)V

    .line 1045
    .line 1046
    .line 1047
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1048
    .line 1049
    return-object v0

    .line 1050
    :pswitch_18
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1051
    .line 1052
    check-cast v1, Lsg/o;

    .line 1053
    .line 1054
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1055
    .line 1056
    check-cast v2, Lay0/k;

    .line 1057
    .line 1058
    move-object/from16 v3, p1

    .line 1059
    .line 1060
    check-cast v3, Ll2/o;

    .line 1061
    .line 1062
    move-object/from16 v4, p2

    .line 1063
    .line 1064
    check-cast v4, Ljava/lang/Integer;

    .line 1065
    .line 1066
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1067
    .line 1068
    .line 1069
    iget v0, v0, Ltj/i;->f:I

    .line 1070
    .line 1071
    or-int/lit8 v0, v0, 0x1

    .line 1072
    .line 1073
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1074
    .line 1075
    .line 1076
    move-result v0

    .line 1077
    invoke-static {v1, v2, v3, v0}, Luk/a;->a(Lsg/o;Lay0/k;Ll2/o;I)V

    .line 1078
    .line 1079
    .line 1080
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1081
    .line 1082
    return-object v0

    .line 1083
    :pswitch_19
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1084
    .line 1085
    check-cast v1, Lkp/q9;

    .line 1086
    .line 1087
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1088
    .line 1089
    check-cast v2, Lay0/a;

    .line 1090
    .line 1091
    move-object/from16 v3, p1

    .line 1092
    .line 1093
    check-cast v3, Ll2/o;

    .line 1094
    .line 1095
    move-object/from16 v4, p2

    .line 1096
    .line 1097
    check-cast v4, Ljava/lang/Integer;

    .line 1098
    .line 1099
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 1100
    .line 1101
    .line 1102
    iget v0, v0, Ltj/i;->f:I

    .line 1103
    .line 1104
    or-int/lit8 v0, v0, 0x1

    .line 1105
    .line 1106
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1107
    .line 1108
    .line 1109
    move-result v0

    .line 1110
    invoke-static {v1, v2, v3, v0}, Lu80/a;->f(Lkp/q9;Lay0/a;Ll2/o;I)V

    .line 1111
    .line 1112
    .line 1113
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1114
    .line 1115
    return-object v0

    .line 1116
    :pswitch_1a
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1117
    .line 1118
    check-cast v1, Lt80/d;

    .line 1119
    .line 1120
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1121
    .line 1122
    check-cast v2, Lay0/a;

    .line 1123
    .line 1124
    move-object/from16 v3, p1

    .line 1125
    .line 1126
    check-cast v3, Ll2/o;

    .line 1127
    .line 1128
    move-object/from16 v4, p2

    .line 1129
    .line 1130
    check-cast v4, Ljava/lang/Integer;

    .line 1131
    .line 1132
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1133
    .line 1134
    .line 1135
    const/4 v4, 0x1

    .line 1136
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 1137
    .line 1138
    .line 1139
    move-result v4

    .line 1140
    iget v0, v0, Ltj/i;->f:I

    .line 1141
    .line 1142
    invoke-static {v1, v2, v3, v4, v0}, Lu80/a;->e(Lt80/d;Lay0/a;Ll2/o;II)V

    .line 1143
    .line 1144
    .line 1145
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1146
    .line 1147
    return-object v0

    .line 1148
    :pswitch_1b
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1149
    .line 1150
    check-cast v1, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 1151
    .line 1152
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1153
    .line 1154
    check-cast v2, Lkj/a;

    .line 1155
    .line 1156
    move-object/from16 v3, p1

    .line 1157
    .line 1158
    check-cast v3, Ll2/o;

    .line 1159
    .line 1160
    move-object/from16 v4, p2

    .line 1161
    .line 1162
    check-cast v4, Ljava/lang/Integer;

    .line 1163
    .line 1164
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 1165
    .line 1166
    .line 1167
    move-result v4

    .line 1168
    iget v0, v0, Ltj/i;->f:I

    .line 1169
    .line 1170
    invoke-static {v1, v2, v0, v3, v4}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->M(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Lkj/a;ILl2/o;I)Llx0/b0;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v0

    .line 1174
    return-object v0

    .line 1175
    :pswitch_1c
    iget-object v1, v0, Ltj/i;->e:Ljava/lang/Object;

    .line 1176
    .line 1177
    check-cast v1, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 1178
    .line 1179
    iget-object v2, v0, Ltj/i;->g:Ljava/lang/Object;

    .line 1180
    .line 1181
    check-cast v2, [Lki/a;

    .line 1182
    .line 1183
    move-object/from16 v3, p1

    .line 1184
    .line 1185
    check-cast v3, Ll2/o;

    .line 1186
    .line 1187
    move-object/from16 v4, p2

    .line 1188
    .line 1189
    check-cast v4, Ljava/lang/Integer;

    .line 1190
    .line 1191
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 1192
    .line 1193
    .line 1194
    move-result v4

    .line 1195
    iget v0, v0, Ltj/i;->f:I

    .line 1196
    .line 1197
    invoke-static {v1, v2, v0, v3, v4}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->z(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;[Lki/a;ILl2/o;I)Llx0/b0;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v0

    .line 1201
    return-object v0

    .line 1202
    nop

    .line 1203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
