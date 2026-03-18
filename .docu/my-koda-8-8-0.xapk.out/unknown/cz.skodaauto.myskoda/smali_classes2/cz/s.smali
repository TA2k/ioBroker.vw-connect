.class public final synthetic Lcz/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(ILay0/a;)V
    .locals 1

    .line 1
    const/16 v0, 0xc

    iput v0, p0, Lcz/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lcz/s;->f:I

    iput-object p2, p0, Lcz/s;->e:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(ILay0/a;II)V
    .locals 0

    .line 2
    iput p4, p0, Lcz/s;->d:I

    iput p1, p0, Lcz/s;->f:I

    iput-object p2, p0, Lcz/s;->e:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;I)V
    .locals 1

    .line 3
    const/16 v0, 0xe

    iput v0, p0, Lcz/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/s;->e:Lay0/a;

    iput p2, p0, Lcz/s;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;II)V
    .locals 0

    .line 4
    iput p3, p0, Lcz/s;->d:I

    iput-object p1, p0, Lcz/s;->e:Lay0/a;

    iput p2, p0, Lcz/s;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lcz/s;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lcz/s;->f:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 22
    .line 23
    invoke-static {p0, p1, p2}, Lz70/l;->b(Lay0/a;Ll2/o;I)V

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 30
    .line 31
    .line 32
    iget p2, p0, Lcz/s;->f:I

    .line 33
    .line 34
    or-int/lit8 p2, p2, 0x1

    .line 35
    .line 36
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 41
    .line 42
    invoke-static {p0, p1, p2}, Lz70/l;->w(Lay0/a;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 47
    .line 48
    .line 49
    iget p2, p0, Lcz/s;->f:I

    .line 50
    .line 51
    or-int/lit8 p2, p2, 0x1

    .line 52
    .line 53
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 58
    .line 59
    invoke-static {p0, p1, p2}, Lxk0/e0;->f(Lay0/a;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 64
    .line 65
    .line 66
    iget p2, p0, Lcz/s;->f:I

    .line 67
    .line 68
    or-int/lit8 p2, p2, 0x1

    .line 69
    .line 70
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 75
    .line 76
    invoke-static {p0, p1, p2}, Llp/qe;->a(Lay0/a;Ll2/o;I)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    iget p2, p0, Lcz/s;->f:I

    .line 84
    .line 85
    or-int/lit8 p2, p2, 0x1

    .line 86
    .line 87
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 92
    .line 93
    invoke-static {p0, p1, p2}, Lw00/a;->n(Lay0/a;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 98
    .line 99
    .line 100
    iget p2, p0, Lcz/s;->f:I

    .line 101
    .line 102
    or-int/lit8 p2, p2, 0x1

    .line 103
    .line 104
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 109
    .line 110
    invoke-static {p0, p1, p2}, Lvu0/g;->d(Lay0/a;Ll2/o;I)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    iget p2, p0, Lcz/s;->f:I

    .line 118
    .line 119
    or-int/lit8 p2, p2, 0x1

    .line 120
    .line 121
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 126
    .line 127
    invoke-static {p0, p1, p2}, Lv50/a;->B(Lay0/a;Ll2/o;I)V

    .line 128
    .line 129
    .line 130
    goto :goto_0

    .line 131
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    iget p2, p0, Lcz/s;->f:I

    .line 135
    .line 136
    or-int/lit8 p2, p2, 0x1

    .line 137
    .line 138
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 143
    .line 144
    invoke-static {p0, p1, p2}, Lv50/a;->y(Lay0/a;Ll2/o;I)V

    .line 145
    .line 146
    .line 147
    goto :goto_0

    .line 148
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 149
    .line 150
    .line 151
    iget p2, p0, Lcz/s;->f:I

    .line 152
    .line 153
    or-int/lit8 p2, p2, 0x1

    .line 154
    .line 155
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 156
    .line 157
    .line 158
    move-result p2

    .line 159
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 160
    .line 161
    invoke-static {p0, p1, p2}, Luz/t;->g(Lay0/a;Ll2/o;I)V

    .line 162
    .line 163
    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 167
    .line 168
    .line 169
    iget p2, p0, Lcz/s;->f:I

    .line 170
    .line 171
    or-int/lit8 p2, p2, 0x1

    .line 172
    .line 173
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 174
    .line 175
    .line 176
    move-result p2

    .line 177
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 178
    .line 179
    invoke-static {p0, p1, p2}, Luz/k0;->y(Lay0/a;Ll2/o;I)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 185
    .line 186
    .line 187
    iget p2, p0, Lcz/s;->f:I

    .line 188
    .line 189
    or-int/lit8 p2, p2, 0x1

    .line 190
    .line 191
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 192
    .line 193
    .line 194
    move-result p2

    .line 195
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 196
    .line 197
    invoke-static {p0, p1, p2}, Luz/k0;->j(Lay0/a;Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_0

    .line 201
    .line 202
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 203
    .line 204
    .line 205
    iget p2, p0, Lcz/s;->f:I

    .line 206
    .line 207
    or-int/lit8 p2, p2, 0x1

    .line 208
    .line 209
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 210
    .line 211
    .line 212
    move-result p2

    .line 213
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 214
    .line 215
    invoke-static {p0, p1, p2}, Ll20/a;->t(Lay0/a;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    goto/16 :goto_0

    .line 219
    .line 220
    :pswitch_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 221
    .line 222
    .line 223
    iget p2, p0, Lcz/s;->f:I

    .line 224
    .line 225
    or-int/lit8 p2, p2, 0x1

    .line 226
    .line 227
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 228
    .line 229
    .line 230
    move-result p2

    .line 231
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 232
    .line 233
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 234
    .line 235
    invoke-static {p2, p0, p1, v0}, Liz/c;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 236
    .line 237
    .line 238
    goto/16 :goto_0

    .line 239
    .line 240
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 241
    .line 242
    .line 243
    iget p2, p0, Lcz/s;->f:I

    .line 244
    .line 245
    or-int/lit8 p2, p2, 0x1

    .line 246
    .line 247
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 248
    .line 249
    .line 250
    move-result p2

    .line 251
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 252
    .line 253
    invoke-static {p0, p1, p2}, Lit0/b;->c(Lay0/a;Ll2/o;I)V

    .line 254
    .line 255
    .line 256
    goto/16 :goto_0

    .line 257
    .line 258
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 259
    .line 260
    .line 261
    move-result p2

    .line 262
    and-int/lit8 v0, p2, 0x3

    .line 263
    .line 264
    const/4 v1, 0x2

    .line 265
    const/4 v2, 0x1

    .line 266
    if-eq v0, v1, :cond_0

    .line 267
    .line 268
    move v0, v2

    .line 269
    goto :goto_1

    .line 270
    :cond_0
    const/4 v0, 0x0

    .line 271
    :goto_1
    and-int/2addr p2, v2

    .line 272
    move-object v5, p1

    .line 273
    check-cast v5, Ll2/t;

    .line 274
    .line 275
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 276
    .line 277
    .line 278
    move-result p1

    .line 279
    if-eqz p1, :cond_1

    .line 280
    .line 281
    sget-object v2, Li91/j4;->b:Li91/a4;

    .line 282
    .line 283
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 284
    .line 285
    sget-object p2, Lx2/c;->i:Lx2/j;

    .line 286
    .line 287
    sget-object v0, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 288
    .line 289
    invoke-virtual {v0, p1, p2}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v3

    .line 293
    const/16 v6, 0x30

    .line 294
    .line 295
    const/4 v7, 0x0

    .line 296
    iget v1, p0, Lcz/s;->f:I

    .line 297
    .line 298
    iget-object v4, p0, Lcz/s;->e:Lay0/a;

    .line 299
    .line 300
    invoke-static/range {v1 .. v7}, Li91/j4;->e(ILi91/a4;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 301
    .line 302
    .line 303
    goto :goto_2

    .line 304
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 305
    .line 306
    .line 307
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 308
    .line 309
    return-object p0

    .line 310
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 311
    .line 312
    .line 313
    iget p2, p0, Lcz/s;->f:I

    .line 314
    .line 315
    or-int/lit8 p2, p2, 0x1

    .line 316
    .line 317
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 318
    .line 319
    .line 320
    move-result p2

    .line 321
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 322
    .line 323
    invoke-static {p0, p1, p2}, Li40/k3;->b(Lay0/a;Ll2/o;I)V

    .line 324
    .line 325
    .line 326
    goto/16 :goto_0

    .line 327
    .line 328
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 329
    .line 330
    .line 331
    iget p2, p0, Lcz/s;->f:I

    .line 332
    .line 333
    or-int/lit8 p2, p2, 0x1

    .line 334
    .line 335
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 336
    .line 337
    .line 338
    move-result p2

    .line 339
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 340
    .line 341
    invoke-static {p0, p1, p2}, Li40/k3;->a(Lay0/a;Ll2/o;I)V

    .line 342
    .line 343
    .line 344
    goto/16 :goto_0

    .line 345
    .line 346
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 347
    .line 348
    .line 349
    iget p2, p0, Lcz/s;->f:I

    .line 350
    .line 351
    or-int/lit8 p2, p2, 0x1

    .line 352
    .line 353
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 354
    .line 355
    .line 356
    move-result p2

    .line 357
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 358
    .line 359
    invoke-static {p0, p1, p2}, Li40/l1;->v0(Lay0/a;Ll2/o;I)V

    .line 360
    .line 361
    .line 362
    goto/16 :goto_0

    .line 363
    .line 364
    :pswitch_11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    const/4 p2, 0x1

    .line 368
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 369
    .line 370
    .line 371
    move-result p2

    .line 372
    iget v0, p0, Lcz/s;->f:I

    .line 373
    .line 374
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 375
    .line 376
    invoke-static {v0, p2, p0, p1}, Li40/o0;->a(IILay0/a;Ll2/o;)V

    .line 377
    .line 378
    .line 379
    goto/16 :goto_0

    .line 380
    .line 381
    :pswitch_12
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 382
    .line 383
    .line 384
    const/4 p2, 0x1

    .line 385
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 386
    .line 387
    .line 388
    move-result p2

    .line 389
    iget v0, p0, Lcz/s;->f:I

    .line 390
    .line 391
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 392
    .line 393
    invoke-static {v0, p2, p0, p1}, Li40/i;->a(IILay0/a;Ll2/o;)V

    .line 394
    .line 395
    .line 396
    goto/16 :goto_0

    .line 397
    .line 398
    :pswitch_13
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 399
    .line 400
    .line 401
    iget p2, p0, Lcz/s;->f:I

    .line 402
    .line 403
    or-int/lit8 p2, p2, 0x1

    .line 404
    .line 405
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 406
    .line 407
    .line 408
    move-result p2

    .line 409
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 410
    .line 411
    invoke-static {p0, p1, p2}, Lh70/m;->i(Lay0/a;Ll2/o;I)V

    .line 412
    .line 413
    .line 414
    goto/16 :goto_0

    .line 415
    .line 416
    :pswitch_14
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 417
    .line 418
    .line 419
    iget p2, p0, Lcz/s;->f:I

    .line 420
    .line 421
    or-int/lit8 p2, p2, 0x1

    .line 422
    .line 423
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 424
    .line 425
    .line 426
    move-result p2

    .line 427
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 428
    .line 429
    invoke-static {p0, p1, p2}, Lh60/a;->a(Lay0/a;Ll2/o;I)V

    .line 430
    .line 431
    .line 432
    goto/16 :goto_0

    .line 433
    .line 434
    :pswitch_15
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    iget p2, p0, Lcz/s;->f:I

    .line 438
    .line 439
    or-int/lit8 p2, p2, 0x1

    .line 440
    .line 441
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 442
    .line 443
    .line 444
    move-result p2

    .line 445
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 446
    .line 447
    invoke-static {p0, p1, p2}, Lh2/r;->o(Lay0/a;Ll2/o;I)V

    .line 448
    .line 449
    .line 450
    goto/16 :goto_0

    .line 451
    .line 452
    :pswitch_16
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 453
    .line 454
    .line 455
    iget p2, p0, Lcz/s;->f:I

    .line 456
    .line 457
    or-int/lit8 p2, p2, 0x1

    .line 458
    .line 459
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 460
    .line 461
    .line 462
    move-result p2

    .line 463
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 464
    .line 465
    invoke-static {p0, p1, p2}, Lh10/a;->h(Lay0/a;Ll2/o;I)V

    .line 466
    .line 467
    .line 468
    goto/16 :goto_0

    .line 469
    .line 470
    :pswitch_17
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 471
    .line 472
    .line 473
    iget p2, p0, Lcz/s;->f:I

    .line 474
    .line 475
    or-int/lit8 p2, p2, 0x1

    .line 476
    .line 477
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 478
    .line 479
    .line 480
    move-result p2

    .line 481
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 482
    .line 483
    invoke-static {p0, p1, p2}, Ld80/b;->e(Lay0/a;Ll2/o;I)V

    .line 484
    .line 485
    .line 486
    goto/16 :goto_0

    .line 487
    .line 488
    :pswitch_18
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 489
    .line 490
    .line 491
    iget p2, p0, Lcz/s;->f:I

    .line 492
    .line 493
    or-int/lit8 p2, p2, 0x1

    .line 494
    .line 495
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 496
    .line 497
    .line 498
    move-result p2

    .line 499
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 500
    .line 501
    invoke-static {p0, p1, p2}, Ld80/b;->e(Lay0/a;Ll2/o;I)V

    .line 502
    .line 503
    .line 504
    goto/16 :goto_0

    .line 505
    .line 506
    :pswitch_19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 507
    .line 508
    .line 509
    iget p2, p0, Lcz/s;->f:I

    .line 510
    .line 511
    or-int/lit8 p2, p2, 0x1

    .line 512
    .line 513
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 514
    .line 515
    .line 516
    move-result p2

    .line 517
    iget-object p0, p0, Lcz/s;->e:Lay0/a;

    .line 518
    .line 519
    invoke-static {p0, p1, p2}, Lcz/t;->k(Lay0/a;Ll2/o;I)V

    .line 520
    .line 521
    .line 522
    goto/16 :goto_0

    .line 523
    .line 524
    nop

    .line 525
    :pswitch_data_0
    .packed-switch 0x0
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
