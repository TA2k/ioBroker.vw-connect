.class public final synthetic Lle/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lle/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lle/b;->e:Ll2/b1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lle/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lg4/l0;

    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Lg4/l0;->d()Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 20
    .line 21
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 22
    .line 23
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    check-cast p1, Lt3/y;

    .line 30
    .line 31
    const-string v0, "it"

    .line 32
    .line 33
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    const/4 v1, 0x1

    .line 41
    invoke-interface {v0, p1, v1}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget p1, p1, Ld3/c;->d:F

    .line 46
    .line 47
    const/16 v0, 0x38

    .line 48
    .line 49
    int-to-float v0, v0

    .line 50
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    int-to-float v0, v0

    .line 55
    add-float/2addr p1, v0

    .line 56
    sget v0, Lxf0/f0;->a:F

    .line 57
    .line 58
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    int-to-float v0, v0

    .line 63
    cmpl-float p1, p1, v0

    .line 64
    .line 65
    if-lez p1, :cond_1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    const/4 v1, 0x0

    .line 69
    :goto_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 74
    .line 75
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_1
    check-cast p1, Lg4/l0;

    .line 82
    .line 83
    const-string v0, "it"

    .line 84
    .line 85
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 89
    .line 90
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :pswitch_2
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 95
    .line 96
    check-cast p1, Lt3/y;

    .line 97
    .line 98
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :pswitch_3
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 103
    .line 104
    check-cast p1, Lt3/y;

    .line 105
    .line 106
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :pswitch_4
    check-cast p1, Lt3/y;

    .line 111
    .line 112
    const-string v0, "it"

    .line 113
    .line 114
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-interface {p1}, Lt3/y;->O()Lt3/y;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    const/4 v0, 0x1

    .line 122
    const/4 v1, 0x0

    .line 123
    if-eqz p1, :cond_2

    .line 124
    .line 125
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    invoke-interface {v2, p1, v0}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    iget v2, p1, Ld3/c;->d:F

    .line 134
    .line 135
    iget p1, p1, Ld3/c;->b:F

    .line 136
    .line 137
    sub-float/2addr v2, p1

    .line 138
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {p1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    goto :goto_2

    .line 147
    :cond_2
    int-to-float p1, v1

    .line 148
    :goto_2
    const/16 v2, 0x1e

    .line 149
    .line 150
    int-to-float v2, v2

    .line 151
    invoke-static {p1, v2}, Ljava/lang/Float;->compare(FF)I

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    if-gez p1, :cond_3

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_3
    move v0, v1

    .line 159
    :goto_3
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 164
    .line 165
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    goto :goto_1

    .line 169
    :pswitch_5
    check-cast p1, Lt4/l;

    .line 170
    .line 171
    iget-wide v0, p1, Lt4/l;->a:J

    .line 172
    .line 173
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 174
    .line 175
    .line 176
    move-result-wide v0

    .line 177
    new-instance p1, Ld3/e;

    .line 178
    .line 179
    invoke-direct {p1, v0, v1}, Ld3/e;-><init>(J)V

    .line 180
    .line 181
    .line 182
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 183
    .line 184
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    goto :goto_1

    .line 188
    :pswitch_6
    check-cast p1, Lc3/t;

    .line 189
    .line 190
    const-string v0, "it"

    .line 191
    .line 192
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    check-cast p1, Lc3/u;

    .line 196
    .line 197
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 198
    .line 199
    .line 200
    move-result p1

    .line 201
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 206
    .line 207
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    goto/16 :goto_1

    .line 211
    .line 212
    :pswitch_7
    check-cast p1, Lzl/f;

    .line 213
    .line 214
    const-string v0, "it"

    .line 215
    .line 216
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 220
    .line 221
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 222
    .line 223
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    goto/16 :goto_1

    .line 227
    .line 228
    :pswitch_8
    check-cast p1, Lzl/e;

    .line 229
    .line 230
    const-string v0, "it"

    .line 231
    .line 232
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 236
    .line 237
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 238
    .line 239
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    goto/16 :goto_1

    .line 243
    .line 244
    :pswitch_9
    check-cast p1, Lt3/y;

    .line 245
    .line 246
    const-string v0, "it"

    .line 247
    .line 248
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    const/4 v1, 0x1

    .line 256
    invoke-interface {v0, p1, v1}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 257
    .line 258
    .line 259
    move-result-object p1

    .line 260
    iget p1, p1, Ld3/c;->d:F

    .line 261
    .line 262
    sget v0, Lxf0/f0;->a:F

    .line 263
    .line 264
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    int-to-float v0, v0

    .line 269
    cmpl-float p1, p1, v0

    .line 270
    .line 271
    if-lez p1, :cond_4

    .line 272
    .line 273
    goto :goto_4

    .line 274
    :cond_4
    const/4 v1, 0x0

    .line 275
    :goto_4
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 280
    .line 281
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    goto/16 :goto_1

    .line 285
    .line 286
    :pswitch_a
    check-cast p1, Ljn/a;

    .line 287
    .line 288
    const-string v0, "it"

    .line 289
    .line 290
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 294
    .line 295
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto/16 :goto_1

    .line 299
    .line 300
    :pswitch_b
    check-cast p1, Lt3/y;

    .line 301
    .line 302
    const-string v0, "it"

    .line 303
    .line 304
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    const/4 v1, 0x1

    .line 312
    invoke-interface {v0, p1, v1}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    iget p1, p1, Ld3/c;->d:F

    .line 317
    .line 318
    sget v0, Lxf0/f0;->a:F

    .line 319
    .line 320
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 321
    .line 322
    .line 323
    move-result v0

    .line 324
    int-to-float v0, v0

    .line 325
    cmpl-float p1, p1, v0

    .line 326
    .line 327
    if-lez p1, :cond_5

    .line 328
    .line 329
    goto :goto_5

    .line 330
    :cond_5
    const/4 v1, 0x0

    .line 331
    :goto_5
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 332
    .line 333
    .line 334
    move-result-object p1

    .line 335
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 336
    .line 337
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 338
    .line 339
    .line 340
    goto/16 :goto_1

    .line 341
    .line 342
    :pswitch_c
    check-cast p1, Lz9/y;

    .line 343
    .line 344
    const-string v0, "$this$navigator"

    .line 345
    .line 346
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    const-string v0, ""

    .line 350
    .line 351
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 352
    .line 353
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    iget-object p0, p1, Lz9/y;->b:Lca/g;

    .line 357
    .line 358
    invoke-virtual {p0}, Lca/g;->i()Lz9/v;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 363
    .line 364
    iget v0, v0, Lca/j;->a:I

    .line 365
    .line 366
    const/4 v1, 0x1

    .line 367
    const/4 v2, 0x0

    .line 368
    invoke-virtual {p0, v0, v1, v2}, Lca/g;->o(IZZ)Z

    .line 369
    .line 370
    .line 371
    move-result v0

    .line 372
    if-eqz v0, :cond_6

    .line 373
    .line 374
    invoke-virtual {p0}, Lca/g;->b()Z

    .line 375
    .line 376
    .line 377
    :cond_6
    const/4 p0, 0x0

    .line 378
    const/4 v0, 0x6

    .line 379
    const-string v1, "/overview"

    .line 380
    .line 381
    invoke-static {p1, v1, p0, v0}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 382
    .line 383
    .line 384
    goto/16 :goto_1

    .line 385
    .line 386
    :pswitch_d
    check-cast p1, Lz9/y;

    .line 387
    .line 388
    const-string v0, "$this$navigator"

    .line 389
    .line 390
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    const-string v0, ""

    .line 394
    .line 395
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 396
    .line 397
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    iget-object p0, p1, Lz9/y;->b:Lca/g;

    .line 401
    .line 402
    invoke-virtual {p0}, Lca/g;->i()Lz9/v;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 407
    .line 408
    iget v0, v0, Lca/j;->a:I

    .line 409
    .line 410
    const/4 v1, 0x1

    .line 411
    const/4 v2, 0x0

    .line 412
    invoke-virtual {p0, v0, v1, v2}, Lca/g;->o(IZZ)Z

    .line 413
    .line 414
    .line 415
    move-result v0

    .line 416
    if-eqz v0, :cond_7

    .line 417
    .line 418
    invoke-virtual {p0}, Lca/g;->b()Z

    .line 419
    .line 420
    .line 421
    :cond_7
    const/4 p0, 0x0

    .line 422
    const/4 v0, 0x6

    .line 423
    const-string v1, "/overview"

    .line 424
    .line 425
    invoke-static {p1, v1, p0, v0}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 426
    .line 427
    .line 428
    goto/16 :goto_1

    .line 429
    .line 430
    :pswitch_e
    check-cast p1, Ljava/lang/Float;

    .line 431
    .line 432
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 433
    .line 434
    .line 435
    move-result p1

    .line 436
    new-instance v0, Lqr0/l;

    .line 437
    .line 438
    const/16 v1, 0x64

    .line 439
    .line 440
    int-to-float v1, v1

    .line 441
    mul-float/2addr p1, v1

    .line 442
    float-to-int p1, p1

    .line 443
    invoke-direct {v0, p1}, Lqr0/l;-><init>(I)V

    .line 444
    .line 445
    .line 446
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 447
    .line 448
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 449
    .line 450
    .line 451
    goto/16 :goto_1

    .line 452
    .line 453
    :pswitch_f
    check-cast p1, Ljava/lang/Float;

    .line 454
    .line 455
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 456
    .line 457
    .line 458
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 459
    .line 460
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 461
    .line 462
    .line 463
    goto/16 :goto_1

    .line 464
    .line 465
    :pswitch_10
    check-cast p1, Ld3/b;

    .line 466
    .line 467
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 468
    .line 469
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object p0

    .line 473
    check-cast p0, Lay0/k;

    .line 474
    .line 475
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 476
    .line 477
    .line 478
    goto/16 :goto_1

    .line 479
    .line 480
    :pswitch_11
    check-cast p1, Ljava/util/List;

    .line 481
    .line 482
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 483
    .line 484
    if-eqz p0, :cond_8

    .line 485
    .line 486
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 487
    .line 488
    .line 489
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 490
    .line 491
    return-object p0

    .line 492
    :pswitch_12
    check-cast p1, Ld2/h;

    .line 493
    .line 494
    iget-boolean v0, p1, Ld2/h;->c:Z

    .line 495
    .line 496
    if-eqz v0, :cond_9

    .line 497
    .line 498
    iget-object p1, p1, Ld2/h;->b:Lg4/g;

    .line 499
    .line 500
    goto :goto_6

    .line 501
    :cond_9
    iget-object p1, p1, Ld2/h;->a:Lg4/g;

    .line 502
    .line 503
    :goto_6
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 504
    .line 505
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 506
    .line 507
    .line 508
    goto/16 :goto_1

    .line 509
    .line 510
    :pswitch_13
    check-cast p1, Lg4/l0;

    .line 511
    .line 512
    const-string v0, "it"

    .line 513
    .line 514
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 518
    .line 519
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 520
    .line 521
    .line 522
    goto/16 :goto_1

    .line 523
    .line 524
    :pswitch_14
    check-cast p1, Lb0/k1;

    .line 525
    .line 526
    const-string v0, "preview"

    .line 527
    .line 528
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 529
    .line 530
    .line 531
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 532
    .line 533
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 534
    .line 535
    .line 536
    goto/16 :goto_1

    .line 537
    .line 538
    :pswitch_15
    check-cast p1, Ljava/lang/Boolean;

    .line 539
    .line 540
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 541
    .line 542
    .line 543
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 544
    .line 545
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 546
    .line 547
    .line 548
    goto/16 :goto_1

    .line 549
    .line 550
    :pswitch_16
    check-cast p1, Lt3/y;

    .line 551
    .line 552
    const-string v0, "it"

    .line 553
    .line 554
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    new-instance v0, Lmc/e;

    .line 558
    .line 559
    const/16 v1, 0x1c

    .line 560
    .line 561
    invoke-direct {v0, p1, v1}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 562
    .line 563
    .line 564
    sget-object v1, Lk1/i1;->a:Lk1/i1;

    .line 565
    .line 566
    invoke-static {v1, v0}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 567
    .line 568
    .line 569
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 570
    .line 571
    .line 572
    move-result-object v0

    .line 573
    const/4 v1, 0x1

    .line 574
    invoke-interface {v0, p1, v1}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 575
    .line 576
    .line 577
    move-result-object p1

    .line 578
    iget p1, p1, Ld3/c;->d:F

    .line 579
    .line 580
    sget v0, Lxf0/f0;->a:F

    .line 581
    .line 582
    invoke-static {v0}, Lxf0/i0;->O(F)I

    .line 583
    .line 584
    .line 585
    move-result v0

    .line 586
    int-to-float v0, v0

    .line 587
    cmpl-float p1, p1, v0

    .line 588
    .line 589
    if-lez p1, :cond_a

    .line 590
    .line 591
    goto :goto_7

    .line 592
    :cond_a
    const/4 v1, 0x0

    .line 593
    :goto_7
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 594
    .line 595
    .line 596
    move-result-object p1

    .line 597
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 598
    .line 599
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 600
    .line 601
    .line 602
    goto/16 :goto_1

    .line 603
    .line 604
    :pswitch_17
    check-cast p1, Lg4/l0;

    .line 605
    .line 606
    const-string v0, "it"

    .line 607
    .line 608
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 612
    .line 613
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 614
    .line 615
    .line 616
    goto/16 :goto_1

    .line 617
    .line 618
    :pswitch_18
    check-cast p1, Lg4/l0;

    .line 619
    .line 620
    const-string v0, "it"

    .line 621
    .line 622
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 623
    .line 624
    .line 625
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 626
    .line 627
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 628
    .line 629
    .line 630
    goto/16 :goto_1

    .line 631
    .line 632
    :pswitch_19
    check-cast p1, Lt3/y;

    .line 633
    .line 634
    const-string v0, "layoutCoordinates"

    .line 635
    .line 636
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    const-wide/16 v0, 0x0

    .line 640
    .line 641
    invoke-interface {p1, v0, v1}, Lt3/y;->R(J)J

    .line 642
    .line 643
    .line 644
    move-result-wide v0

    .line 645
    new-instance p1, Ld3/b;

    .line 646
    .line 647
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 648
    .line 649
    .line 650
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 651
    .line 652
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 653
    .line 654
    .line 655
    goto/16 :goto_1

    .line 656
    .line 657
    :pswitch_1a
    check-cast p1, Lt3/y;

    .line 658
    .line 659
    const-string v0, "coordinates"

    .line 660
    .line 661
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    invoke-interface {p1}, Lt3/y;->O()Lt3/y;

    .line 665
    .line 666
    .line 667
    move-result-object p1

    .line 668
    if-eqz p1, :cond_b

    .line 669
    .line 670
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 671
    .line 672
    .line 673
    move-result-object v0

    .line 674
    const/4 v1, 0x1

    .line 675
    invoke-interface {v0, p1, v1}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 676
    .line 677
    .line 678
    move-result-object p1

    .line 679
    iget v0, p1, Ld3/c;->d:F

    .line 680
    .line 681
    iget p1, p1, Ld3/c;->b:F

    .line 682
    .line 683
    sub-float/2addr v0, p1

    .line 684
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 685
    .line 686
    .line 687
    move-result-object p1

    .line 688
    invoke-static {p1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 689
    .line 690
    .line 691
    move-result p1

    .line 692
    new-instance v0, Lt4/f;

    .line 693
    .line 694
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 695
    .line 696
    .line 697
    goto :goto_8

    .line 698
    :cond_b
    const/4 v0, 0x0

    .line 699
    :goto_8
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 700
    .line 701
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 702
    .line 703
    .line 704
    goto/16 :goto_1

    .line 705
    .line 706
    :pswitch_1b
    check-cast p1, Lt3/y;

    .line 707
    .line 708
    const-string v0, "it"

    .line 709
    .line 710
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 711
    .line 712
    .line 713
    invoke-interface {p1}, Lt3/y;->h()J

    .line 714
    .line 715
    .line 716
    move-result-wide v0

    .line 717
    const-wide v2, 0xffffffffL

    .line 718
    .line 719
    .line 720
    .line 721
    .line 722
    and-long/2addr v0, v2

    .line 723
    long-to-int p1, v0

    .line 724
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 725
    .line 726
    .line 727
    move-result-object p1

    .line 728
    invoke-static {p1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 729
    .line 730
    .line 731
    move-result p1

    .line 732
    new-instance v0, Lt4/f;

    .line 733
    .line 734
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 735
    .line 736
    .line 737
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 738
    .line 739
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 740
    .line 741
    .line 742
    goto/16 :goto_1

    .line 743
    .line 744
    :pswitch_1c
    check-cast p1, Lpe/b;

    .line 745
    .line 746
    const-string v0, "it"

    .line 747
    .line 748
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 749
    .line 750
    .line 751
    iget-object p0, p0, Lle/b;->e:Ll2/b1;

    .line 752
    .line 753
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 754
    .line 755
    .line 756
    goto/16 :goto_1

    .line 757
    .line 758
    nop

    .line 759
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
