.class public final synthetic Ln70/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;II)V
    .locals 0

    .line 1
    const/16 p2, 0xe

    iput p2, p0, Ln70/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/d0;->e:Lx2/s;

    iput p3, p0, Ln70/d0;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;IIB)V
    .locals 0

    .line 2
    iput p3, p0, Ln70/d0;->d:I

    iput-object p1, p0, Ln70/d0;->e:Lx2/s;

    iput p2, p0, Ln70/d0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ln70/d0;->d:I

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 22
    .line 23
    invoke-static {p0, p1, p2}, Lx40/a;->r(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 41
    .line 42
    invoke-static {p0, p1, p2}, Lx40/a;->r(Lx2/s;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 58
    .line 59
    invoke-static {p0, p1, p2}, Lwy/a;->c(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 75
    .line 76
    invoke-static {p0, p1, p2}, Lwy/a;->a(Lx2/s;Ll2/o;I)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 81
    .line 82
    .line 83
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 92
    .line 93
    invoke-static {p0, p1, p2}, Lwy/a;->a(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 109
    .line 110
    invoke-static {p0, p1, p2}, Lv50/a;->h(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 126
    .line 127
    invoke-static {p0, p1, p2}, Luz/k0;->t(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 143
    .line 144
    invoke-static {p0, p1, p2}, Luz/k0;->r(Lx2/s;Ll2/o;I)V

    .line 145
    .line 146
    .line 147
    goto :goto_0

    .line 148
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 160
    .line 161
    invoke-static {p0, p1, p2}, Luz/k0;->r(Lx2/s;Ll2/o;I)V

    .line 162
    .line 163
    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 178
    .line 179
    invoke-static {p0, p1, p2}, Luz/g;->c(Lx2/s;Ll2/o;I)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 185
    .line 186
    .line 187
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 196
    .line 197
    invoke-static {p0, p1, p2}, Luz/g;->a(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 214
    .line 215
    invoke-static {p0, p1, p2}, Luz/g;->a(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ln70/d0;->f:I

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
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 232
    .line 233
    invoke-static {p0, p1, p2}, Lt10/a;->r(Lx2/s;Ll2/o;I)V

    .line 234
    .line 235
    .line 236
    goto/16 :goto_0

    .line 237
    .line 238
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    iget p2, p0, Ln70/d0;->f:I

    .line 242
    .line 243
    or-int/lit8 p2, p2, 0x1

    .line 244
    .line 245
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 246
    .line 247
    .line 248
    move-result p2

    .line 249
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 250
    .line 251
    invoke-static {p0, p1, p2}, Lt10/a;->p(Lx2/s;Ll2/o;I)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_0

    .line 255
    .line 256
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 257
    .line 258
    .line 259
    iget p2, p0, Ln70/d0;->f:I

    .line 260
    .line 261
    or-int/lit8 p2, p2, 0x1

    .line 262
    .line 263
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 264
    .line 265
    .line 266
    move-result p2

    .line 267
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 268
    .line 269
    invoke-static {p0, p1, p2}, Lt10/a;->p(Lx2/s;Ll2/o;I)V

    .line 270
    .line 271
    .line 272
    goto/16 :goto_0

    .line 273
    .line 274
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    const/4 p2, 0x1

    .line 278
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 279
    .line 280
    .line 281
    move-result p2

    .line 282
    iget v0, p0, Ln70/d0;->f:I

    .line 283
    .line 284
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 285
    .line 286
    invoke-static {p2, v0, p1, p0}, Lt1/b;->b(IILl2/o;Lx2/s;)V

    .line 287
    .line 288
    .line 289
    goto/16 :goto_0

    .line 290
    .line 291
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 292
    .line 293
    .line 294
    iget p2, p0, Ln70/d0;->f:I

    .line 295
    .line 296
    or-int/lit8 p2, p2, 0x1

    .line 297
    .line 298
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 299
    .line 300
    .line 301
    move-result p2

    .line 302
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 303
    .line 304
    invoke-static {p0, p1, p2}, Lkp/w5;->a(Lx2/s;Ll2/o;I)V

    .line 305
    .line 306
    .line 307
    goto/16 :goto_0

    .line 308
    .line 309
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 310
    .line 311
    .line 312
    iget p2, p0, Ln70/d0;->f:I

    .line 313
    .line 314
    or-int/lit8 p2, p2, 0x1

    .line 315
    .line 316
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 317
    .line 318
    .line 319
    move-result p2

    .line 320
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 321
    .line 322
    invoke-static {p0, p1, p2}, Loz/e;->c(Lx2/s;Ll2/o;I)V

    .line 323
    .line 324
    .line 325
    goto/16 :goto_0

    .line 326
    .line 327
    :pswitch_11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 328
    .line 329
    .line 330
    iget p2, p0, Ln70/d0;->f:I

    .line 331
    .line 332
    or-int/lit8 p2, p2, 0x1

    .line 333
    .line 334
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 335
    .line 336
    .line 337
    move-result p2

    .line 338
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 339
    .line 340
    invoke-static {p0, p1, p2}, Loz/e;->a(Lx2/s;Ll2/o;I)V

    .line 341
    .line 342
    .line 343
    goto/16 :goto_0

    .line 344
    .line 345
    :pswitch_12
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 346
    .line 347
    .line 348
    iget p2, p0, Ln70/d0;->f:I

    .line 349
    .line 350
    or-int/lit8 p2, p2, 0x1

    .line 351
    .line 352
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 353
    .line 354
    .line 355
    move-result p2

    .line 356
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 357
    .line 358
    invoke-static {p0, p1, p2}, Loz/e;->a(Lx2/s;Ll2/o;I)V

    .line 359
    .line 360
    .line 361
    goto/16 :goto_0

    .line 362
    .line 363
    :pswitch_13
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 364
    .line 365
    .line 366
    iget p2, p0, Ln70/d0;->f:I

    .line 367
    .line 368
    or-int/lit8 p2, p2, 0x1

    .line 369
    .line 370
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 371
    .line 372
    .line 373
    move-result p2

    .line 374
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 375
    .line 376
    invoke-static {p0, p1, p2}, Los0/a;->d(Lx2/s;Ll2/o;I)V

    .line 377
    .line 378
    .line 379
    goto/16 :goto_0

    .line 380
    .line 381
    :pswitch_14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 382
    .line 383
    .line 384
    iget p2, p0, Ln70/d0;->f:I

    .line 385
    .line 386
    or-int/lit8 p2, p2, 0x1

    .line 387
    .line 388
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 389
    .line 390
    .line 391
    move-result p2

    .line 392
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 393
    .line 394
    invoke-static {p0, p1, p2}, Los0/a;->d(Lx2/s;Ll2/o;I)V

    .line 395
    .line 396
    .line 397
    goto/16 :goto_0

    .line 398
    .line 399
    :pswitch_15
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 400
    .line 401
    .line 402
    iget p2, p0, Ln70/d0;->f:I

    .line 403
    .line 404
    or-int/lit8 p2, p2, 0x1

    .line 405
    .line 406
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 407
    .line 408
    .line 409
    move-result p2

    .line 410
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 411
    .line 412
    invoke-static {p0, p1, p2}, Lo90/b;->h(Lx2/s;Ll2/o;I)V

    .line 413
    .line 414
    .line 415
    goto/16 :goto_0

    .line 416
    .line 417
    :pswitch_16
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 418
    .line 419
    .line 420
    iget p2, p0, Ln70/d0;->f:I

    .line 421
    .line 422
    or-int/lit8 p2, p2, 0x1

    .line 423
    .line 424
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 425
    .line 426
    .line 427
    move-result p2

    .line 428
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 429
    .line 430
    invoke-static {p0, p1, p2}, Lo90/b;->h(Lx2/s;Ll2/o;I)V

    .line 431
    .line 432
    .line 433
    goto/16 :goto_0

    .line 434
    .line 435
    :pswitch_17
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 436
    .line 437
    .line 438
    iget p2, p0, Ln70/d0;->f:I

    .line 439
    .line 440
    or-int/lit8 p2, p2, 0x1

    .line 441
    .line 442
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 443
    .line 444
    .line 445
    move-result p2

    .line 446
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 447
    .line 448
    invoke-static {p0, p1, p2}, Lo00/a;->f(Lx2/s;Ll2/o;I)V

    .line 449
    .line 450
    .line 451
    goto/16 :goto_0

    .line 452
    .line 453
    :pswitch_18
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 454
    .line 455
    .line 456
    iget p2, p0, Ln70/d0;->f:I

    .line 457
    .line 458
    or-int/lit8 p2, p2, 0x1

    .line 459
    .line 460
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 461
    .line 462
    .line 463
    move-result p2

    .line 464
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 465
    .line 466
    invoke-static {p0, p1, p2}, Lo00/a;->d(Lx2/s;Ll2/o;I)V

    .line 467
    .line 468
    .line 469
    goto/16 :goto_0

    .line 470
    .line 471
    :pswitch_19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 472
    .line 473
    .line 474
    iget p2, p0, Ln70/d0;->f:I

    .line 475
    .line 476
    or-int/lit8 p2, p2, 0x1

    .line 477
    .line 478
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 479
    .line 480
    .line 481
    move-result p2

    .line 482
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 483
    .line 484
    invoke-static {p0, p1, p2}, Lo00/a;->d(Lx2/s;Ll2/o;I)V

    .line 485
    .line 486
    .line 487
    goto/16 :goto_0

    .line 488
    .line 489
    :pswitch_1a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 490
    .line 491
    .line 492
    iget p2, p0, Ln70/d0;->f:I

    .line 493
    .line 494
    or-int/lit8 p2, p2, 0x1

    .line 495
    .line 496
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 497
    .line 498
    .line 499
    move-result p2

    .line 500
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 501
    .line 502
    invoke-static {p0, p1, p2}, Lo00/a;->b(Lx2/s;Ll2/o;I)V

    .line 503
    .line 504
    .line 505
    goto/16 :goto_0

    .line 506
    .line 507
    :pswitch_1b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 508
    .line 509
    .line 510
    iget p2, p0, Ln70/d0;->f:I

    .line 511
    .line 512
    or-int/lit8 p2, p2, 0x1

    .line 513
    .line 514
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 515
    .line 516
    .line 517
    move-result p2

    .line 518
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 519
    .line 520
    invoke-static {p0, p1, p2}, Lo00/a;->b(Lx2/s;Ll2/o;I)V

    .line 521
    .line 522
    .line 523
    goto/16 :goto_0

    .line 524
    .line 525
    :pswitch_1c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 526
    .line 527
    .line 528
    iget p2, p0, Ln70/d0;->f:I

    .line 529
    .line 530
    or-int/lit8 p2, p2, 0x1

    .line 531
    .line 532
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 533
    .line 534
    .line 535
    move-result p2

    .line 536
    iget-object p0, p0, Ln70/d0;->e:Lx2/s;

    .line 537
    .line 538
    invoke-static {p0, p1, p2}, Ln70/a;->g0(Lx2/s;Ll2/o;I)V

    .line 539
    .line 540
    .line 541
    goto/16 :goto_0

    .line 542
    .line 543
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
