.class public final synthetic Ld00/b;
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
    iput p3, p0, Ld00/b;->d:I

    iput-object p1, p0, Ld00/b;->e:Lx2/s;

    iput p2, p0, Ld00/b;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;III)V
    .locals 0

    .line 2
    iput p4, p0, Ld00/b;->d:I

    iput-object p1, p0, Ld00/b;->e:Lx2/s;

    iput p3, p0, Ld00/b;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld00/b;->d:I

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 22
    .line 23
    invoke-static {p0, p1, p2}, Ln70/a;->g0(Lx2/s;Ll2/o;I)V

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 41
    .line 42
    invoke-static {p0, p1, p2}, Ln70/a;->Z(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 58
    .line 59
    invoke-static {p0, p1, p2}, Ln70/a;->r0(Lx2/s;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 75
    .line 76
    invoke-static {p0, p1, p2}, Ln70/a;->E(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 92
    .line 93
    invoke-static {p0, p1, p2}, Ln70/a;->E(Lx2/s;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 109
    .line 110
    invoke-static {p0, p1, p2}, Llp/se;->e(Lx2/s;Ll2/o;I)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 115
    .line 116
    .line 117
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 126
    .line 127
    invoke-static {p0, p1, p2}, Llp/se;->c(Lx2/s;Ll2/o;I)V

    .line 128
    .line 129
    .line 130
    goto :goto_0

    .line 131
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 143
    .line 144
    invoke-static {p0, p1, p2}, Llp/se;->c(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 160
    .line 161
    invoke-static {p0, p1, p2}, Llp/me;->a(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 178
    .line 179
    invoke-static {p0, p1, p2}, Llp/me;->b(Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 196
    .line 197
    invoke-static {p0, p1, p2}, Llp/me;->b(Lx2/s;Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_0

    .line 201
    .line 202
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 203
    .line 204
    .line 205
    iget p2, p0, Ld00/b;->f:I

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
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 214
    .line 215
    invoke-static {p0, p1, p2}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

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
    const/4 p2, 0x1

    .line 224
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 225
    .line 226
    .line 227
    move-result p2

    .line 228
    iget v0, p0, Ld00/b;->f:I

    .line 229
    .line 230
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 231
    .line 232
    invoke-static {p2, v0, p1, p0}, Li91/j0;->r(IILl2/o;Lx2/s;)V

    .line 233
    .line 234
    .line 235
    goto/16 :goto_0

    .line 236
    .line 237
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 238
    .line 239
    .line 240
    iget p2, p0, Ld00/b;->f:I

    .line 241
    .line 242
    or-int/lit8 p2, p2, 0x1

    .line 243
    .line 244
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 245
    .line 246
    .line 247
    move-result p2

    .line 248
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 249
    .line 250
    invoke-static {p0, p1, p2}, Li40/l1;->t0(Lx2/s;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    goto/16 :goto_0

    .line 254
    .line 255
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 256
    .line 257
    .line 258
    const/4 p2, 0x1

    .line 259
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 260
    .line 261
    .line 262
    move-result p2

    .line 263
    iget v0, p0, Ld00/b;->f:I

    .line 264
    .line 265
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 266
    .line 267
    invoke-static {p2, v0, p1, p0}, Li40/l1;->r0(IILl2/o;Lx2/s;)V

    .line 268
    .line 269
    .line 270
    goto/16 :goto_0

    .line 271
    .line 272
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    const/4 p2, 0x1

    .line 276
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 277
    .line 278
    .line 279
    move-result p2

    .line 280
    iget v0, p0, Ld00/b;->f:I

    .line 281
    .line 282
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 283
    .line 284
    invoke-static {p2, v0, p1, p0}, Li40/l1;->r0(IILl2/o;Lx2/s;)V

    .line 285
    .line 286
    .line 287
    goto/16 :goto_0

    .line 288
    .line 289
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 290
    .line 291
    .line 292
    iget p2, p0, Ld00/b;->f:I

    .line 293
    .line 294
    or-int/lit8 p2, p2, 0x1

    .line 295
    .line 296
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 297
    .line 298
    .line 299
    move-result p2

    .line 300
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 301
    .line 302
    invoke-static {p0, p1, p2}, Lha0/b;->i(Lx2/s;Ll2/o;I)V

    .line 303
    .line 304
    .line 305
    goto/16 :goto_0

    .line 306
    .line 307
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 308
    .line 309
    .line 310
    iget p2, p0, Ld00/b;->f:I

    .line 311
    .line 312
    or-int/lit8 p2, p2, 0x1

    .line 313
    .line 314
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 315
    .line 316
    .line 317
    move-result p2

    .line 318
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 319
    .line 320
    invoke-static {p0, p1, p2}, Lha0/b;->f(Lx2/s;Ll2/o;I)V

    .line 321
    .line 322
    .line 323
    goto/16 :goto_0

    .line 324
    .line 325
    :pswitch_11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 326
    .line 327
    .line 328
    iget p2, p0, Ld00/b;->f:I

    .line 329
    .line 330
    or-int/lit8 p2, p2, 0x1

    .line 331
    .line 332
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 333
    .line 334
    .line 335
    move-result p2

    .line 336
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 337
    .line 338
    invoke-static {p0, p1, p2}, Lha0/b;->f(Lx2/s;Ll2/o;I)V

    .line 339
    .line 340
    .line 341
    goto/16 :goto_0

    .line 342
    .line 343
    :pswitch_12
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 344
    .line 345
    .line 346
    iget p2, p0, Ld00/b;->f:I

    .line 347
    .line 348
    or-int/lit8 p2, p2, 0x1

    .line 349
    .line 350
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 351
    .line 352
    .line 353
    move-result p2

    .line 354
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 355
    .line 356
    invoke-static {p0, p1, p2}, Lh70/a;->a(Lx2/s;Ll2/o;I)V

    .line 357
    .line 358
    .line 359
    goto/16 :goto_0

    .line 360
    .line 361
    :pswitch_13
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 362
    .line 363
    .line 364
    iget p2, p0, Ld00/b;->f:I

    .line 365
    .line 366
    or-int/lit8 p2, p2, 0x1

    .line 367
    .line 368
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 369
    .line 370
    .line 371
    move-result p2

    .line 372
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 373
    .line 374
    invoke-static {p0, p1, p2}, Lf20/a;->a(Lx2/s;Ll2/o;I)V

    .line 375
    .line 376
    .line 377
    goto/16 :goto_0

    .line 378
    .line 379
    :pswitch_14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    iget p2, p0, Ld00/b;->f:I

    .line 383
    .line 384
    or-int/lit8 p2, p2, 0x1

    .line 385
    .line 386
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 387
    .line 388
    .line 389
    move-result p2

    .line 390
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 391
    .line 392
    invoke-static {p0, p1, p2}, Lf20/a;->a(Lx2/s;Ll2/o;I)V

    .line 393
    .line 394
    .line 395
    goto/16 :goto_0

    .line 396
    .line 397
    :pswitch_15
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 398
    .line 399
    .line 400
    iget p2, p0, Ld00/b;->f:I

    .line 401
    .line 402
    or-int/lit8 p2, p2, 0x1

    .line 403
    .line 404
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 405
    .line 406
    .line 407
    move-result p2

    .line 408
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 409
    .line 410
    invoke-static {p0, p1, p2}, Ldl0/e;->f(Lx2/s;Ll2/o;I)V

    .line 411
    .line 412
    .line 413
    goto/16 :goto_0

    .line 414
    .line 415
    :pswitch_16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 416
    .line 417
    .line 418
    iget p2, p0, Ld00/b;->f:I

    .line 419
    .line 420
    or-int/lit8 p2, p2, 0x1

    .line 421
    .line 422
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 423
    .line 424
    .line 425
    move-result p2

    .line 426
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 427
    .line 428
    invoke-static {p0, p1, p2}, Ljp/sf;->d(Lx2/s;Ll2/o;I)V

    .line 429
    .line 430
    .line 431
    goto/16 :goto_0

    .line 432
    .line 433
    :pswitch_17
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 434
    .line 435
    .line 436
    iget p2, p0, Ld00/b;->f:I

    .line 437
    .line 438
    or-int/lit8 p2, p2, 0x1

    .line 439
    .line 440
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 441
    .line 442
    .line 443
    move-result p2

    .line 444
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 445
    .line 446
    invoke-static {p0, p1, p2}, Ljp/sf;->b(Lx2/s;Ll2/o;I)V

    .line 447
    .line 448
    .line 449
    goto/16 :goto_0

    .line 450
    .line 451
    :pswitch_18
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 452
    .line 453
    .line 454
    iget p2, p0, Ld00/b;->f:I

    .line 455
    .line 456
    or-int/lit8 p2, p2, 0x1

    .line 457
    .line 458
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 459
    .line 460
    .line 461
    move-result p2

    .line 462
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 463
    .line 464
    invoke-static {p0, p1, p2}, Ljp/sf;->b(Lx2/s;Ll2/o;I)V

    .line 465
    .line 466
    .line 467
    goto/16 :goto_0

    .line 468
    .line 469
    :pswitch_19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 470
    .line 471
    .line 472
    iget p2, p0, Ld00/b;->f:I

    .line 473
    .line 474
    or-int/lit8 p2, p2, 0x1

    .line 475
    .line 476
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 477
    .line 478
    .line 479
    move-result p2

    .line 480
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 481
    .line 482
    invoke-static {p0, p1, p2}, Ld00/o;->i(Lx2/s;Ll2/o;I)V

    .line 483
    .line 484
    .line 485
    goto/16 :goto_0

    .line 486
    .line 487
    :pswitch_1a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 488
    .line 489
    .line 490
    iget p2, p0, Ld00/b;->f:I

    .line 491
    .line 492
    or-int/lit8 p2, p2, 0x1

    .line 493
    .line 494
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 495
    .line 496
    .line 497
    move-result p2

    .line 498
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 499
    .line 500
    invoke-static {p0, p1, p2}, Ld00/o;->i(Lx2/s;Ll2/o;I)V

    .line 501
    .line 502
    .line 503
    goto/16 :goto_0

    .line 504
    .line 505
    :pswitch_1b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 506
    .line 507
    .line 508
    iget p2, p0, Ld00/b;->f:I

    .line 509
    .line 510
    or-int/lit8 p2, p2, 0x1

    .line 511
    .line 512
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 513
    .line 514
    .line 515
    move-result p2

    .line 516
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 517
    .line 518
    invoke-static {p0, p1, p2}, Ld00/o;->e(Lx2/s;Ll2/o;I)V

    .line 519
    .line 520
    .line 521
    goto/16 :goto_0

    .line 522
    .line 523
    :pswitch_1c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 524
    .line 525
    .line 526
    iget p2, p0, Ld00/b;->f:I

    .line 527
    .line 528
    or-int/lit8 p2, p2, 0x1

    .line 529
    .line 530
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 531
    .line 532
    .line 533
    move-result p2

    .line 534
    iget-object p0, p0, Ld00/b;->e:Lx2/s;

    .line 535
    .line 536
    invoke-static {p0, p1, p2}, Ld00/o;->e(Lx2/s;Ll2/o;I)V

    .line 537
    .line 538
    .line 539
    goto/16 :goto_0

    .line 540
    .line 541
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
