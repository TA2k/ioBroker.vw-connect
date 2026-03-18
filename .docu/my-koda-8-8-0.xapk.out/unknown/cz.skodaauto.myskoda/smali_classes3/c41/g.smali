.class public final Lc41/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lc41/g;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lc41/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lxy/f;

    .line 15
    .line 16
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ljava/util/List;

    .line 19
    .line 20
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, p0}, Lxy/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lym0/b;

    .line 38
    .line 39
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Ljava/util/List;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {v0, v1, p0}, Lym0/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    move-object v3, p1

    .line 57
    check-cast v3, Lv2/j;

    .line 58
    .line 59
    sget-object p1, Lv2/l;->c:Ljava/lang/Object;

    .line 60
    .line 61
    monitor-enter p1

    .line 62
    :try_start_0
    sget-wide v1, Lv2/l;->e:J

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    int-to-long v4, v0

    .line 66
    add-long/2addr v4, v1

    .line 67
    sput-wide v4, Lv2/l;->e:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    monitor-exit p1

    .line 70
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v4, p1

    .line 73
    check-cast v4, Lay0/k;

    .line 74
    .line 75
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v5, p0

    .line 78
    check-cast v5, Lay0/k;

    .line 79
    .line 80
    new-instance v0, Lv2/b;

    .line 81
    .line 82
    invoke-direct/range {v0 .. v5}, Lv2/b;-><init>(JLv2/j;Lay0/k;Lay0/k;)V

    .line 83
    .line 84
    .line 85
    return-object v0

    .line 86
    :catchall_0
    move-exception v0

    .line 87
    move-object p0, v0

    .line 88
    monitor-exit p1

    .line 89
    throw p0

    .line 90
    :pswitch_2
    check-cast p1, Ljava/lang/Throwable;

    .line 91
    .line 92
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast p1, Luu/g;

    .line 95
    .line 96
    iget-object v0, p1, Luu/g;->d:Llx0/b0;

    .line 97
    .line 98
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Luu/f;

    .line 103
    .line 104
    monitor-enter v1

    .line 105
    :try_start_1
    iget-object v0, p1, Luu/g;->f:Ll2/j1;

    .line 106
    .line 107
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    check-cast v0, Luu/d;

    .line 112
    .line 113
    if-ne v0, p0, :cond_0

    .line 114
    .line 115
    iget-object p0, p1, Luu/g;->f:Ll2/j1;

    .line 116
    .line 117
    const/4 p1, 0x0

    .line 118
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :catchall_1
    move-exception v0

    .line 123
    move-object p0, v0

    .line 124
    goto :goto_1

    .line 125
    :cond_0
    :goto_0
    monitor-exit v1

    .line 126
    return-object v1

    .line 127
    :goto_1
    monitor-exit v1

    .line 128
    throw p0

    .line 129
    :pswitch_3
    check-cast p1, Ln3/b;

    .line 130
    .line 131
    iget-object p1, p1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 132
    .line 133
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Lc3/j;

    .line 136
    .line 137
    invoke-virtual {p1}, Landroid/view/InputEvent;->getDevice()Landroid/view/InputDevice;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    const/4 v2, 0x0

    .line 142
    if-nez v1, :cond_1

    .line 143
    .line 144
    goto/16 :goto_2

    .line 145
    .line 146
    :cond_1
    const/16 v3, 0x201

    .line 147
    .line 148
    invoke-virtual {v1, v3}, Landroid/view/InputDevice;->supportsSource(I)Z

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    if-nez v3, :cond_2

    .line 153
    .line 154
    goto/16 :goto_2

    .line 155
    .line 156
    :cond_2
    invoke-virtual {v1}, Landroid/view/InputDevice;->isVirtual()Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-eqz v1, :cond_3

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_3
    invoke-static {p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    const/4 v3, 0x2

    .line 168
    if-ne v1, v3, :cond_a

    .line 169
    .line 170
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getSource()I

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    const/16 v3, 0x101

    .line 175
    .line 176
    if-ne v1, v3, :cond_4

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :cond_4
    const/16 v1, 0x13

    .line 180
    .line 181
    invoke-static {v1, p1}, Lt1/l0;->m(ILandroid/view/KeyEvent;)Z

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    if-eqz v1, :cond_5

    .line 186
    .line 187
    const/4 p0, 0x5

    .line 188
    check-cast v0, Lc3/l;

    .line 189
    .line 190
    invoke-virtual {v0, p0}, Lc3/l;->h(I)Z

    .line 191
    .line 192
    .line 193
    move-result v2

    .line 194
    goto :goto_2

    .line 195
    :cond_5
    const/16 v1, 0x14

    .line 196
    .line 197
    invoke-static {v1, p1}, Lt1/l0;->m(ILandroid/view/KeyEvent;)Z

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    if-eqz v1, :cond_6

    .line 202
    .line 203
    const/4 p0, 0x6

    .line 204
    check-cast v0, Lc3/l;

    .line 205
    .line 206
    invoke-virtual {v0, p0}, Lc3/l;->h(I)Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    goto :goto_2

    .line 211
    :cond_6
    const/16 v1, 0x15

    .line 212
    .line 213
    invoke-static {v1, p1}, Lt1/l0;->m(ILandroid/view/KeyEvent;)Z

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    if-eqz v1, :cond_7

    .line 218
    .line 219
    const/4 p0, 0x3

    .line 220
    check-cast v0, Lc3/l;

    .line 221
    .line 222
    invoke-virtual {v0, p0}, Lc3/l;->h(I)Z

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    goto :goto_2

    .line 227
    :cond_7
    const/16 v1, 0x16

    .line 228
    .line 229
    invoke-static {v1, p1}, Lt1/l0;->m(ILandroid/view/KeyEvent;)Z

    .line 230
    .line 231
    .line 232
    move-result v1

    .line 233
    if-eqz v1, :cond_8

    .line 234
    .line 235
    const/4 p0, 0x4

    .line 236
    check-cast v0, Lc3/l;

    .line 237
    .line 238
    invoke-virtual {v0, p0}, Lc3/l;->h(I)Z

    .line 239
    .line 240
    .line 241
    move-result v2

    .line 242
    goto :goto_2

    .line 243
    :cond_8
    const/16 v0, 0x17

    .line 244
    .line 245
    invoke-static {v0, p1}, Lt1/l0;->m(ILandroid/view/KeyEvent;)Z

    .line 246
    .line 247
    .line 248
    move-result p1

    .line 249
    if-eqz p1, :cond_a

    .line 250
    .line 251
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p0, Lt1/p0;

    .line 254
    .line 255
    iget-object p0, p0, Lt1/p0;->c:Lw3/b2;

    .line 256
    .line 257
    if-eqz p0, :cond_9

    .line 258
    .line 259
    check-cast p0, Lw3/i1;

    .line 260
    .line 261
    invoke-virtual {p0}, Lw3/i1;->b()V

    .line 262
    .line 263
    .line 264
    :cond_9
    const/4 v2, 0x1

    .line 265
    :cond_a
    :goto_2
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    return-object p0

    .line 270
    :pswitch_4
    check-cast p1, Ln3/b;

    .line 271
    .line 272
    iget-object p1, p1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 273
    .line 274
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v0, Lt1/p0;

    .line 277
    .line 278
    invoke-virtual {v0}, Lt1/p0;->a()Lt1/c0;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    sget-object v1, Lt1/c0;->e:Lt1/c0;

    .line 283
    .line 284
    if-ne v0, v1, :cond_b

    .line 285
    .line 286
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 287
    .line 288
    .line 289
    move-result v0

    .line 290
    const/4 v1, 0x4

    .line 291
    if-ne v0, v1, :cond_b

    .line 292
    .line 293
    invoke-static {p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 294
    .line 295
    .line 296
    move-result p1

    .line 297
    const/4 v0, 0x1

    .line 298
    if-ne p1, v0, :cond_b

    .line 299
    .line 300
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 301
    .line 302
    check-cast p0, Le2/w0;

    .line 303
    .line 304
    const/4 p1, 0x0

    .line 305
    invoke-virtual {p0, p1}, Le2/w0;->g(Ld3/b;)V

    .line 306
    .line 307
    .line 308
    goto :goto_3

    .line 309
    :cond_b
    const/4 v0, 0x0

    .line 310
    :goto_3
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    return-object p0

    .line 315
    :pswitch_5
    check-cast p1, Ljava/lang/Number;

    .line 316
    .line 317
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 318
    .line 319
    .line 320
    move-result p1

    .line 321
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v0, Lr40/e;

    .line 324
    .line 325
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast p0, Ljava/util/List;

    .line 328
    .line 329
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    invoke-virtual {v0, p0}, Lr40/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    return-object p0

    .line 338
    :pswitch_6
    check-cast p1, Ljava/lang/Number;

    .line 339
    .line 340
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 341
    .line 342
    .line 343
    move-result p1

    .line 344
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v0, Lr40/e;

    .line 347
    .line 348
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast p0, Ljava/util/List;

    .line 351
    .line 352
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object p0

    .line 356
    invoke-virtual {v0, p0}, Lr40/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    return-object p0

    .line 361
    :pswitch_7
    check-cast p1, Ljava/lang/Number;

    .line 362
    .line 363
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 364
    .line 365
    .line 366
    move-result p1

    .line 367
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v0, Lnc0/l;

    .line 370
    .line 371
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 372
    .line 373
    .line 374
    move-result-object v1

    .line 375
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast p0, Ljava/util/List;

    .line 378
    .line 379
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object p0

    .line 383
    invoke-virtual {v0, v1, p0}, Lnc0/l;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object p0

    .line 387
    return-object p0

    .line 388
    :pswitch_8
    check-cast p1, Lh2/sa;

    .line 389
    .line 390
    const-string v0, "it"

    .line 391
    .line 392
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 393
    .line 394
    .line 395
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast p1, Lay0/k;

    .line 398
    .line 399
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast p0, Lbl0/o;

    .line 402
    .line 403
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 407
    .line 408
    return-object p0

    .line 409
    :pswitch_9
    check-cast p1, Ljava/lang/Number;

    .line 410
    .line 411
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 412
    .line 413
    .line 414
    move-result p1

    .line 415
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 416
    .line 417
    check-cast v0, Lnh/i;

    .line 418
    .line 419
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast p0, Ljava/util/List;

    .line 422
    .line 423
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object p0

    .line 427
    invoke-virtual {v0, p0}, Lnh/i;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object p0

    .line 431
    return-object p0

    .line 432
    :pswitch_a
    check-cast p1, Ljava/lang/Throwable;

    .line 433
    .line 434
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 435
    .line 436
    check-cast p1, La8/b;

    .line 437
    .line 438
    iget-object v1, p1, La8/b;->f:Ljava/lang/Object;

    .line 439
    .line 440
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 441
    .line 442
    check-cast p0, Lvy0/l;

    .line 443
    .line 444
    monitor-enter v1

    .line 445
    :try_start_2
    iget-object p1, p1, La8/b;->g:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast p1, Ljava/util/ArrayList;

    .line 448
    .line 449
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 450
    .line 451
    .line 452
    monitor-exit v1

    .line 453
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object p0

    .line 456
    :catchall_2
    move-exception v0

    .line 457
    move-object p0, v0

    .line 458
    monitor-exit v1

    .line 459
    throw p0

    .line 460
    :pswitch_b
    check-cast p1, Lc3/t;

    .line 461
    .line 462
    const-string v0, "it"

    .line 463
    .line 464
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 465
    .line 466
    .line 467
    check-cast p1, Lc3/u;

    .line 468
    .line 469
    invoke-virtual {p1}, Lc3/u;->a()Z

    .line 470
    .line 471
    .line 472
    move-result p1

    .line 473
    if-eqz p1, :cond_c

    .line 474
    .line 475
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 476
    .line 477
    check-cast p1, Ljv0/h;

    .line 478
    .line 479
    iget-boolean p1, p1, Ljv0/h;->i:Z

    .line 480
    .line 481
    if-eqz p1, :cond_c

    .line 482
    .line 483
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 484
    .line 485
    check-cast p0, Lay0/a;

    .line 486
    .line 487
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    :cond_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 491
    .line 492
    return-object p0

    .line 493
    :pswitch_c
    check-cast p1, Ljava/lang/Number;

    .line 494
    .line 495
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 496
    .line 497
    .line 498
    move-result p1

    .line 499
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast v0, Li40/r2;

    .line 502
    .line 503
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 504
    .line 505
    check-cast p0, Ljava/util/List;

    .line 506
    .line 507
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object p0

    .line 511
    invoke-virtual {v0, p0}, Li40/r2;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object p0

    .line 515
    return-object p0

    .line 516
    :pswitch_d
    check-cast p1, Ljava/lang/Number;

    .line 517
    .line 518
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 519
    .line 520
    .line 521
    move-result p1

    .line 522
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 523
    .line 524
    check-cast v0, Li40/r2;

    .line 525
    .line 526
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 527
    .line 528
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 529
    .line 530
    .line 531
    move-result-object p0

    .line 532
    invoke-virtual {v0, p0}, Li40/r2;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object p0

    .line 536
    return-object p0

    .line 537
    :pswitch_e
    check-cast p1, Ljava/lang/Number;

    .line 538
    .line 539
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 540
    .line 541
    .line 542
    move-result p1

    .line 543
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast v0, Li40/j2;

    .line 546
    .line 547
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 548
    .line 549
    .line 550
    move-result-object v1

    .line 551
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 552
    .line 553
    check-cast p0, Ljava/util/List;

    .line 554
    .line 555
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object p0

    .line 559
    invoke-virtual {v0, v1, p0}, Li40/j2;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    move-result-object p0

    .line 563
    return-object p0

    .line 564
    :pswitch_f
    check-cast p1, Ljava/lang/Number;

    .line 565
    .line 566
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 567
    .line 568
    .line 569
    move-result p1

    .line 570
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 571
    .line 572
    check-cast v0, Li40/q0;

    .line 573
    .line 574
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 575
    .line 576
    .line 577
    move-result-object v1

    .line 578
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast p0, Ljava/util/ArrayList;

    .line 581
    .line 582
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object p0

    .line 586
    invoke-virtual {v0, v1, p0}, Li40/q0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object p0

    .line 590
    return-object p0

    .line 591
    :pswitch_10
    check-cast p1, Lh40/m3;

    .line 592
    .line 593
    const-string v0, "it"

    .line 594
    .line 595
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 596
    .line 597
    .line 598
    iget-object p1, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 599
    .line 600
    check-cast p1, Lay0/k;

    .line 601
    .line 602
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast p0, Lh40/m3;

    .line 605
    .line 606
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 610
    .line 611
    return-object p0

    .line 612
    :pswitch_11
    check-cast p1, Ljava/lang/Number;

    .line 613
    .line 614
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 615
    .line 616
    .line 617
    move-result p1

    .line 618
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 619
    .line 620
    check-cast v0, Lhz0/t1;

    .line 621
    .line 622
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 623
    .line 624
    check-cast p0, Ljava/util/List;

    .line 625
    .line 626
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object p0

    .line 630
    invoke-virtual {v0, p0}, Lhz0/t1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 631
    .line 632
    .line 633
    move-result-object p0

    .line 634
    return-object p0

    .line 635
    :pswitch_12
    check-cast p1, Ljava/lang/Number;

    .line 636
    .line 637
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 638
    .line 639
    .line 640
    move-result p1

    .line 641
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 642
    .line 643
    check-cast v0, Lh60/b;

    .line 644
    .line 645
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 646
    .line 647
    .line 648
    move-result-object v1

    .line 649
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 650
    .line 651
    check-cast p0, Ljava/util/List;

    .line 652
    .line 653
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object p0

    .line 657
    invoke-virtual {v0, v1, p0}, Lh60/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 658
    .line 659
    .line 660
    move-result-object p0

    .line 661
    return-object p0

    .line 662
    :pswitch_13
    check-cast p1, Ljava/lang/Number;

    .line 663
    .line 664
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 665
    .line 666
    .line 667
    move-result p1

    .line 668
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 669
    .line 670
    check-cast v0, Lh60/b;

    .line 671
    .line 672
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 673
    .line 674
    .line 675
    move-result-object v1

    .line 676
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 677
    .line 678
    check-cast p0, Ljava/util/List;

    .line 679
    .line 680
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 681
    .line 682
    .line 683
    move-result-object p0

    .line 684
    invoke-virtual {v0, v1, p0}, Lh60/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 685
    .line 686
    .line 687
    move-result-object p0

    .line 688
    return-object p0

    .line 689
    :pswitch_14
    check-cast p1, Ljava/lang/Number;

    .line 690
    .line 691
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 692
    .line 693
    .line 694
    move-result p1

    .line 695
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 696
    .line 697
    check-cast v0, Lh60/b;

    .line 698
    .line 699
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 700
    .line 701
    .line 702
    move-result-object v1

    .line 703
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 704
    .line 705
    check-cast p0, Ljava/util/List;

    .line 706
    .line 707
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object p0

    .line 711
    invoke-virtual {v0, v1, p0}, Lh60/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object p0

    .line 715
    return-object p0

    .line 716
    :pswitch_15
    check-cast p1, Ln3/b;

    .line 717
    .line 718
    iget-object p1, p1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 719
    .line 720
    iget-object p1, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast p1, Ll2/b1;

    .line 723
    .line 724
    iget-object p0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 725
    .line 726
    check-cast p0, Lh2/yb;

    .line 727
    .line 728
    invoke-virtual {p0}, Lh2/yb;->b()Z

    .line 729
    .line 730
    .line 731
    move-result p0

    .line 732
    if-nez p0, :cond_d

    .line 733
    .line 734
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 735
    .line 736
    invoke-interface {p1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 737
    .line 738
    .line 739
    :cond_d
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 740
    .line 741
    return-object p0

    .line 742
    :pswitch_16
    check-cast p1, Ljava/lang/Throwable;

    .line 743
    .line 744
    instance-of v0, p1, Lfb/x;

    .line 745
    .line 746
    if-eqz v0, :cond_e

    .line 747
    .line 748
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 749
    .line 750
    check-cast v0, Leb/v;

    .line 751
    .line 752
    check-cast p1, Lfb/x;

    .line 753
    .line 754
    iget p1, p1, Lfb/x;->d:I

    .line 755
    .line 756
    iget-object v0, v0, Leb/v;->f:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 757
    .line 758
    const/16 v1, -0x100

    .line 759
    .line 760
    invoke-virtual {v0, v1, p1}, Ljava/util/concurrent/atomic/AtomicInteger;->compareAndSet(II)Z

    .line 761
    .line 762
    .line 763
    :cond_e
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 764
    .line 765
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 766
    .line 767
    const/4 p1, 0x0

    .line 768
    invoke-interface {p0, p1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 769
    .line 770
    .line 771
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 772
    .line 773
    return-object p0

    .line 774
    :pswitch_17
    check-cast p1, Ljava/lang/Number;

    .line 775
    .line 776
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 777
    .line 778
    .line 779
    move-result p1

    .line 780
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 781
    .line 782
    check-cast v0, Lck/a;

    .line 783
    .line 784
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 785
    .line 786
    .line 787
    move-result-object v1

    .line 788
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 789
    .line 790
    check-cast p0, Ljava/util/List;

    .line 791
    .line 792
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 793
    .line 794
    .line 795
    move-result-object p0

    .line 796
    invoke-virtual {v0, v1, p0}, Lck/a;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 797
    .line 798
    .line 799
    move-result-object p0

    .line 800
    return-object p0

    .line 801
    :pswitch_18
    check-cast p1, Ljava/lang/Number;

    .line 802
    .line 803
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 804
    .line 805
    .line 806
    move-result p1

    .line 807
    iget-object v0, p0, Lc41/g;->f:Ljava/lang/Object;

    .line 808
    .line 809
    check-cast v0, Lc1/c2;

    .line 810
    .line 811
    iget-object p0, p0, Lc41/g;->e:Ljava/lang/Object;

    .line 812
    .line 813
    check-cast p0, Ljava/util/List;

    .line 814
    .line 815
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 816
    .line 817
    .line 818
    move-result-object p0

    .line 819
    invoke-virtual {v0, p0}, Lc1/c2;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 820
    .line 821
    .line 822
    move-result-object p0

    .line 823
    return-object p0

    .line 824
    nop

    .line 825
    :pswitch_data_0
    .packed-switch 0x0
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
