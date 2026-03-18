.class public final Lh0/v1;
.super Lh0/u1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static d(Lh0/o2;Landroid/util/Size;)Lh0/v1;
    .locals 8

    .line 1
    sget-object v0, Lh0/o2;->R0:Lh0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-interface {p0, v0, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lu/f0;

    .line 9
    .line 10
    if-eqz v0, :cond_d

    .line 11
    .line 12
    new-instance v0, Lh0/v1;

    .line 13
    .line 14
    invoke-direct {v0}, Lh0/u1;-><init>()V

    .line 15
    .line 16
    .line 17
    sget-object v2, Lh0/o2;->P0:Lh0/g;

    .line 18
    .line 19
    invoke-interface {p0, v2, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lh0/z1;

    .line 24
    .line 25
    sget-object v3, Lh0/n1;->f:Lh0/n1;

    .line 26
    .line 27
    invoke-static {}, Lh0/z1;->a()Lh0/z1;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    iget-object v4, v4, Lh0/z1;->g:Lh0/o0;

    .line 32
    .line 33
    iget v4, v4, Lh0/o0;->c:I

    .line 34
    .line 35
    if-eqz v2, :cond_4

    .line 36
    .line 37
    iget-object v3, v2, Lh0/z1;->g:Lh0/o0;

    .line 38
    .line 39
    iget v4, v3, Lh0/o0;->c:I

    .line 40
    .line 41
    iget-object v3, v2, Lh0/z1;->c:Ljava/util/List;

    .line 42
    .line 43
    check-cast v3, Ljava/util/List;

    .line 44
    .line 45
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    if-eqz v5, :cond_1

    .line 54
    .line 55
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    check-cast v5, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 60
    .line 61
    iget-object v6, v0, Lh0/u1;->c:Ljava/util/ArrayList;

    .line 62
    .line 63
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    if-eqz v7, :cond_0

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    iget-object v3, v2, Lh0/z1;->d:Ljava/util/List;

    .line 75
    .line 76
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_3

    .line 85
    .line 86
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    check-cast v5, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 91
    .line 92
    iget-object v6, v0, Lh0/u1;->d:Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    if-eqz v7, :cond_2

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_2
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_3
    iget-object v3, v2, Lh0/z1;->g:Lh0/o0;

    .line 106
    .line 107
    iget-object v3, v3, Lh0/o0;->d:Ljava/util/List;

    .line 108
    .line 109
    iget-object v5, v0, Lh0/u1;->b:Lb0/n1;

    .line 110
    .line 111
    invoke-virtual {v5, v3}, Lb0/n1;->a(Ljava/util/Collection;)V

    .line 112
    .line 113
    .line 114
    iget-object v2, v2, Lh0/z1;->g:Lh0/o0;

    .line 115
    .line 116
    iget-object v3, v2, Lh0/o0;->b:Lh0/n1;

    .line 117
    .line 118
    :cond_4
    iget-object v2, v0, Lh0/u1;->b:Lb0/n1;

    .line 119
    .line 120
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    invoke-static {v3}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    iput-object v3, v2, Lb0/n1;->g:Ljava/lang/Object;

    .line 128
    .line 129
    instance-of v2, p0, Lh0/o1;

    .line 130
    .line 131
    const/4 v3, 0x0

    .line 132
    if-eqz v2, :cond_7

    .line 133
    .line 134
    sget-object v2, Ly/b;->a:Landroid/util/Rational;

    .line 135
    .line 136
    const-class v2, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;

    .line 137
    .line 138
    sget-object v5, Lx/a;->a:Ld01/x;

    .line 139
    .line 140
    invoke-virtual {v5, v2}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    check-cast v2, Landroidx/camera/camera2/internal/compat/quirk/PreviewPixelHDRnetQuirk;

    .line 145
    .line 146
    if-nez v2, :cond_5

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_5
    sget-object v2, Ly/b;->a:Landroid/util/Rational;

    .line 150
    .line 151
    new-instance v5, Landroid/util/Rational;

    .line 152
    .line 153
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 158
    .line 159
    .line 160
    move-result p1

    .line 161
    invoke-direct {v5, v6, p1}, Landroid/util/Rational;-><init>(II)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v2, v5}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result p1

    .line 168
    if-eqz p1, :cond_6

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_6
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    sget-object v2, Landroid/hardware/camera2/CaptureRequest;->TONEMAP_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 176
    .line 177
    const/4 v5, 0x2

    .line 178
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 179
    .line 180
    .line 181
    move-result-object v5

    .line 182
    invoke-static {v2}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    invoke-virtual {p1, v2, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    new-instance v2, Lt/a;

    .line 190
    .line 191
    invoke-static {p1}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    invoke-direct {v2, p1, v3}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 196
    .line 197
    .line 198
    iget-object p1, v0, Lh0/u1;->b:Lb0/n1;

    .line 199
    .line 200
    invoke-virtual {p1, v2}, Lb0/n1;->i(Lh0/q0;)V

    .line 201
    .line 202
    .line 203
    :cond_7
    :goto_2
    new-instance p1, Lt/a;

    .line 204
    .line 205
    sget-object p1, Lt/a;->f:Lh0/g;

    .line 206
    .line 207
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v2

    .line 211
    invoke-interface {p0, p1, v2}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    check-cast p1, Ljava/lang/Integer;

    .line 216
    .line 217
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 218
    .line 219
    .line 220
    move-result p1

    .line 221
    iget-object v2, v0, Lh0/u1;->b:Lb0/n1;

    .line 222
    .line 223
    iput p1, v2, Lb0/n1;->d:I

    .line 224
    .line 225
    new-instance p1, Lu/k0;

    .line 226
    .line 227
    invoke-direct {p1}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    .line 228
    .line 229
    .line 230
    sget-object v2, Lt/a;->h:Lh0/g;

    .line 231
    .line 232
    invoke-interface {p0, v2, p1}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    check-cast p1, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 237
    .line 238
    iget-object v2, v0, Lh0/u1;->c:Ljava/util/ArrayList;

    .line 239
    .line 240
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    move-result v4

    .line 244
    if-eqz v4, :cond_8

    .line 245
    .line 246
    goto :goto_3

    .line 247
    :cond_8
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    :goto_3
    new-instance p1, Lu/i0;

    .line 251
    .line 252
    invoke-direct {p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;-><init>()V

    .line 253
    .line 254
    .line 255
    sget-object v2, Lt/a;->i:Lh0/g;

    .line 256
    .line 257
    invoke-interface {p0, v2, p1}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object p1

    .line 261
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 262
    .line 263
    iget-object v2, v0, Lh0/u1;->d:Ljava/util/ArrayList;

    .line 264
    .line 265
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    move-result v4

    .line 269
    if-eqz v4, :cond_9

    .line 270
    .line 271
    goto :goto_4

    .line 272
    :cond_9
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    :goto_4
    new-instance p1, Lu/b0;

    .line 276
    .line 277
    invoke-direct {p1}, Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;-><init>()V

    .line 278
    .line 279
    .line 280
    sget-object v2, Lt/a;->j:Lh0/g;

    .line 281
    .line 282
    invoke-interface {p0, v2, p1}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object p1

    .line 286
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 287
    .line 288
    new-instance v2, Lu/l0;

    .line 289
    .line 290
    invoke-direct {v2, p1}, Lu/l0;-><init>(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)V

    .line 291
    .line 292
    .line 293
    iget-object p1, v0, Lh0/u1;->b:Lb0/n1;

    .line 294
    .line 295
    invoke-virtual {p1, v2}, Lb0/n1;->c(Lh0/m;)V

    .line 296
    .line 297
    .line 298
    iget-object p1, v0, Lh0/u1;->e:Ljava/util/ArrayList;

    .line 299
    .line 300
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v4

    .line 304
    if-nez v4, :cond_a

    .line 305
    .line 306
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    :cond_a
    sget-object p1, Lh0/o2;->b1:Lh0/g;

    .line 310
    .line 311
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 312
    .line 313
    .line 314
    move-result-object v2

    .line 315
    invoke-interface {p0, p1, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v2

    .line 319
    check-cast v2, Ljava/lang/Integer;

    .line 320
    .line 321
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 322
    .line 323
    .line 324
    move-result v3

    .line 325
    if-eqz v3, :cond_b

    .line 326
    .line 327
    iget-object v4, v0, Lh0/u1;->b:Lb0/n1;

    .line 328
    .line 329
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    if-eqz v3, :cond_b

    .line 333
    .line 334
    iget-object v3, v4, Lb0/n1;->g:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v3, Lh0/j1;

    .line 337
    .line 338
    invoke-virtual {v3, p1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 339
    .line 340
    .line 341
    :cond_b
    invoke-interface {p0}, Lh0/o2;->v()I

    .line 342
    .line 343
    .line 344
    move-result p1

    .line 345
    if-eqz p1, :cond_c

    .line 346
    .line 347
    iget-object v2, v0, Lh0/u1;->b:Lb0/n1;

    .line 348
    .line 349
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 350
    .line 351
    .line 352
    if-eqz p1, :cond_c

    .line 353
    .line 354
    sget-object v3, Lh0/o2;->a1:Lh0/g;

    .line 355
    .line 356
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 357
    .line 358
    .line 359
    move-result-object p1

    .line 360
    iget-object v2, v2, Lb0/n1;->g:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v2, Lh0/j1;

    .line 363
    .line 364
    invoke-virtual {v2, v3, p1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 365
    .line 366
    .line 367
    :cond_c
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 368
    .line 369
    .line 370
    move-result-object p1

    .line 371
    sget-object v2, Lt/a;->k:Lh0/g;

    .line 372
    .line 373
    invoke-interface {p0, v2, v1}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v1

    .line 377
    check-cast v1, Ljava/lang/String;

    .line 378
    .line 379
    invoke-virtual {p1, v2, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    sget-object v1, Lt/a;->g:Lh0/g;

    .line 383
    .line 384
    const-wide/16 v2, -0x1

    .line 385
    .line 386
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 387
    .line 388
    .line 389
    move-result-object v2

    .line 390
    invoke-interface {p0, v1, v2}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v2

    .line 394
    check-cast v2, Ljava/lang/Long;

    .line 395
    .line 396
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 397
    .line 398
    .line 399
    invoke-virtual {p1, v1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    iget-object v1, v0, Lh0/u1;->b:Lb0/n1;

    .line 403
    .line 404
    invoke-virtual {v1, p1}, Lb0/n1;->i(Lh0/q0;)V

    .line 405
    .line 406
    .line 407
    invoke-static {p0}, La0/i;->d(Lh0/q0;)La0/i;

    .line 408
    .line 409
    .line 410
    move-result-object p0

    .line 411
    invoke-virtual {p0}, La0/i;->c()La0/j;

    .line 412
    .line 413
    .line 414
    move-result-object p0

    .line 415
    iget-object p1, v0, Lh0/u1;->b:Lb0/n1;

    .line 416
    .line 417
    invoke-virtual {p1, p0}, Lb0/n1;->i(Lh0/q0;)V

    .line 418
    .line 419
    .line 420
    return-object v0

    .line 421
    :cond_d
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 422
    .line 423
    new-instance v0, Ljava/lang/StringBuilder;

    .line 424
    .line 425
    const-string v1, "Implementation is missing option unpacker for "

    .line 426
    .line 427
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 428
    .line 429
    .line 430
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    sget-object v2, Ll0/k;->g1:Lh0/g;

    .line 435
    .line 436
    invoke-interface {p0, v2, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object p0

    .line 440
    check-cast p0, Ljava/lang/String;

    .line 441
    .line 442
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 443
    .line 444
    .line 445
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 446
    .line 447
    .line 448
    move-result-object p0

    .line 449
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    throw p1
.end method


# virtual methods
.method public final a(Lh0/q0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/u1;->b:Lb0/n1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb0/n1;->i(Lh0/q0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Lh0/t0;Lb0/y;I)V
    .locals 1

    .line 1
    invoke-static {p1}, Lh0/i;->a(Lh0/t0;)Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    iput-object p2, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    iput-object p2, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->h()Lh0/i;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    iget-object p3, p0, Lh0/u1;->a:Ljava/util/LinkedHashSet;

    .line 20
    .line 21
    invoke-interface {p3, p2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lh0/u1;->b:Lb0/n1;

    .line 25
    .line 26
    iget-object p0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljava/util/HashSet;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 35
    .line 36
    const-string p1, "Null dynamicRange"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
.end method

.method public final c()Lh0/z1;
    .locals 10

    .line 1
    new-instance v0, Lh0/z1;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    iget-object v2, p0, Lh0/u1;->a:Ljava/util/LinkedHashSet;

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    iget-object v3, p0, Lh0/u1;->c:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 15
    .line 16
    .line 17
    new-instance v3, Ljava/util/ArrayList;

    .line 18
    .line 19
    iget-object v4, p0, Lh0/u1;->d:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 22
    .line 23
    .line 24
    new-instance v4, Ljava/util/ArrayList;

    .line 25
    .line 26
    iget-object v5, p0, Lh0/u1;->e:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    iget-object v5, p0, Lh0/u1;->b:Lb0/n1;

    .line 32
    .line 33
    invoke-virtual {v5}, Lb0/n1;->j()Lh0/o0;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    iget-object v6, p0, Lh0/u1;->f:Lh0/w1;

    .line 38
    .line 39
    iget-object v7, p0, Lh0/u1;->g:Landroid/hardware/camera2/params/InputConfiguration;

    .line 40
    .line 41
    iget v8, p0, Lh0/u1;->h:I

    .line 42
    .line 43
    iget-object v9, p0, Lh0/u1;->i:Lh0/i;

    .line 44
    .line 45
    invoke-direct/range {v0 .. v9}, Lh0/z1;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/o0;Lh0/x1;Landroid/hardware/camera2/params/InputConfiguration;ILh0/i;)V

    .line 46
    .line 47
    .line 48
    return-object v0
.end method
