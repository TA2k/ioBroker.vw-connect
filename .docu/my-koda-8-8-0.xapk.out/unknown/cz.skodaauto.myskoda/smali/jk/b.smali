.class public final synthetic Ljk/b;
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
    iput p2, p0, Ljk/b;->d:I

    iput-object p3, p0, Ljk/b;->g:Ljava/lang/Object;

    iput-object p4, p0, Ljk/b;->e:Ljava/lang/Object;

    iput p1, p0, Ljk/b;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ILjava/lang/Object;II)V
    .locals 0

    .line 2
    iput p5, p0, Ljk/b;->d:I

    iput-object p1, p0, Ljk/b;->g:Ljava/lang/Object;

    iput p2, p0, Ljk/b;->f:I

    iput-object p3, p0, Ljk/b;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ljk/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 9
    .line 10
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lki/j;

    .line 13
    .line 14
    check-cast p1, Ll2/o;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget p0, p0, Ljk/b;->f:I

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->q(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Lki/j;ILl2/o;I)Llx0/b0;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Lt2/b;

    .line 32
    .line 33
    check-cast p1, Ll2/o;

    .line 34
    .line 35
    check-cast p2, Ljava/lang/Integer;

    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 38
    .line 39
    .line 40
    iget p2, p0, Ljk/b;->f:I

    .line 41
    .line 42
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    or-int/lit8 p2, p2, 0x1

    .line 47
    .line 48
    iget-object p0, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-virtual {v0, p0, p1, p2}, Lt2/b;->d(Ljava/lang/Object;Ll2/o;I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Ljava/lang/String;

    .line 59
    .line 60
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Ljava/lang/String;

    .line 63
    .line 64
    check-cast p1, Ll2/o;

    .line 65
    .line 66
    check-cast p2, Ljava/lang/Integer;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    const/4 p2, 0x1

    .line 72
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    iget p0, p0, Ljk/b;->f:I

    .line 77
    .line 78
    invoke-static {v0, p0, v1, p1, p2}, Lt10/a;->w(Ljava/lang/String;ILjava/lang/String;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_2
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v0, Le2/w0;

    .line 87
    .line 88
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v1, Lt2/b;

    .line 91
    .line 92
    check-cast p1, Ll2/o;

    .line 93
    .line 94
    check-cast p2, Ljava/lang/Integer;

    .line 95
    .line 96
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    iget p0, p0, Ljk/b;->f:I

    .line 100
    .line 101
    or-int/lit8 p0, p0, 0x1

    .line 102
    .line 103
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    invoke-static {v0, v1, p1, p0}, Lt1/l0;->f(Le2/w0;Lt2/b;Ll2/o;I)V

    .line 108
    .line 109
    .line 110
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_3
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lg4/g;

    .line 116
    .line 117
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v1, Ljava/util/List;

    .line 120
    .line 121
    check-cast p1, Ll2/o;

    .line 122
    .line 123
    check-cast p2, Ljava/lang/Integer;

    .line 124
    .line 125
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 126
    .line 127
    .line 128
    iget p0, p0, Ljk/b;->f:I

    .line 129
    .line 130
    or-int/lit8 p0, p0, 0x1

    .line 131
    .line 132
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    invoke-static {v0, v1, p1, p0}, Lt1/d;->a(Lg4/g;Ljava/util/List;Ll2/o;I)V

    .line 137
    .line 138
    .line 139
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_4
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Lqg/k;

    .line 145
    .line 146
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v1, Lay0/k;

    .line 149
    .line 150
    check-cast p1, Ll2/o;

    .line 151
    .line 152
    check-cast p2, Ljava/lang/Integer;

    .line 153
    .line 154
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    iget p0, p0, Ljk/b;->f:I

    .line 158
    .line 159
    or-int/lit8 p0, p0, 0x1

    .line 160
    .line 161
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-static {v0, v1, p1, p0}, Lrk/a;->b(Lqg/k;Lay0/k;Ll2/o;I)V

    .line 166
    .line 167
    .line 168
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object p0

    .line 171
    :pswitch_5
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v0, Ljava/lang/String;

    .line 174
    .line 175
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v1, Lay0/k;

    .line 178
    .line 179
    check-cast p1, Ll2/o;

    .line 180
    .line 181
    check-cast p2, Ljava/lang/Integer;

    .line 182
    .line 183
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    iget p0, p0, Ljk/b;->f:I

    .line 187
    .line 188
    or-int/lit8 p0, p0, 0x1

    .line 189
    .line 190
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 191
    .line 192
    .line 193
    move-result p0

    .line 194
    invoke-static {v0, v1, p1, p0}, Lr30/a;->d(Ljava/lang/String;Lay0/k;Ll2/o;I)V

    .line 195
    .line 196
    .line 197
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object p0

    .line 200
    :pswitch_6
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v0, Lq00/a;

    .line 203
    .line 204
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v1, Lay0/a;

    .line 207
    .line 208
    check-cast p1, Ll2/o;

    .line 209
    .line 210
    check-cast p2, Ljava/lang/Integer;

    .line 211
    .line 212
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 213
    .line 214
    .line 215
    iget p0, p0, Ljk/b;->f:I

    .line 216
    .line 217
    or-int/lit8 p0, p0, 0x1

    .line 218
    .line 219
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    invoke-static {v0, v1, p1, p0}, Ljp/yg;->d(Lq00/a;Lay0/a;Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object p0

    .line 229
    :pswitch_7
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v0, Lq00/a;

    .line 232
    .line 233
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast v1, Lay0/k;

    .line 236
    .line 237
    check-cast p1, Ll2/o;

    .line 238
    .line 239
    check-cast p2, Ljava/lang/Integer;

    .line 240
    .line 241
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 242
    .line 243
    .line 244
    iget p0, p0, Ljk/b;->f:I

    .line 245
    .line 246
    or-int/lit8 p0, p0, 0x1

    .line 247
    .line 248
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 249
    .line 250
    .line 251
    move-result p0

    .line 252
    invoke-static {v0, v1, p1, p0}, Ljp/yg;->e(Lq00/a;Lay0/k;Ll2/o;I)V

    .line 253
    .line 254
    .line 255
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 256
    .line 257
    return-object p0

    .line 258
    :pswitch_8
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast v0, Lpg/l;

    .line 261
    .line 262
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v1, Lay0/k;

    .line 265
    .line 266
    check-cast p1, Ll2/o;

    .line 267
    .line 268
    check-cast p2, Ljava/lang/Integer;

    .line 269
    .line 270
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 271
    .line 272
    .line 273
    iget p0, p0, Ljk/b;->f:I

    .line 274
    .line 275
    or-int/lit8 p0, p0, 0x1

    .line 276
    .line 277
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 278
    .line 279
    .line 280
    move-result p0

    .line 281
    invoke-static {v0, v1, p1, p0}, Lqk/b;->b(Lpg/l;Lay0/k;Ll2/o;I)V

    .line 282
    .line 283
    .line 284
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    return-object p0

    .line 287
    :pswitch_9
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 290
    .line 291
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 292
    .line 293
    check-cast v1, Lay0/a;

    .line 294
    .line 295
    check-cast p1, Ll2/o;

    .line 296
    .line 297
    check-cast p2, Ljava/lang/Integer;

    .line 298
    .line 299
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 300
    .line 301
    .line 302
    move-result p2

    .line 303
    iget p0, p0, Ljk/b;->f:I

    .line 304
    .line 305
    invoke-static {v0, v1, p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->c(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Lay0/a;ILl2/o;I)Llx0/b0;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    return-object p0

    .line 310
    :pswitch_a
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast v0, Lp1/m;

    .line 313
    .line 314
    check-cast p1, Ll2/o;

    .line 315
    .line 316
    check-cast p2, Ljava/lang/Integer;

    .line 317
    .line 318
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 319
    .line 320
    .line 321
    const/4 p2, 0x1

    .line 322
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 323
    .line 324
    .line 325
    move-result p2

    .line 326
    iget v1, p0, Ljk/b;->f:I

    .line 327
    .line 328
    iget-object p0, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 329
    .line 330
    invoke-virtual {v0, v1, p0, p1, p2}, Lp1/m;->e(ILjava/lang/Object;Ll2/o;I)V

    .line 331
    .line 332
    .line 333
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 334
    .line 335
    return-object p0

    .line 336
    :pswitch_b
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 337
    .line 338
    check-cast v0, Lnt0/e;

    .line 339
    .line 340
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v1, Lay0/a;

    .line 343
    .line 344
    check-cast p1, Ll2/o;

    .line 345
    .line 346
    check-cast p2, Ljava/lang/Integer;

    .line 347
    .line 348
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 349
    .line 350
    .line 351
    iget p0, p0, Ljk/b;->f:I

    .line 352
    .line 353
    or-int/lit8 p0, p0, 0x1

    .line 354
    .line 355
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 356
    .line 357
    .line 358
    move-result p0

    .line 359
    invoke-static {v0, v1, p1, p0}, Lot0/a;->h(Lnt0/e;Lay0/a;Ll2/o;I)V

    .line 360
    .line 361
    .line 362
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 363
    .line 364
    return-object p0

    .line 365
    :pswitch_c
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 366
    .line 367
    check-cast v0, Lng/e;

    .line 368
    .line 369
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v1, Lay0/k;

    .line 372
    .line 373
    check-cast p1, Ll2/o;

    .line 374
    .line 375
    check-cast p2, Ljava/lang/Integer;

    .line 376
    .line 377
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 378
    .line 379
    .line 380
    iget p0, p0, Ljk/b;->f:I

    .line 381
    .line 382
    or-int/lit8 p0, p0, 0x1

    .line 383
    .line 384
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 385
    .line 386
    .line 387
    move-result p0

    .line 388
    invoke-static {v0, v1, p1, p0}, Ljp/wb;->c(Lng/e;Lay0/k;Ll2/o;I)V

    .line 389
    .line 390
    .line 391
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    return-object p0

    .line 394
    :pswitch_d
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v0, Ln90/f;

    .line 397
    .line 398
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast v1, Lay0/a;

    .line 401
    .line 402
    check-cast p1, Ll2/o;

    .line 403
    .line 404
    check-cast p2, Ljava/lang/Integer;

    .line 405
    .line 406
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 407
    .line 408
    .line 409
    iget p0, p0, Ljk/b;->f:I

    .line 410
    .line 411
    or-int/lit8 p0, p0, 0x1

    .line 412
    .line 413
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 414
    .line 415
    .line 416
    move-result p0

    .line 417
    invoke-static {v0, v1, p1, p0}, Lo90/b;->a(Ln90/f;Lay0/a;Ll2/o;I)V

    .line 418
    .line 419
    .line 420
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 421
    .line 422
    return-object p0

    .line 423
    :pswitch_e
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 424
    .line 425
    check-cast v0, Lx2/s;

    .line 426
    .line 427
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast v1, Ln00/d;

    .line 430
    .line 431
    check-cast p1, Ll2/o;

    .line 432
    .line 433
    check-cast p2, Ljava/lang/Integer;

    .line 434
    .line 435
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 436
    .line 437
    .line 438
    iget p0, p0, Ljk/b;->f:I

    .line 439
    .line 440
    or-int/lit8 p0, p0, 0x1

    .line 441
    .line 442
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 443
    .line 444
    .line 445
    move-result p0

    .line 446
    invoke-static {v0, v1, p1, p0}, Lo00/a;->e(Lx2/s;Ln00/d;Ll2/o;I)V

    .line 447
    .line 448
    .line 449
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 450
    .line 451
    return-object p0

    .line 452
    :pswitch_f
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 453
    .line 454
    check-cast v0, Lql0/g;

    .line 455
    .line 456
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 457
    .line 458
    check-cast v1, Lay0/a;

    .line 459
    .line 460
    check-cast p1, Ll2/o;

    .line 461
    .line 462
    check-cast p2, Ljava/lang/Integer;

    .line 463
    .line 464
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 465
    .line 466
    .line 467
    iget p0, p0, Ljk/b;->f:I

    .line 468
    .line 469
    or-int/lit8 p0, p0, 0x1

    .line 470
    .line 471
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 472
    .line 473
    .line 474
    move-result p0

    .line 475
    invoke-static {v0, v1, p1, p0}, Lny/j;->b(Lql0/g;Lay0/a;Ll2/o;I)V

    .line 476
    .line 477
    .line 478
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 479
    .line 480
    return-object p0

    .line 481
    :pswitch_10
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast v0, Lz9/y;

    .line 484
    .line 485
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 486
    .line 487
    check-cast v1, Lay0/k;

    .line 488
    .line 489
    check-cast p1, Ll2/o;

    .line 490
    .line 491
    check-cast p2, Ljava/lang/Integer;

    .line 492
    .line 493
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 494
    .line 495
    .line 496
    iget p0, p0, Ljk/b;->f:I

    .line 497
    .line 498
    or-int/lit8 p0, p0, 0x1

    .line 499
    .line 500
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 501
    .line 502
    .line 503
    move-result p0

    .line 504
    invoke-static {v0, v1, p1, p0}, Lny/j;->i(Lz9/y;Lay0/k;Ll2/o;I)V

    .line 505
    .line 506
    .line 507
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 508
    .line 509
    return-object p0

    .line 510
    :pswitch_11
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 511
    .line 512
    check-cast v0, Lm80/j;

    .line 513
    .line 514
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast v1, Lay0/a;

    .line 517
    .line 518
    check-cast p1, Ll2/o;

    .line 519
    .line 520
    check-cast p2, Ljava/lang/Integer;

    .line 521
    .line 522
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 523
    .line 524
    .line 525
    iget p0, p0, Ljk/b;->f:I

    .line 526
    .line 527
    or-int/lit8 p0, p0, 0x1

    .line 528
    .line 529
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 530
    .line 531
    .line 532
    move-result p0

    .line 533
    invoke-static {v0, v1, p1, p0}, Ln80/a;->e(Lm80/j;Lay0/a;Ll2/o;I)V

    .line 534
    .line 535
    .line 536
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 537
    .line 538
    return-object p0

    .line 539
    :pswitch_12
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 540
    .line 541
    check-cast v0, Ln1/h;

    .line 542
    .line 543
    check-cast p1, Ll2/o;

    .line 544
    .line 545
    check-cast p2, Ljava/lang/Integer;

    .line 546
    .line 547
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 548
    .line 549
    .line 550
    const/4 p2, 0x1

    .line 551
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 552
    .line 553
    .line 554
    move-result p2

    .line 555
    iget v1, p0, Ljk/b;->f:I

    .line 556
    .line 557
    iget-object p0, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 558
    .line 559
    invoke-virtual {v0, v1, p0, p1, p2}, Ln1/h;->e(ILjava/lang/Object;Ll2/o;I)V

    .line 560
    .line 561
    .line 562
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 563
    .line 564
    return-object p0

    .line 565
    :pswitch_13
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 566
    .line 567
    check-cast v0, Lmc/t;

    .line 568
    .line 569
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 570
    .line 571
    check-cast v1, Lay0/k;

    .line 572
    .line 573
    check-cast p1, Ll2/o;

    .line 574
    .line 575
    check-cast p2, Ljava/lang/Integer;

    .line 576
    .line 577
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 578
    .line 579
    .line 580
    iget p0, p0, Ljk/b;->f:I

    .line 581
    .line 582
    or-int/lit8 p0, p0, 0x1

    .line 583
    .line 584
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 585
    .line 586
    .line 587
    move-result p0

    .line 588
    invoke-static {v0, v1, p1, p0}, Lmc/d;->d(Lmc/t;Lay0/k;Ll2/o;I)V

    .line 589
    .line 590
    .line 591
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 592
    .line 593
    return-object p0

    .line 594
    :pswitch_14
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 595
    .line 596
    check-cast v0, Lm1/h;

    .line 597
    .line 598
    check-cast p1, Ll2/o;

    .line 599
    .line 600
    check-cast p2, Ljava/lang/Integer;

    .line 601
    .line 602
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 603
    .line 604
    .line 605
    const/4 p2, 0x1

    .line 606
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 607
    .line 608
    .line 609
    move-result p2

    .line 610
    iget v1, p0, Ljk/b;->f:I

    .line 611
    .line 612
    iget-object p0, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 613
    .line 614
    invoke-virtual {v0, v1, p0, p1, p2}, Lm1/h;->e(ILjava/lang/Object;Ll2/o;I)V

    .line 615
    .line 616
    .line 617
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 618
    .line 619
    return-object p0

    .line 620
    :pswitch_15
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast v0, Lx2/s;

    .line 623
    .line 624
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 625
    .line 626
    check-cast v1, Lx61/a;

    .line 627
    .line 628
    check-cast p1, Ll2/o;

    .line 629
    .line 630
    check-cast p2, Ljava/lang/Integer;

    .line 631
    .line 632
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 633
    .line 634
    .line 635
    iget p0, p0, Ljk/b;->f:I

    .line 636
    .line 637
    or-int/lit8 p0, p0, 0x1

    .line 638
    .line 639
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 640
    .line 641
    .line 642
    move-result p0

    .line 643
    invoke-static {v0, v1, p1, p0}, Llp/af;->c(Lx2/s;Lx61/a;Ll2/o;I)V

    .line 644
    .line 645
    .line 646
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 647
    .line 648
    return-object p0

    .line 649
    :pswitch_16
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 650
    .line 651
    check-cast v0, Lk20/d;

    .line 652
    .line 653
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 654
    .line 655
    check-cast v1, Lay0/a;

    .line 656
    .line 657
    check-cast p1, Ll2/o;

    .line 658
    .line 659
    check-cast p2, Ljava/lang/Integer;

    .line 660
    .line 661
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 662
    .line 663
    .line 664
    iget p0, p0, Ljk/b;->f:I

    .line 665
    .line 666
    or-int/lit8 p0, p0, 0x1

    .line 667
    .line 668
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 669
    .line 670
    .line 671
    move-result p0

    .line 672
    invoke-static {v0, v1, p1, p0}, Ll20/a;->r(Lk20/d;Lay0/a;Ll2/o;I)V

    .line 673
    .line 674
    .line 675
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 676
    .line 677
    return-object p0

    .line 678
    :pswitch_17
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 679
    .line 680
    check-cast v0, [Ll2/t1;

    .line 681
    .line 682
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 683
    .line 684
    check-cast v1, Lay0/n;

    .line 685
    .line 686
    check-cast p1, Ll2/o;

    .line 687
    .line 688
    check-cast p2, Ljava/lang/Integer;

    .line 689
    .line 690
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 691
    .line 692
    .line 693
    iget p0, p0, Ljk/b;->f:I

    .line 694
    .line 695
    or-int/lit8 p0, p0, 0x1

    .line 696
    .line 697
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 698
    .line 699
    .line 700
    move-result p0

    .line 701
    invoke-static {v0, v1, p1, p0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 702
    .line 703
    .line 704
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 705
    .line 706
    return-object p0

    .line 707
    :pswitch_18
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 708
    .line 709
    check-cast v0, Ll2/t1;

    .line 710
    .line 711
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 712
    .line 713
    check-cast v1, Lay0/n;

    .line 714
    .line 715
    check-cast p1, Ll2/o;

    .line 716
    .line 717
    check-cast p2, Ljava/lang/Integer;

    .line 718
    .line 719
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 720
    .line 721
    .line 722
    iget p0, p0, Ljk/b;->f:I

    .line 723
    .line 724
    or-int/lit8 p0, p0, 0x1

    .line 725
    .line 726
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 727
    .line 728
    .line 729
    move-result p0

    .line 730
    invoke-static {v0, v1, p1, p0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 731
    .line 732
    .line 733
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 734
    .line 735
    return-object p0

    .line 736
    :pswitch_19
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast v0, Lmc/x;

    .line 739
    .line 740
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 741
    .line 742
    check-cast v1, Lay0/k;

    .line 743
    .line 744
    check-cast p1, Ll2/o;

    .line 745
    .line 746
    check-cast p2, Ljava/lang/Integer;

    .line 747
    .line 748
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 749
    .line 750
    .line 751
    iget p0, p0, Ljk/b;->f:I

    .line 752
    .line 753
    or-int/lit8 p0, p0, 0x1

    .line 754
    .line 755
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 756
    .line 757
    .line 758
    move-result p0

    .line 759
    invoke-static {v0, v1, p1, p0}, Lkk/a;->b(Lmc/x;Lay0/k;Ll2/o;I)V

    .line 760
    .line 761
    .line 762
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 763
    .line 764
    return-object p0

    .line 765
    :pswitch_1a
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 766
    .line 767
    check-cast v0, Lmc/a0;

    .line 768
    .line 769
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 770
    .line 771
    check-cast v1, Lay0/k;

    .line 772
    .line 773
    check-cast p1, Ll2/o;

    .line 774
    .line 775
    check-cast p2, Ljava/lang/Integer;

    .line 776
    .line 777
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 778
    .line 779
    .line 780
    iget p0, p0, Ljk/b;->f:I

    .line 781
    .line 782
    or-int/lit8 p0, p0, 0x1

    .line 783
    .line 784
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 785
    .line 786
    .line 787
    move-result p0

    .line 788
    invoke-static {v0, v1, p1, p0}, Lkk/a;->d(Lmc/a0;Lay0/k;Ll2/o;I)V

    .line 789
    .line 790
    .line 791
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 792
    .line 793
    return-object p0

    .line 794
    :pswitch_1b
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 795
    .line 796
    check-cast v0, Lxh/e;

    .line 797
    .line 798
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 799
    .line 800
    check-cast v1, Lay0/k;

    .line 801
    .line 802
    check-cast p1, Ll2/o;

    .line 803
    .line 804
    check-cast p2, Ljava/lang/Integer;

    .line 805
    .line 806
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 807
    .line 808
    .line 809
    iget p0, p0, Ljk/b;->f:I

    .line 810
    .line 811
    or-int/lit8 p0, p0, 0x1

    .line 812
    .line 813
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 814
    .line 815
    .line 816
    move-result p0

    .line 817
    invoke-static {v0, v1, p1, p0}, Llp/kd;->a(Lxh/e;Lay0/k;Ll2/o;I)V

    .line 818
    .line 819
    .line 820
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 821
    .line 822
    return-object p0

    .line 823
    :pswitch_1c
    iget-object v0, p0, Ljk/b;->g:Ljava/lang/Object;

    .line 824
    .line 825
    check-cast v0, Lhe/h;

    .line 826
    .line 827
    iget-object v1, p0, Ljk/b;->e:Ljava/lang/Object;

    .line 828
    .line 829
    check-cast v1, Lay0/k;

    .line 830
    .line 831
    check-cast p1, Ll2/o;

    .line 832
    .line 833
    check-cast p2, Ljava/lang/Integer;

    .line 834
    .line 835
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 836
    .line 837
    .line 838
    iget p0, p0, Ljk/b;->f:I

    .line 839
    .line 840
    or-int/lit8 p0, p0, 0x1

    .line 841
    .line 842
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 843
    .line 844
    .line 845
    move-result p0

    .line 846
    invoke-static {v0, v1, p1, p0}, Ljk/a;->a(Lhe/h;Lay0/k;Ll2/o;I)V

    .line 847
    .line 848
    .line 849
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 850
    .line 851
    return-object p0

    .line 852
    nop

    .line 853
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
