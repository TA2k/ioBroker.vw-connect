.class public final synthetic Le2/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Li3/c;Lx2/s;ZI)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    iput v0, p0, Le2/x0;->d:I

    sget-object v0, Li91/d1;->d:[Li91/d1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/x0;->g:Ljava/lang/Object;

    iput-object p2, p0, Le2/x0;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Le2/x0;->e:Z

    iput p4, p0, Le2/x0;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZII)V
    .locals 0

    .line 2
    iput p5, p0, Le2/x0;->d:I

    iput-object p1, p0, Le2/x0;->g:Ljava/lang/Object;

    iput-object p2, p0, Le2/x0;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Le2/x0;->e:Z

    iput p4, p0, Le2/x0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZLjava/lang/Object;II)V
    .locals 0

    .line 3
    iput p5, p0, Le2/x0;->d:I

    iput-object p1, p0, Le2/x0;->g:Ljava/lang/Object;

    iput-boolean p2, p0, Le2/x0;->e:Z

    iput-object p3, p0, Le2/x0;->h:Ljava/lang/Object;

    iput p4, p0, Le2/x0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lyj0/a;Lx2/s;ZII)V
    .locals 0

    .line 4
    const/16 p4, 0x15

    iput p4, p0, Le2/x0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/x0;->g:Ljava/lang/Object;

    iput-object p2, p0, Le2/x0;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Le2/x0;->e:Z

    iput p5, p0, Le2/x0;->f:I

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    .line 5
    iput p5, p0, Le2/x0;->d:I

    iput-boolean p1, p0, Le2/x0;->e:Z

    iput-object p2, p0, Le2/x0;->g:Ljava/lang/Object;

    iput-object p3, p0, Le2/x0;->h:Ljava/lang/Object;

    iput p4, p0, Le2/x0;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Le2/x0;->d:I

    .line 2
    .line 3
    iget v1, p0, Le2/x0;->f:I

    .line 4
    .line 5
    iget-boolean v2, p0, Le2/x0;->e:Z

    .line 6
    .line 7
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    iget-object v5, p0, Le2/x0;->h:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v6, p0, Le2/x0;->g:Ljava/lang/Object;

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object v7, v6

    .line 18
    check-cast v7, Lyj0/a;

    .line 19
    .line 20
    move-object v8, v5

    .line 21
    check-cast v8, Lx2/s;

    .line 22
    .line 23
    move-object v10, p1

    .line 24
    check-cast v10, Ll2/o;

    .line 25
    .line 26
    check-cast p2, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 32
    .line 33
    .line 34
    move-result v11

    .line 35
    iget-boolean v9, p0, Le2/x0;->e:Z

    .line 36
    .line 37
    iget v12, p0, Le2/x0;->f:I

    .line 38
    .line 39
    invoke-static/range {v7 .. v12}, Lzj0/d;->c(Lyj0/a;Lx2/s;ZLl2/o;II)V

    .line 40
    .line 41
    .line 42
    return-object v3

    .line 43
    :pswitch_0
    check-cast v6, Lwk0/f;

    .line 44
    .line 45
    check-cast v5, Lay0/k;

    .line 46
    .line 47
    check-cast p1, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    or-int/lit8 p0, v1, 0x1

    .line 55
    .line 56
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    invoke-static {v6, v2, v5, p1, p0}, Lxk0/h;->m(Lwk0/f;ZLay0/k;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    return-object v3

    .line 64
    :pswitch_1
    check-cast v6, Lwk0/g;

    .line 65
    .line 66
    check-cast v5, Lay0/k;

    .line 67
    .line 68
    check-cast p1, Ll2/o;

    .line 69
    .line 70
    check-cast p2, Ljava/lang/Integer;

    .line 71
    .line 72
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    or-int/lit8 p0, v1, 0x1

    .line 76
    .line 77
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    invoke-static {v6, v2, v5, p1, p0}, Lxk0/h;->n(Lwk0/g;ZLay0/k;Ll2/o;I)V

    .line 82
    .line 83
    .line 84
    return-object v3

    .line 85
    :pswitch_2
    check-cast v6, Lwk0/k;

    .line 86
    .line 87
    check-cast v5, Lay0/k;

    .line 88
    .line 89
    check-cast p1, Ll2/o;

    .line 90
    .line 91
    check-cast p2, Ljava/lang/Integer;

    .line 92
    .line 93
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 94
    .line 95
    .line 96
    or-int/lit8 p0, v1, 0x1

    .line 97
    .line 98
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    invoke-static {v6, v2, v5, p1, p0}, Lxk0/h;->o(Lwk0/k;ZLay0/k;Ll2/o;I)V

    .line 103
    .line 104
    .line 105
    return-object v3

    .line 106
    :pswitch_3
    check-cast v6, Lzb/r0;

    .line 107
    .line 108
    check-cast v5, Ljava/lang/String;

    .line 109
    .line 110
    check-cast p1, Ll2/o;

    .line 111
    .line 112
    check-cast p2, Ljava/lang/Integer;

    .line 113
    .line 114
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 115
    .line 116
    .line 117
    or-int/lit8 p0, v1, 0x1

    .line 118
    .line 119
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    invoke-static {v6, v5, v2, p1, p0}, Lxj/f;->j(Lzb/r0;Ljava/lang/String;ZLl2/o;I)V

    .line 124
    .line 125
    .line 126
    return-object v3

    .line 127
    :pswitch_4
    check-cast v6, Lk1/q;

    .line 128
    .line 129
    check-cast v5, Lj2/p;

    .line 130
    .line 131
    check-cast p1, Ll2/o;

    .line 132
    .line 133
    check-cast p2, Ljava/lang/Integer;

    .line 134
    .line 135
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    or-int/lit8 p0, v1, 0x1

    .line 139
    .line 140
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    invoke-static {v6, v5, v2, p1, p0}, Lxf0/y1;->j(Lk1/q;Lj2/p;ZLl2/o;I)V

    .line 145
    .line 146
    .line 147
    return-object v3

    .line 148
    :pswitch_5
    check-cast v6, Luj/k0;

    .line 149
    .line 150
    check-cast v5, Lay0/k;

    .line 151
    .line 152
    check-cast p1, Ll2/o;

    .line 153
    .line 154
    check-cast p2, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    or-int/lit8 p0, v1, 0x1

    .line 160
    .line 161
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v6, v2, v5, p1, p0}, Luj/k0;->D(ZLay0/k;Ll2/o;I)V

    .line 166
    .line 167
    .line 168
    return-object v3

    .line 169
    :pswitch_6
    check-cast v6, Luj/b0;

    .line 170
    .line 171
    check-cast v5, Lay0/k;

    .line 172
    .line 173
    check-cast p1, Ll2/o;

    .line 174
    .line 175
    check-cast p2, Ljava/lang/Integer;

    .line 176
    .line 177
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 178
    .line 179
    .line 180
    or-int/lit8 p0, v1, 0x1

    .line 181
    .line 182
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    invoke-virtual {v6, v2, v5, p1, p0}, Luj/b0;->D(ZLay0/k;Ll2/o;I)V

    .line 187
    .line 188
    .line 189
    return-object v3

    .line 190
    :pswitch_7
    check-cast v6, Luj/b0;

    .line 191
    .line 192
    check-cast v5, Lt2/b;

    .line 193
    .line 194
    check-cast p1, Ll2/o;

    .line 195
    .line 196
    check-cast p2, Ljava/lang/Integer;

    .line 197
    .line 198
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    or-int/lit8 p0, v1, 0x1

    .line 202
    .line 203
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 204
    .line 205
    .line 206
    move-result p0

    .line 207
    invoke-virtual {v6, v2, v5, p1, p0}, Luj/b0;->l(ZLt2/b;Ll2/o;I)V

    .line 208
    .line 209
    .line 210
    return-object v3

    .line 211
    :pswitch_8
    check-cast v6, Luj/e;

    .line 212
    .line 213
    check-cast v5, Lt2/b;

    .line 214
    .line 215
    check-cast p1, Ll2/o;

    .line 216
    .line 217
    check-cast p2, Ljava/lang/Integer;

    .line 218
    .line 219
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 220
    .line 221
    .line 222
    or-int/lit8 p0, v1, 0x1

    .line 223
    .line 224
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 225
    .line 226
    .line 227
    move-result p0

    .line 228
    invoke-virtual {v6, v2, v5, p1, p0}, Luj/e;->l(ZLt2/b;Ll2/o;I)V

    .line 229
    .line 230
    .line 231
    return-object v3

    .line 232
    :pswitch_9
    check-cast v6, Lay0/a;

    .line 233
    .line 234
    check-cast v5, Lay0/a;

    .line 235
    .line 236
    check-cast p1, Ll2/o;

    .line 237
    .line 238
    check-cast p2, Ljava/lang/Integer;

    .line 239
    .line 240
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 241
    .line 242
    .line 243
    or-int/lit8 p0, v1, 0x1

    .line 244
    .line 245
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 246
    .line 247
    .line 248
    move-result p0

    .line 249
    invoke-static {p0, v6, v5, p1, v2}, Llp/t1;->c(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 250
    .line 251
    .line 252
    return-object v3

    .line 253
    :pswitch_a
    check-cast v6, Lon0/a0;

    .line 254
    .line 255
    check-cast v5, Lay0/k;

    .line 256
    .line 257
    check-cast p1, Ll2/o;

    .line 258
    .line 259
    check-cast p2, Ljava/lang/Integer;

    .line 260
    .line 261
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 262
    .line 263
    .line 264
    or-int/lit8 p0, v1, 0x1

    .line 265
    .line 266
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 267
    .line 268
    .line 269
    move-result p0

    .line 270
    invoke-static {v6, v2, v5, p1, p0}, Ls60/j;->b(Lon0/a0;ZLay0/k;Ll2/o;I)V

    .line 271
    .line 272
    .line 273
    return-object v3

    .line 274
    :pswitch_b
    move-object v7, v6

    .line 275
    check-cast v7, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 276
    .line 277
    move-object v9, v5

    .line 278
    check-cast v9, Lay0/a;

    .line 279
    .line 280
    move-object v11, p1

    .line 281
    check-cast v11, Ll2/o;

    .line 282
    .line 283
    check-cast p2, Ljava/lang/Integer;

    .line 284
    .line 285
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 286
    .line 287
    .line 288
    move-result v12

    .line 289
    iget-boolean v8, p0, Le2/x0;->e:Z

    .line 290
    .line 291
    iget v10, p0, Le2/x0;->f:I

    .line 292
    .line 293
    invoke-static/range {v7 .. v12}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->l(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;ZLay0/a;ILl2/o;I)Llx0/b0;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    return-object p0

    .line 298
    :pswitch_c
    check-cast v6, Ljava/util/List;

    .line 299
    .line 300
    check-cast v5, Ljava/util/List;

    .line 301
    .line 302
    check-cast p1, Ll2/o;

    .line 303
    .line 304
    check-cast p2, Ljava/lang/Integer;

    .line 305
    .line 306
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 307
    .line 308
    .line 309
    or-int/lit8 p0, v1, 0x1

    .line 310
    .line 311
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 312
    .line 313
    .line 314
    move-result p0

    .line 315
    invoke-static {v6, v5, v2, p1, p0}, Ln70/a;->w(Ljava/util/List;Ljava/util/List;ZLl2/o;I)V

    .line 316
    .line 317
    .line 318
    return-object v3

    .line 319
    :pswitch_d
    check-cast v6, Ljava/util/List;

    .line 320
    .line 321
    check-cast v5, Lay0/k;

    .line 322
    .line 323
    check-cast p1, Ll2/o;

    .line 324
    .line 325
    check-cast p2, Ljava/lang/Integer;

    .line 326
    .line 327
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 328
    .line 329
    .line 330
    or-int/lit8 p0, v1, 0x1

    .line 331
    .line 332
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 333
    .line 334
    .line 335
    move-result p0

    .line 336
    invoke-static {p0, v5, v6, p1, v2}, Lm60/a;->a(ILay0/k;Ljava/util/List;Ll2/o;Z)V

    .line 337
    .line 338
    .line 339
    return-object v3

    .line 340
    :pswitch_e
    check-cast v6, Lmc/y;

    .line 341
    .line 342
    check-cast v5, Lay0/k;

    .line 343
    .line 344
    check-cast p1, Ll2/o;

    .line 345
    .line 346
    check-cast p2, Ljava/lang/Integer;

    .line 347
    .line 348
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 349
    .line 350
    .line 351
    or-int/lit8 p0, v1, 0x1

    .line 352
    .line 353
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 354
    .line 355
    .line 356
    move-result p0

    .line 357
    invoke-static {v6, v5, v2, p1, p0}, Lkk/a;->e(Lmc/y;Lay0/k;ZLl2/o;I)V

    .line 358
    .line 359
    .line 360
    return-object v3

    .line 361
    :pswitch_f
    check-cast v6, Li91/k1;

    .line 362
    .line 363
    check-cast v5, Lx2/s;

    .line 364
    .line 365
    check-cast p1, Ll2/o;

    .line 366
    .line 367
    check-cast p2, Ljava/lang/Integer;

    .line 368
    .line 369
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 370
    .line 371
    .line 372
    or-int/lit8 p0, v1, 0x1

    .line 373
    .line 374
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 375
    .line 376
    .line 377
    move-result p0

    .line 378
    invoke-static {v6, v5, v2, p1, p0}, Li91/j0;->I(Li91/k1;Lx2/s;ZLl2/o;I)V

    .line 379
    .line 380
    .line 381
    return-object v3

    .line 382
    :pswitch_10
    check-cast v6, Li3/c;

    .line 383
    .line 384
    sget-object p0, Li91/d1;->d:[Li91/d1;

    .line 385
    .line 386
    check-cast v5, Lx2/s;

    .line 387
    .line 388
    check-cast p1, Ll2/o;

    .line 389
    .line 390
    check-cast p2, Ljava/lang/Integer;

    .line 391
    .line 392
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 393
    .line 394
    .line 395
    or-int/lit8 p0, v1, 0x1

    .line 396
    .line 397
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 398
    .line 399
    .line 400
    move-result p0

    .line 401
    invoke-static {v6, v5, v2, p1, p0}, Li91/j0;->e(Li3/c;Lx2/s;ZLl2/o;I)V

    .line 402
    .line 403
    .line 404
    return-object v3

    .line 405
    :pswitch_11
    check-cast v6, Lh50/i;

    .line 406
    .line 407
    check-cast v5, Ljava/lang/String;

    .line 408
    .line 409
    check-cast p1, Ll2/o;

    .line 410
    .line 411
    check-cast p2, Ljava/lang/Integer;

    .line 412
    .line 413
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    or-int/lit8 p0, v1, 0x1

    .line 417
    .line 418
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 419
    .line 420
    .line 421
    move-result p0

    .line 422
    invoke-static {v6, v2, v5, p1, p0}, Li50/c;->k(Lh50/i;ZLjava/lang/String;Ll2/o;I)V

    .line 423
    .line 424
    .line 425
    return-object v3

    .line 426
    :pswitch_12
    check-cast v6, Lh40/m;

    .line 427
    .line 428
    check-cast v5, Lx2/s;

    .line 429
    .line 430
    check-cast p1, Ll2/o;

    .line 431
    .line 432
    check-cast p2, Ljava/lang/Integer;

    .line 433
    .line 434
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    or-int/lit8 p0, v1, 0x1

    .line 438
    .line 439
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 440
    .line 441
    .line 442
    move-result p0

    .line 443
    invoke-static {v6, v2, v5, p1, p0}, Li40/m2;->c(Lh40/m;ZLx2/s;Ll2/o;I)V

    .line 444
    .line 445
    .line 446
    return-object v3

    .line 447
    :pswitch_13
    check-cast v6, Le30/v;

    .line 448
    .line 449
    check-cast v5, Ld01/h0;

    .line 450
    .line 451
    check-cast p1, Ll2/o;

    .line 452
    .line 453
    check-cast p2, Ljava/lang/Integer;

    .line 454
    .line 455
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 456
    .line 457
    .line 458
    or-int/lit8 p0, v1, 0x1

    .line 459
    .line 460
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 461
    .line 462
    .line 463
    move-result p0

    .line 464
    invoke-static {v6, v2, v5, p1, p0}, Lf30/a;->p(Le30/v;ZLd01/h0;Ll2/o;I)V

    .line 465
    .line 466
    .line 467
    return-object v3

    .line 468
    :pswitch_14
    check-cast v6, Lr4/j;

    .line 469
    .line 470
    check-cast v5, Le2/w0;

    .line 471
    .line 472
    check-cast p1, Ll2/o;

    .line 473
    .line 474
    check-cast p2, Ljava/lang/Integer;

    .line 475
    .line 476
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 477
    .line 478
    .line 479
    or-int/lit8 p0, v1, 0x1

    .line 480
    .line 481
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 482
    .line 483
    .line 484
    move-result p0

    .line 485
    invoke-static {v2, v6, v5, p1, p0}, Lkp/w;->a(ZLr4/j;Le2/w0;Ll2/o;I)V

    .line 486
    .line 487
    .line 488
    return-object v3

    .line 489
    :pswitch_data_0
    .packed-switch 0x0
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
