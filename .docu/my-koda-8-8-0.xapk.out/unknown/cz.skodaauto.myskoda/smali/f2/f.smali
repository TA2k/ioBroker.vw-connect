.class public final Lf2/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc1/w1;Lt2/b;Lh2/xb;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lf2/f;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/f;->e:Ljava/lang/Object;

    iput-object p2, p0, Lf2/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lf2/f;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Lf2/f;->d:I

    iput-object p1, p0, Lf2/f;->e:Ljava/lang/Object;

    iput-object p2, p0, Lf2/f;->f:Ljava/lang/Object;

    iput-object p3, p0, Lf2/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lt2/b;Lt2/b;Lt2/b;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lf2/f;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/f;->g:Ljava/lang/Object;

    iput-object p2, p0, Lf2/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lf2/f;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lx2/s;Ll2/b1;Lt2/b;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lf2/f;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lf2/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lf2/f;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lf2/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    and-int/2addr p2, v3

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_5

    .line 32
    .line 33
    iget-object p2, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p2, Lx2/s;

    .line 36
    .line 37
    iget-object v0, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Ll2/b1;

    .line 40
    .line 41
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 46
    .line 47
    if-ne v1, v4, :cond_1

    .line 48
    .line 49
    new-instance v1, Lle/b;

    .line 50
    .line 51
    const/16 v4, 0x19

    .line 52
    .line 53
    invoke-direct {v1, v0, v4}, Lle/b;-><init>(Ll2/b1;I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    check-cast v1, Lay0/k;

    .line 60
    .line 61
    invoke-static {p2, v1}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Lt2/b;

    .line 68
    .line 69
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 70
    .line 71
    invoke-static {v0, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-wide v4, p1, Ll2/t;->T:J

    .line 76
    .line 77
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 90
    .line 91
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 95
    .line 96
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 97
    .line 98
    .line 99
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 100
    .line 101
    if-eqz v6, :cond_2

    .line 102
    .line 103
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_2
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 108
    .line 109
    .line 110
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 111
    .line 112
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 113
    .line 114
    .line 115
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 116
    .line 117
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 121
    .line 122
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 123
    .line 124
    if-nez v4, :cond_3

    .line 125
    .line 126
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    if-nez v4, :cond_4

    .line 139
    .line 140
    :cond_3
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 141
    .line 142
    .line 143
    :cond_4
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 144
    .line 145
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    invoke-static {v2, p0, p1, v3}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 159
    .line 160
    check-cast p2, Ljava/lang/Number;

    .line 161
    .line 162
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 163
    .line 164
    .line 165
    move-result p2

    .line 166
    and-int/lit8 v0, p2, 0x3

    .line 167
    .line 168
    const/4 v1, 0x2

    .line 169
    const/4 v2, 0x0

    .line 170
    const/4 v3, 0x1

    .line 171
    if-eq v0, v1, :cond_6

    .line 172
    .line 173
    move v0, v3

    .line 174
    goto :goto_3

    .line 175
    :cond_6
    move v0, v2

    .line 176
    :goto_3
    and-int/2addr p2, v3

    .line 177
    check-cast p1, Ll2/t;

    .line 178
    .line 179
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 180
    .line 181
    .line 182
    move-result p2

    .line 183
    if-eqz p2, :cond_7

    .line 184
    .line 185
    iget-object p2, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p2, Ljava/lang/String;

    .line 188
    .line 189
    iget-object v0, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v0, Ljava/lang/String;

    .line 192
    .line 193
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast p0, [Ljava/lang/Object;

    .line 196
    .line 197
    invoke-static {p0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-static {p2, v0, p1, p0}, Lkp/a7;->c(Ljava/lang/String;Ljava/lang/String;Ll2/t;[Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 206
    .line 207
    .line 208
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    return-object p0

    .line 211
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 212
    .line 213
    check-cast p2, Ljava/lang/Number;

    .line 214
    .line 215
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 216
    .line 217
    .line 218
    move-result p2

    .line 219
    and-int/lit8 v0, p2, 0x3

    .line 220
    .line 221
    const/4 v1, 0x2

    .line 222
    const/4 v2, 0x0

    .line 223
    const/4 v3, 0x1

    .line 224
    if-eq v0, v1, :cond_8

    .line 225
    .line 226
    move v0, v3

    .line 227
    goto :goto_5

    .line 228
    :cond_8
    move v0, v2

    .line 229
    :goto_5
    and-int/2addr p2, v3

    .line 230
    check-cast p1, Ll2/t;

    .line 231
    .line 232
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 233
    .line 234
    .line 235
    move-result p2

    .line 236
    if-eqz p2, :cond_c

    .line 237
    .line 238
    iget-object p2, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast p2, Lc1/w1;

    .line 241
    .line 242
    new-instance v0, Le1/u;

    .line 243
    .line 244
    const/4 v1, 0x3

    .line 245
    invoke-direct {v0, p2, v1}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 246
    .line 247
    .line 248
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 249
    .line 250
    invoke-static {p2, v0}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object p2

    .line 254
    iget-object v0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v0, Lt2/b;

    .line 257
    .line 258
    iget-object p0, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast p0, Lh2/xb;

    .line 261
    .line 262
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 263
    .line 264
    invoke-static {v1, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    iget-wide v4, p1, Ll2/t;->T:J

    .line 269
    .line 270
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 271
    .line 272
    .line 273
    move-result v2

    .line 274
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 275
    .line 276
    .line 277
    move-result-object v4

    .line 278
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 279
    .line 280
    .line 281
    move-result-object p2

    .line 282
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 283
    .line 284
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 285
    .line 286
    .line 287
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 288
    .line 289
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 290
    .line 291
    .line 292
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 293
    .line 294
    if-eqz v6, :cond_9

    .line 295
    .line 296
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 297
    .line 298
    .line 299
    goto :goto_6

    .line 300
    :cond_9
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 301
    .line 302
    .line 303
    :goto_6
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 304
    .line 305
    invoke-static {v5, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 306
    .line 307
    .line 308
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 309
    .line 310
    invoke-static {v1, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 311
    .line 312
    .line 313
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 314
    .line 315
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 316
    .line 317
    if-nez v4, :cond_a

    .line 318
    .line 319
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v4

    .line 323
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v4

    .line 331
    if-nez v4, :cond_b

    .line 332
    .line 333
    :cond_a
    invoke-static {v2, p1, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 334
    .line 335
    .line 336
    :cond_b
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 337
    .line 338
    invoke-static {v1, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 339
    .line 340
    .line 341
    const/4 p2, 0x6

    .line 342
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 343
    .line 344
    .line 345
    move-result-object p2

    .line 346
    invoke-virtual {v0, p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    goto :goto_7

    .line 353
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 354
    .line 355
    .line 356
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 357
    .line 358
    return-object p0

    .line 359
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 360
    .line 361
    check-cast p2, Ljava/lang/Number;

    .line 362
    .line 363
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 364
    .line 365
    .line 366
    move-result p2

    .line 367
    iget-object v0, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v0, Lt2/b;

    .line 370
    .line 371
    iget-object v1, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v1, Lt2/b;

    .line 374
    .line 375
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast p0, Lt2/b;

    .line 378
    .line 379
    and-int/lit8 v2, p2, 0x3

    .line 380
    .line 381
    const/4 v3, 0x2

    .line 382
    const/4 v4, 0x0

    .line 383
    const/4 v5, 0x1

    .line 384
    if-eq v2, v3, :cond_d

    .line 385
    .line 386
    move v2, v5

    .line 387
    goto :goto_8

    .line 388
    :cond_d
    move v2, v4

    .line 389
    :goto_8
    and-int/2addr p2, v5

    .line 390
    check-cast p1, Ll2/t;

    .line 391
    .line 392
    invoke-virtual {p1, p2, v2}, Ll2/t;->O(IZ)Z

    .line 393
    .line 394
    .line 395
    move-result p2

    .line 396
    if-eqz p2, :cond_10

    .line 397
    .line 398
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 399
    .line 400
    const/high16 v2, 0x3f800000    # 1.0f

    .line 401
    .line 402
    invoke-static {p2, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 403
    .line 404
    .line 405
    move-result-object p2

    .line 406
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 407
    .line 408
    .line 409
    move-result v2

    .line 410
    invoke-virtual {p1, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 411
    .line 412
    .line 413
    move-result v3

    .line 414
    or-int/2addr v2, v3

    .line 415
    invoke-virtual {p1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    move-result v3

    .line 419
    or-int/2addr v2, v3

    .line 420
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v3

    .line 424
    if-nez v2, :cond_e

    .line 425
    .line 426
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 427
    .line 428
    if-ne v3, v2, :cond_f

    .line 429
    .line 430
    :cond_e
    new-instance v3, Lal/b;

    .line 431
    .line 432
    invoke-direct {v3, p0, v1, v0}, Lal/b;-><init>(Lt2/b;Lt2/b;Lt2/b;)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {p1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    :cond_f
    check-cast v3, Lay0/n;

    .line 439
    .line 440
    const/4 p0, 0x6

    .line 441
    invoke-static {p2, v3, p1, p0, v4}, Lt3/k1;->c(Lx2/s;Lay0/n;Ll2/o;II)V

    .line 442
    .line 443
    .line 444
    goto :goto_9

    .line 445
    :cond_10
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 446
    .line 447
    .line 448
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 449
    .line 450
    return-object p0

    .line 451
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 452
    .line 453
    check-cast p2, Ljava/lang/Number;

    .line 454
    .line 455
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 456
    .line 457
    .line 458
    move-result p2

    .line 459
    iget-object v0, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast v0, Lh2/g4;

    .line 462
    .line 463
    and-int/lit8 v1, p2, 0x3

    .line 464
    .line 465
    const/4 v2, 0x2

    .line 466
    const/4 v3, 0x1

    .line 467
    if-eq v1, v2, :cond_11

    .line 468
    .line 469
    move v1, v3

    .line 470
    goto :goto_a

    .line 471
    :cond_11
    const/4 v1, 0x0

    .line 472
    :goto_a
    and-int/2addr p2, v3

    .line 473
    move-object v10, p1

    .line 474
    check-cast v10, Ll2/t;

    .line 475
    .line 476
    invoke-virtual {v10, p2, v1}, Ll2/t;->O(IZ)Z

    .line 477
    .line 478
    .line 479
    move-result p1

    .line 480
    if-eqz p1, :cond_12

    .line 481
    .line 482
    sget-object v2, Lh2/v3;->a:Lh2/v3;

    .line 483
    .line 484
    invoke-virtual {v0}, Lh2/g4;->h()Ljava/lang/Long;

    .line 485
    .line 486
    .line 487
    move-result-object v3

    .line 488
    invoke-virtual {v0}, Lh2/g4;->g()Ljava/lang/Long;

    .line 489
    .line 490
    .line 491
    move-result-object v4

    .line 492
    invoke-virtual {v0}, Lh2/g4;->f()I

    .line 493
    .line 494
    .line 495
    move-result v5

    .line 496
    iget-object p1, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 497
    .line 498
    move-object v6, p1

    .line 499
    check-cast v6, Lh2/g2;

    .line 500
    .line 501
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 502
    .line 503
    sget-object p2, Lh2/f4;->c:Lk1/a1;

    .line 504
    .line 505
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 506
    .line 507
    .line 508
    move-result-object v7

    .line 509
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 510
    .line 511
    check-cast p0, Lh2/z1;

    .line 512
    .line 513
    iget-wide v8, p0, Lh2/z1;->c:J

    .line 514
    .line 515
    const v11, 0x186000

    .line 516
    .line 517
    .line 518
    invoke-virtual/range {v2 .. v11}, Lh2/v3;->b(Ljava/lang/Long;Ljava/lang/Long;ILh2/g2;Lx2/s;JLl2/o;I)V

    .line 519
    .line 520
    .line 521
    goto :goto_b

    .line 522
    :cond_12
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 523
    .line 524
    .line 525
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 526
    .line 527
    return-object p0

    .line 528
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 529
    .line 530
    check-cast p2, Ljava/lang/Number;

    .line 531
    .line 532
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 533
    .line 534
    .line 535
    move-result p2

    .line 536
    iget-object v0, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v0, Lh2/o3;

    .line 539
    .line 540
    and-int/lit8 v1, p2, 0x3

    .line 541
    .line 542
    const/4 v2, 0x2

    .line 543
    const/4 v3, 0x1

    .line 544
    if-eq v1, v2, :cond_13

    .line 545
    .line 546
    move v1, v3

    .line 547
    goto :goto_c

    .line 548
    :cond_13
    const/4 v1, 0x0

    .line 549
    :goto_c
    and-int/2addr p2, v3

    .line 550
    move-object v9, p1

    .line 551
    check-cast v9, Ll2/t;

    .line 552
    .line 553
    invoke-virtual {v9, p2, v1}, Ll2/t;->O(IZ)Z

    .line 554
    .line 555
    .line 556
    move-result p1

    .line 557
    if-eqz p1, :cond_14

    .line 558
    .line 559
    sget-object v2, Lh2/c2;->a:Lh2/c2;

    .line 560
    .line 561
    invoke-virtual {v0}, Lh2/o3;->g()Ljava/lang/Long;

    .line 562
    .line 563
    .line 564
    move-result-object v3

    .line 565
    invoke-virtual {v0}, Lh2/o3;->f()I

    .line 566
    .line 567
    .line 568
    move-result v4

    .line 569
    iget-object p1, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 570
    .line 571
    move-object v5, p1

    .line 572
    check-cast v5, Lh2/g2;

    .line 573
    .line 574
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 575
    .line 576
    sget-object p2, Lh2/m3;->e:Lk1/a1;

    .line 577
    .line 578
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 579
    .line 580
    .line 581
    move-result-object v6

    .line 582
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast p0, Lh2/z1;

    .line 585
    .line 586
    iget-wide v7, p0, Lh2/z1;->c:J

    .line 587
    .line 588
    const v10, 0x30c00

    .line 589
    .line 590
    .line 591
    invoke-virtual/range {v2 .. v10}, Lh2/c2;->a(Ljava/lang/Long;ILh2/g2;Lx2/s;JLl2/o;I)V

    .line 592
    .line 593
    .line 594
    goto :goto_d

    .line 595
    :cond_14
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 596
    .line 597
    .line 598
    :goto_d
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 599
    .line 600
    return-object p0

    .line 601
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 602
    .line 603
    check-cast p2, Ljava/lang/Number;

    .line 604
    .line 605
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 606
    .line 607
    .line 608
    move-result p2

    .line 609
    and-int/lit8 v0, p2, 0x3

    .line 610
    .line 611
    const/4 v1, 0x2

    .line 612
    const/4 v2, 0x1

    .line 613
    if-eq v0, v1, :cond_15

    .line 614
    .line 615
    move v0, v2

    .line 616
    goto :goto_e

    .line 617
    :cond_15
    const/4 v0, 0x0

    .line 618
    :goto_e
    and-int/2addr p2, v2

    .line 619
    check-cast p1, Ll2/t;

    .line 620
    .line 621
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 622
    .line 623
    .line 624
    move-result p2

    .line 625
    if-eqz p2, :cond_16

    .line 626
    .line 627
    sget-object p2, Lf2/i;->a:Ll2/e0;

    .line 628
    .line 629
    iget-object v0, p0, Lf2/f;->e:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast v0, Ll2/b1;

    .line 632
    .line 633
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object v0

    .line 637
    check-cast v0, Le3/s;

    .line 638
    .line 639
    iget-wide v0, v0, Le3/s;->a:J

    .line 640
    .line 641
    invoke-static {v0, v1}, Le3/s;->d(J)F

    .line 642
    .line 643
    .line 644
    move-result v0

    .line 645
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 646
    .line 647
    .line 648
    move-result-object v0

    .line 649
    invoke-virtual {p2, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 650
    .line 651
    .line 652
    move-result-object p2

    .line 653
    new-instance v0, Lf2/e;

    .line 654
    .line 655
    iget-object v1, p0, Lf2/f;->f:Ljava/lang/Object;

    .line 656
    .line 657
    check-cast v1, Lk1/z0;

    .line 658
    .line 659
    iget-object p0, p0, Lf2/f;->g:Ljava/lang/Object;

    .line 660
    .line 661
    check-cast p0, Lt2/b;

    .line 662
    .line 663
    const/4 v2, 0x1

    .line 664
    invoke-direct {v0, v1, p0, v2}, Lf2/e;-><init>(Lk1/z0;Lt2/b;I)V

    .line 665
    .line 666
    .line 667
    const p0, -0x33da2ede    # -4.3467912E7f

    .line 668
    .line 669
    .line 670
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 671
    .line 672
    .line 673
    move-result-object p0

    .line 674
    const/16 v0, 0x38

    .line 675
    .line 676
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 677
    .line 678
    .line 679
    goto :goto_f

    .line 680
    :cond_16
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 681
    .line 682
    .line 683
    :goto_f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 684
    .line 685
    return-object p0

    .line 686
    nop

    .line 687
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
