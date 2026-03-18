.class public final synthetic Lxk0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lxk0/w;->d:I

    iput-object p3, p0, Lxk0/w;->f:Ljava/lang/Object;

    iput-object p4, p0, Lxk0/w;->g:Ljava/lang/Object;

    iput p1, p0, Lxk0/w;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILe3/s;Ljava/lang/String;I)V
    .locals 0

    .line 2
    const/4 p4, 0x6

    iput p4, p0, Lxk0/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lxk0/w;->e:I

    iput-object p2, p0, Lxk0/w;->f:Ljava/lang/Object;

    iput-object p3, p0, Lxk0/w;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lay0/n;I)V
    .locals 1

    .line 3
    const/16 v0, 0xa

    iput v0, p0, Lxk0/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/w;->g:Ljava/lang/Object;

    iput-object p2, p0, Lxk0/w;->f:Ljava/lang/Object;

    iput p3, p0, Lxk0/w;->e:I

    return-void
.end method

.method public synthetic constructor <init>(Lxm0/b;Lay0/a;II)V
    .locals 0

    .line 4
    const/4 p3, 0x4

    iput p3, p0, Lxk0/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/w;->f:Ljava/lang/Object;

    iput-object p2, p0, Lxk0/w;->g:Ljava/lang/Object;

    iput p4, p0, Lxk0/w;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxk0/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkh/i;

    .line 9
    .line 10
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lay0/k;

    .line 13
    .line 14
    check-cast p1, Ll2/o;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    iget p0, p0, Lxk0/w;->e:I

    .line 22
    .line 23
    or-int/lit8 p0, p0, 0x1

    .line 24
    .line 25
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {v0, v1, p1, p0}, Ljp/i1;->j(Lkh/i;Lay0/k;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lxj0/m;

    .line 38
    .line 39
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lyl/l;

    .line 42
    .line 43
    check-cast p1, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 48
    .line 49
    .line 50
    iget p0, p0, Lxk0/w;->e:I

    .line 51
    .line 52
    or-int/lit8 p0, p0, 0x1

    .line 53
    .line 54
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    invoke-static {v0, v1, p1, p0}, Lzj0/d;->g(Lxj0/m;Lyl/l;Ll2/o;I)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_1
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lxj0/k;

    .line 65
    .line 66
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v1, Lyl/l;

    .line 69
    .line 70
    check-cast p1, Ll2/o;

    .line 71
    .line 72
    check-cast p2, Ljava/lang/Integer;

    .line 73
    .line 74
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    iget p0, p0, Lxk0/w;->e:I

    .line 78
    .line 79
    or-int/lit8 p0, p0, 0x1

    .line 80
    .line 81
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    invoke-static {v0, v1, p1, p0}, Lzj0/d;->a(Lxj0/k;Lyl/l;Ll2/o;I)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :pswitch_2
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Lxj0/p;

    .line 92
    .line 93
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v1, Lyl/l;

    .line 96
    .line 97
    check-cast p1, Ll2/o;

    .line 98
    .line 99
    check-cast p2, Ljava/lang/Integer;

    .line 100
    .line 101
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 102
    .line 103
    .line 104
    iget p0, p0, Lxk0/w;->e:I

    .line 105
    .line 106
    or-int/lit8 p0, p0, 0x1

    .line 107
    .line 108
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    invoke-static {v0, v1, p1, p0}, Lzj0/d;->i(Lxj0/p;Lyl/l;Ll2/o;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :pswitch_3
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v0, Lxj0/r;

    .line 119
    .line 120
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v1, Lyl/l;

    .line 123
    .line 124
    check-cast p1, Ll2/o;

    .line 125
    .line 126
    check-cast p2, Ljava/lang/Integer;

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 129
    .line 130
    .line 131
    iget p0, p0, Lxk0/w;->e:I

    .line 132
    .line 133
    or-int/lit8 p0, p0, 0x1

    .line 134
    .line 135
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    invoke-static {v0, v1, p1, p0}, Lzj0/j;->i(Lxj0/r;Lyl/l;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :pswitch_4
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v0, Lzj0/c;

    .line 146
    .line 147
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v1, Lyl/l;

    .line 150
    .line 151
    check-cast p1, Ll2/o;

    .line 152
    .line 153
    check-cast p2, Ljava/lang/Integer;

    .line 154
    .line 155
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 156
    .line 157
    .line 158
    iget p0, p0, Lxk0/w;->e:I

    .line 159
    .line 160
    or-int/lit8 p0, p0, 0x1

    .line 161
    .line 162
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    invoke-static {v0, v1, p1, p0}, Lzj0/j;->b(Lzj0/c;Lyl/l;Ll2/o;I)V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_0

    .line 170
    .line 171
    :pswitch_5
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v0, Luu/g;

    .line 174
    .line 175
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 184
    .line 185
    .line 186
    iget p0, p0, Lxk0/w;->e:I

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
    invoke-static {v0, v1, p1, p0}, Lzj0/j;->e(Luu/g;Lay0/k;Ll2/o;I)V

    .line 195
    .line 196
    .line 197
    goto/16 :goto_0

    .line 198
    .line 199
    :pswitch_6
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Lxj0/j;

    .line 202
    .line 203
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v1, Lt2/b;

    .line 206
    .line 207
    check-cast p1, Ll2/o;

    .line 208
    .line 209
    check-cast p2, Ljava/lang/Integer;

    .line 210
    .line 211
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 212
    .line 213
    .line 214
    iget p0, p0, Lxk0/w;->e:I

    .line 215
    .line 216
    or-int/lit8 p0, p0, 0x1

    .line 217
    .line 218
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    invoke-static {v0, v1, p1, p0}, Lzj0/d;->b(Lxj0/j;Lt2/b;Ll2/o;I)V

    .line 223
    .line 224
    .line 225
    goto/16 :goto_0

    .line 226
    .line 227
    :pswitch_7
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v0, Lfd/d;

    .line 230
    .line 231
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast v1, Lb6/f;

    .line 234
    .line 235
    check-cast p1, Ll2/o;

    .line 236
    .line 237
    check-cast p2, Ljava/lang/Integer;

    .line 238
    .line 239
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    iget p0, p0, Lxk0/w;->e:I

    .line 243
    .line 244
    or-int/lit8 p0, p0, 0x1

    .line 245
    .line 246
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 247
    .line 248
    .line 249
    move-result p0

    .line 250
    invoke-static {v0, v1, p1, p0}, Lzj/a;->a(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    goto/16 :goto_0

    .line 254
    .line 255
    :pswitch_8
    iget-object v0, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v0, Lay0/a;

    .line 258
    .line 259
    iget-object v1, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast v1, Lay0/n;

    .line 262
    .line 263
    check-cast p1, Ll2/o;

    .line 264
    .line 265
    check-cast p2, Ljava/lang/Integer;

    .line 266
    .line 267
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 268
    .line 269
    .line 270
    iget p0, p0, Lxk0/w;->e:I

    .line 271
    .line 272
    or-int/lit8 p0, p0, 0x1

    .line 273
    .line 274
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 275
    .line 276
    .line 277
    move-result p0

    .line 278
    invoke-static {v0, v1, p1, p0}, Lzb/b;->f(Lay0/a;Lay0/n;Ll2/o;I)V

    .line 279
    .line 280
    .line 281
    goto/16 :goto_0

    .line 282
    .line 283
    :pswitch_9
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v0, Lkn/c0;

    .line 286
    .line 287
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v1, Lay0/a;

    .line 290
    .line 291
    check-cast p1, Ll2/o;

    .line 292
    .line 293
    check-cast p2, Ljava/lang/Integer;

    .line 294
    .line 295
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 296
    .line 297
    .line 298
    iget p0, p0, Lxk0/w;->e:I

    .line 299
    .line 300
    or-int/lit8 p0, p0, 0x1

    .line 301
    .line 302
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 303
    .line 304
    .line 305
    move-result p0

    .line 306
    invoke-static {v0, v1, p1, p0}, Lzb/b;->j(Lkn/c0;Lay0/a;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    goto/16 :goto_0

    .line 310
    .line 311
    :pswitch_a
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v0, Ly70/p1;

    .line 314
    .line 315
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v1, Lay0/a;

    .line 318
    .line 319
    check-cast p1, Ll2/o;

    .line 320
    .line 321
    check-cast p2, Ljava/lang/Integer;

    .line 322
    .line 323
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 324
    .line 325
    .line 326
    iget p0, p0, Lxk0/w;->e:I

    .line 327
    .line 328
    or-int/lit8 p0, p0, 0x1

    .line 329
    .line 330
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 331
    .line 332
    .line 333
    move-result p0

    .line 334
    invoke-static {v0, v1, p1, p0}, Lz70/l;->u(Ly70/p1;Lay0/a;Ll2/o;I)V

    .line 335
    .line 336
    .line 337
    goto/16 :goto_0

    .line 338
    .line 339
    :pswitch_b
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 340
    .line 341
    check-cast v0, Ly70/z0;

    .line 342
    .line 343
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 344
    .line 345
    check-cast v1, Lay0/k;

    .line 346
    .line 347
    check-cast p1, Ll2/o;

    .line 348
    .line 349
    check-cast p2, Ljava/lang/Integer;

    .line 350
    .line 351
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 352
    .line 353
    .line 354
    iget p0, p0, Lxk0/w;->e:I

    .line 355
    .line 356
    or-int/lit8 p0, p0, 0x1

    .line 357
    .line 358
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 359
    .line 360
    .line 361
    move-result p0

    .line 362
    invoke-static {v0, v1, p1, p0}, Lz70/l;->H(Ly70/z0;Lay0/k;Ll2/o;I)V

    .line 363
    .line 364
    .line 365
    goto/16 :goto_0

    .line 366
    .line 367
    :pswitch_c
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v0, Le3/s;

    .line 370
    .line 371
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v1, Ljava/lang/String;

    .line 374
    .line 375
    check-cast p1, Ll2/o;

    .line 376
    .line 377
    check-cast p2, Ljava/lang/Integer;

    .line 378
    .line 379
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    const/4 p2, 0x1

    .line 383
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 384
    .line 385
    .line 386
    move-result p2

    .line 387
    iget p0, p0, Lxk0/w;->e:I

    .line 388
    .line 389
    invoke-static {p0, v0, v1, p1, p2}, Lz70/s;->e(ILe3/s;Ljava/lang/String;Ll2/o;I)V

    .line 390
    .line 391
    .line 392
    goto/16 :goto_0

    .line 393
    .line 394
    :pswitch_d
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v0, Landroidx/media3/exoplayer/ExoPlayer;

    .line 397
    .line 398
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast v1, Ll2/b1;

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
    iget p0, p0, Lxk0/w;->e:I

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
    invoke-static {v0, v1, p1, p0}, Lz10/a;->p(Landroidx/media3/exoplayer/ExoPlayer;Ll2/b1;Ll2/o;I)V

    .line 418
    .line 419
    .line 420
    goto/16 :goto_0

    .line 421
    .line 422
    :pswitch_e
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 423
    .line 424
    check-cast v0, Lxm0/b;

    .line 425
    .line 426
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v1, Lay0/a;

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
    const/4 p2, 0x1

    .line 438
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 439
    .line 440
    .line 441
    move-result p2

    .line 442
    iget p0, p0, Lxk0/w;->e:I

    .line 443
    .line 444
    invoke-static {v0, v1, p1, p2, p0}, Lym0/a;->e(Lxm0/b;Lay0/a;Ll2/o;II)V

    .line 445
    .line 446
    .line 447
    goto/16 :goto_0

    .line 448
    .line 449
    :pswitch_f
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast v0, Ljd/i;

    .line 452
    .line 453
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 454
    .line 455
    check-cast v1, Lay0/k;

    .line 456
    .line 457
    check-cast p1, Ll2/o;

    .line 458
    .line 459
    check-cast p2, Ljava/lang/Integer;

    .line 460
    .line 461
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 462
    .line 463
    .line 464
    iget p0, p0, Lxk0/w;->e:I

    .line 465
    .line 466
    or-int/lit8 p0, p0, 0x1

    .line 467
    .line 468
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 469
    .line 470
    .line 471
    move-result p0

    .line 472
    invoke-static {v0, v1, p1, p0}, Lyj/a;->h(Ljd/i;Lay0/k;Ll2/o;I)V

    .line 473
    .line 474
    .line 475
    goto/16 :goto_0

    .line 476
    .line 477
    :pswitch_10
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 478
    .line 479
    check-cast v0, Lid/e;

    .line 480
    .line 481
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast v1, Lay0/k;

    .line 484
    .line 485
    check-cast p1, Ll2/o;

    .line 486
    .line 487
    check-cast p2, Ljava/lang/Integer;

    .line 488
    .line 489
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 490
    .line 491
    .line 492
    iget p0, p0, Lxk0/w;->e:I

    .line 493
    .line 494
    or-int/lit8 p0, p0, 0x1

    .line 495
    .line 496
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 497
    .line 498
    .line 499
    move-result p0

    .line 500
    invoke-static {v0, v1, p1, p0}, Lyj/a;->a(Lid/e;Lay0/k;Ll2/o;I)V

    .line 501
    .line 502
    .line 503
    goto/16 :goto_0

    .line 504
    .line 505
    :pswitch_11
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 506
    .line 507
    check-cast v0, Ljava/lang/String;

    .line 508
    .line 509
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 510
    .line 511
    check-cast v1, Ljava/lang/Boolean;

    .line 512
    .line 513
    check-cast p1, Ll2/o;

    .line 514
    .line 515
    check-cast p2, Ljava/lang/Integer;

    .line 516
    .line 517
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 518
    .line 519
    .line 520
    iget p0, p0, Lxk0/w;->e:I

    .line 521
    .line 522
    or-int/lit8 p0, p0, 0x1

    .line 523
    .line 524
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 525
    .line 526
    .line 527
    move-result p0

    .line 528
    invoke-static {v0, v1, p1, p0}, Lxk0/e0;->a(Ljava/lang/String;Ljava/lang/Boolean;Ll2/o;I)V

    .line 529
    .line 530
    .line 531
    goto/16 :goto_0

    .line 532
    .line 533
    :pswitch_12
    iget-object v0, p0, Lxk0/w;->f:Ljava/lang/Object;

    .line 534
    .line 535
    check-cast v0, Lwk0/q0;

    .line 536
    .line 537
    iget-object v1, p0, Lxk0/w;->g:Ljava/lang/Object;

    .line 538
    .line 539
    check-cast v1, Lay0/a;

    .line 540
    .line 541
    check-cast p1, Ll2/o;

    .line 542
    .line 543
    check-cast p2, Ljava/lang/Integer;

    .line 544
    .line 545
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 546
    .line 547
    .line 548
    iget p0, p0, Lxk0/w;->e:I

    .line 549
    .line 550
    or-int/lit8 p0, p0, 0x1

    .line 551
    .line 552
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 553
    .line 554
    .line 555
    move-result p0

    .line 556
    invoke-static {v0, v1, p1, p0}, Lxk0/h;->C(Lwk0/q0;Lay0/a;Ll2/o;I)V

    .line 557
    .line 558
    .line 559
    goto/16 :goto_0

    .line 560
    .line 561
    :pswitch_data_0
    .packed-switch 0x0
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
