.class public final synthetic Lph/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lph/a;->d:I

    iput-object p3, p0, Lph/a;->e:Ljava/lang/Object;

    iput-object p4, p0, Lph/a;->g:Ljava/lang/Object;

    iput-object p5, p0, Lph/a;->h:Ljava/lang/Object;

    iput p1, p0, Lph/a;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/a;Lrh/s;I)V
    .locals 1

    .line 2
    const/4 v0, 0x3

    iput v0, p0, Lph/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lph/a;->g:Ljava/lang/Object;

    iput-object p2, p0, Lph/a;->e:Ljava/lang/Object;

    iput-object p3, p0, Lph/a;->h:Ljava/lang/Object;

    iput p4, p0, Lph/a;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lay0/a;II)V
    .locals 0

    .line 3
    iput p5, p0, Lph/a;->d:I

    iput-object p1, p0, Lph/a;->g:Ljava/lang/Object;

    iput-object p2, p0, Lph/a;->h:Ljava/lang/Object;

    iput-object p3, p0, Lph/a;->e:Ljava/lang/Object;

    iput p4, p0, Lph/a;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lq40/d;Lay0/a;Lay0/a;I)V
    .locals 1

    .line 4
    const/4 v0, 0x2

    iput v0, p0, Lph/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lph/a;->h:Ljava/lang/Object;

    iput-object p2, p0, Lph/a;->e:Ljava/lang/Object;

    iput-object p3, p0, Lph/a;->g:Ljava/lang/Object;

    iput p4, p0, Lph/a;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ls10/c0;Lx2/s;Lay0/a;II)V
    .locals 0

    .line 5
    const/16 p4, 0x8

    iput p4, p0, Lph/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lph/a;->g:Ljava/lang/Object;

    iput-object p2, p0, Lph/a;->h:Ljava/lang/Object;

    iput-object p3, p0, Lph/a;->e:Ljava/lang/Object;

    iput p5, p0, Lph/a;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lph/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luj/b0;

    .line 9
    .line 10
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lyj/b;

    .line 13
    .line 14
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lyj/b;

    .line 17
    .line 18
    check-cast p1, Ll2/o;

    .line 19
    .line 20
    check-cast p2, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    iget p0, p0, Lph/a;->f:I

    .line 26
    .line 27
    or-int/lit8 p0, p0, 0x1

    .line 28
    .line 29
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/b0;->F0(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Luj/b0;

    .line 42
    .line 43
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lpe/b;

    .line 46
    .line 47
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v2, Lay0/k;

    .line 50
    .line 51
    check-cast p1, Ll2/o;

    .line 52
    .line 53
    check-cast p2, Ljava/lang/Integer;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 56
    .line 57
    .line 58
    iget p0, p0, Lph/a;->f:I

    .line 59
    .line 60
    or-int/lit8 p0, p0, 0x1

    .line 61
    .line 62
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/b0;->d0(Lpe/b;Lay0/k;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_1
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v0, Luj/b0;

    .line 75
    .line 76
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v1, Lfd/d;

    .line 79
    .line 80
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v2, Lb6/f;

    .line 83
    .line 84
    check-cast p1, Ll2/o;

    .line 85
    .line 86
    check-cast p2, Ljava/lang/Integer;

    .line 87
    .line 88
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    iget p0, p0, Lph/a;->f:I

    .line 92
    .line 93
    or-int/lit8 p0, p0, 0x1

    .line 94
    .line 95
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/b0;->i(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_2
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v0, Luj/n;

    .line 108
    .line 109
    iget-object v1, p0, Lph/a;->h:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v1, Lpe/a;

    .line 112
    .line 113
    iget-object v2, p0, Lph/a;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v2, Lay0/a;

    .line 116
    .line 117
    check-cast p1, Ll2/o;

    .line 118
    .line 119
    check-cast p2, Ljava/lang/Integer;

    .line 120
    .line 121
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 122
    .line 123
    .line 124
    iget p0, p0, Lph/a;->f:I

    .line 125
    .line 126
    or-int/lit8 p0, p0, 0x1

    .line 127
    .line 128
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->Z(Lpe/a;Lay0/a;Ll2/o;I)V

    .line 133
    .line 134
    .line 135
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_3
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v0, Luj/n;

    .line 141
    .line 142
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v1, Lze/d;

    .line 145
    .line 146
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v2, Lay0/k;

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
    iget p0, p0, Lph/a;->f:I

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
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->R(Lze/d;Lay0/k;Ll2/o;I)V

    .line 166
    .line 167
    .line 168
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object p0

    .line 171
    :pswitch_4
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v0, Luj/n;

    .line 174
    .line 175
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v1, Lqe/a;

    .line 178
    .line 179
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v2, Lay0/k;

    .line 182
    .line 183
    check-cast p1, Ll2/o;

    .line 184
    .line 185
    check-cast p2, Ljava/lang/Integer;

    .line 186
    .line 187
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 188
    .line 189
    .line 190
    iget p0, p0, Lph/a;->f:I

    .line 191
    .line 192
    or-int/lit8 p0, p0, 0x1

    .line 193
    .line 194
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 195
    .line 196
    .line 197
    move-result p0

    .line 198
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->d(Lqe/a;Lay0/k;Ll2/o;I)V

    .line 199
    .line 200
    .line 201
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    return-object p0

    .line 204
    :pswitch_5
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v0, Luj/n;

    .line 207
    .line 208
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v1, Ldf/c;

    .line 211
    .line 212
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v2, Lay0/k;

    .line 215
    .line 216
    check-cast p1, Ll2/o;

    .line 217
    .line 218
    check-cast p2, Ljava/lang/Integer;

    .line 219
    .line 220
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 221
    .line 222
    .line 223
    iget p0, p0, Lph/a;->f:I

    .line 224
    .line 225
    or-int/lit8 p0, p0, 0x1

    .line 226
    .line 227
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->w(Ldf/c;Lay0/k;Ll2/o;I)V

    .line 232
    .line 233
    .line 234
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_6
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Luj/n;

    .line 240
    .line 241
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 242
    .line 243
    check-cast v1, Laf/d;

    .line 244
    .line 245
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 246
    .line 247
    check-cast v2, Lay0/k;

    .line 248
    .line 249
    check-cast p1, Ll2/o;

    .line 250
    .line 251
    check-cast p2, Ljava/lang/Integer;

    .line 252
    .line 253
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 254
    .line 255
    .line 256
    iget p0, p0, Lph/a;->f:I

    .line 257
    .line 258
    or-int/lit8 p0, p0, 0x1

    .line 259
    .line 260
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->H(Laf/d;Lay0/k;Ll2/o;I)V

    .line 265
    .line 266
    .line 267
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    return-object p0

    .line 270
    :pswitch_7
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast v0, Luj/n;

    .line 273
    .line 274
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v1, Lue/a;

    .line 277
    .line 278
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast v2, Lay0/k;

    .line 281
    .line 282
    check-cast p1, Ll2/o;

    .line 283
    .line 284
    check-cast p2, Ljava/lang/Integer;

    .line 285
    .line 286
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 287
    .line 288
    .line 289
    iget p0, p0, Lph/a;->f:I

    .line 290
    .line 291
    or-int/lit8 p0, p0, 0x1

    .line 292
    .line 293
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 294
    .line 295
    .line 296
    move-result p0

    .line 297
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->H0(Lue/a;Lay0/k;Ll2/o;I)V

    .line 298
    .line 299
    .line 300
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_8
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v0, Luj/n;

    .line 306
    .line 307
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 308
    .line 309
    check-cast v1, Lpe/b;

    .line 310
    .line 311
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v2, Lay0/k;

    .line 314
    .line 315
    check-cast p1, Ll2/o;

    .line 316
    .line 317
    check-cast p2, Ljava/lang/Integer;

    .line 318
    .line 319
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 320
    .line 321
    .line 322
    iget p0, p0, Lph/a;->f:I

    .line 323
    .line 324
    or-int/lit8 p0, p0, 0x1

    .line 325
    .line 326
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 327
    .line 328
    .line 329
    move-result p0

    .line 330
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->d0(Lpe/b;Lay0/k;Ll2/o;I)V

    .line 331
    .line 332
    .line 333
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 334
    .line 335
    return-object p0

    .line 336
    :pswitch_9
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 337
    .line 338
    check-cast v0, Luj/n;

    .line 339
    .line 340
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v1, Lef/a;

    .line 343
    .line 344
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v2, Lay0/k;

    .line 347
    .line 348
    check-cast p1, Ll2/o;

    .line 349
    .line 350
    check-cast p2, Ljava/lang/Integer;

    .line 351
    .line 352
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 353
    .line 354
    .line 355
    iget p0, p0, Lph/a;->f:I

    .line 356
    .line 357
    or-int/lit8 p0, p0, 0x1

    .line 358
    .line 359
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 360
    .line 361
    .line 362
    move-result p0

    .line 363
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/n;->n(Lef/a;Lay0/k;Ll2/o;I)V

    .line 364
    .line 365
    .line 366
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 367
    .line 368
    return-object p0

    .line 369
    :pswitch_a
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v0, Luj/f;

    .line 372
    .line 373
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 374
    .line 375
    check-cast v1, Lhc/a;

    .line 376
    .line 377
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v2, Lay0/k;

    .line 380
    .line 381
    check-cast p1, Ll2/o;

    .line 382
    .line 383
    check-cast p2, Ljava/lang/Integer;

    .line 384
    .line 385
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 386
    .line 387
    .line 388
    iget p0, p0, Lph/a;->f:I

    .line 389
    .line 390
    or-int/lit8 p0, p0, 0x1

    .line 391
    .line 392
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 393
    .line 394
    .line 395
    move-result p0

    .line 396
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/f;->s(Lhc/a;Lay0/k;Ll2/o;I)V

    .line 397
    .line 398
    .line 399
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 400
    .line 401
    return-object p0

    .line 402
    :pswitch_b
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v0, Luj/f;

    .line 405
    .line 406
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast v1, Llc/q;

    .line 409
    .line 410
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 411
    .line 412
    check-cast v2, Lay0/k;

    .line 413
    .line 414
    check-cast p1, Ll2/o;

    .line 415
    .line 416
    check-cast p2, Ljava/lang/Integer;

    .line 417
    .line 418
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 419
    .line 420
    .line 421
    iget p0, p0, Lph/a;->f:I

    .line 422
    .line 423
    or-int/lit8 p0, p0, 0x1

    .line 424
    .line 425
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 426
    .line 427
    .line 428
    move-result p0

    .line 429
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/f;->b(Llc/q;Lay0/k;Ll2/o;I)V

    .line 430
    .line 431
    .line 432
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 433
    .line 434
    return-object p0

    .line 435
    :pswitch_c
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v0, Luj/e;

    .line 438
    .line 439
    iget-object v1, p0, Lph/a;->h:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast v1, Llc/q;

    .line 442
    .line 443
    iget-object v2, p0, Lph/a;->e:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v2, Lay0/a;

    .line 446
    .line 447
    check-cast p1, Ll2/o;

    .line 448
    .line 449
    check-cast p2, Ljava/lang/Integer;

    .line 450
    .line 451
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 452
    .line 453
    .line 454
    iget p0, p0, Lph/a;->f:I

    .line 455
    .line 456
    or-int/lit8 p0, p0, 0x1

    .line 457
    .line 458
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 459
    .line 460
    .line 461
    move-result p0

    .line 462
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/e;->E0(Llc/q;Lay0/a;Ll2/o;I)V

    .line 463
    .line 464
    .line 465
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 466
    .line 467
    return-object p0

    .line 468
    :pswitch_d
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 469
    .line 470
    check-cast v0, Luj/d;

    .line 471
    .line 472
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 473
    .line 474
    check-cast v1, Lsd/d;

    .line 475
    .line 476
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 477
    .line 478
    check-cast v2, Lay0/k;

    .line 479
    .line 480
    check-cast p1, Ll2/o;

    .line 481
    .line 482
    check-cast p2, Ljava/lang/Integer;

    .line 483
    .line 484
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 485
    .line 486
    .line 487
    iget p0, p0, Lph/a;->f:I

    .line 488
    .line 489
    or-int/lit8 p0, p0, 0x1

    .line 490
    .line 491
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 492
    .line 493
    .line 494
    move-result p0

    .line 495
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/d;->g0(Lsd/d;Lay0/k;Ll2/o;I)V

    .line 496
    .line 497
    .line 498
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 499
    .line 500
    return-object p0

    .line 501
    :pswitch_e
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 502
    .line 503
    check-cast v0, Luj/c;

    .line 504
    .line 505
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 506
    .line 507
    check-cast v1, Lfd/d;

    .line 508
    .line 509
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 510
    .line 511
    check-cast v2, Lb6/f;

    .line 512
    .line 513
    check-cast p1, Ll2/o;

    .line 514
    .line 515
    check-cast p2, Ljava/lang/Integer;

    .line 516
    .line 517
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 518
    .line 519
    .line 520
    iget p0, p0, Lph/a;->f:I

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
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/c;->i(Lfd/d;Lb6/f;Ll2/o;I)V

    .line 529
    .line 530
    .line 531
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 532
    .line 533
    return-object p0

    .line 534
    :pswitch_f
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 535
    .line 536
    check-cast v0, Luj/b;

    .line 537
    .line 538
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 539
    .line 540
    check-cast v1, Lyj/b;

    .line 541
    .line 542
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 543
    .line 544
    check-cast v2, Lyj/b;

    .line 545
    .line 546
    check-cast p1, Ll2/o;

    .line 547
    .line 548
    check-cast p2, Ljava/lang/Integer;

    .line 549
    .line 550
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 551
    .line 552
    .line 553
    iget p0, p0, Lph/a;->f:I

    .line 554
    .line 555
    or-int/lit8 p0, p0, 0x1

    .line 556
    .line 557
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 558
    .line 559
    .line 560
    move-result p0

    .line 561
    invoke-virtual {v0, v1, v2, p1, p0}, Luj/b;->F0(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 562
    .line 563
    .line 564
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 565
    .line 566
    return-object p0

    .line 567
    :pswitch_10
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 568
    .line 569
    check-cast v0, Lu2/e;

    .line 570
    .line 571
    iget-object v1, p0, Lph/a;->h:Ljava/lang/Object;

    .line 572
    .line 573
    check-cast v1, Lt2/b;

    .line 574
    .line 575
    check-cast p1, Ll2/o;

    .line 576
    .line 577
    check-cast p2, Ljava/lang/Integer;

    .line 578
    .line 579
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 580
    .line 581
    .line 582
    iget p2, p0, Lph/a;->f:I

    .line 583
    .line 584
    or-int/lit8 p2, p2, 0x1

    .line 585
    .line 586
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 587
    .line 588
    .line 589
    move-result p2

    .line 590
    iget-object p0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 591
    .line 592
    invoke-virtual {v0, p0, v1, p1, p2}, Lu2/e;->b(Ljava/lang/Object;Lt2/b;Ll2/o;I)V

    .line 593
    .line 594
    .line 595
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 596
    .line 597
    return-object p0

    .line 598
    :pswitch_11
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 599
    .line 600
    move-object v1, v0

    .line 601
    check-cast v1, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 602
    .line 603
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 604
    .line 605
    move-object v2, v0

    .line 606
    check-cast v2, Ljava/lang/String;

    .line 607
    .line 608
    iget-object v0, p0, Lph/a;->h:Ljava/lang/Object;

    .line 609
    .line 610
    move-object v3, v0

    .line 611
    check-cast v3, Ljava/lang/String;

    .line 612
    .line 613
    move-object v5, p1

    .line 614
    check-cast v5, Ll2/o;

    .line 615
    .line 616
    check-cast p2, Ljava/lang/Integer;

    .line 617
    .line 618
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 619
    .line 620
    .line 621
    move-result v6

    .line 622
    iget v4, p0, Lph/a;->f:I

    .line 623
    .line 624
    invoke-static/range {v1 .. v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->f(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Ljava/lang/String;ILl2/o;I)Llx0/b0;

    .line 625
    .line 626
    .line 627
    move-result-object p0

    .line 628
    return-object p0

    .line 629
    :pswitch_12
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 630
    .line 631
    move-object v1, v0

    .line 632
    check-cast v1, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 633
    .line 634
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 635
    .line 636
    move-object v2, v0

    .line 637
    check-cast v2, Ljava/lang/String;

    .line 638
    .line 639
    iget-object v0, p0, Lph/a;->h:Ljava/lang/Object;

    .line 640
    .line 641
    move-object v3, v0

    .line 642
    check-cast v3, Lay0/k;

    .line 643
    .line 644
    move-object v5, p1

    .line 645
    check-cast v5, Ll2/o;

    .line 646
    .line 647
    check-cast p2, Ljava/lang/Integer;

    .line 648
    .line 649
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 650
    .line 651
    .line 652
    move-result v6

    .line 653
    iget v4, p0, Lph/a;->f:I

    .line 654
    .line 655
    invoke-static/range {v1 .. v6}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->C(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/k;ILl2/o;I)Llx0/b0;

    .line 656
    .line 657
    .line 658
    move-result-object p0

    .line 659
    return-object p0

    .line 660
    :pswitch_13
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 661
    .line 662
    check-cast v0, Lt2/b;

    .line 663
    .line 664
    check-cast p1, Ll2/o;

    .line 665
    .line 666
    check-cast p2, Ljava/lang/Integer;

    .line 667
    .line 668
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 669
    .line 670
    .line 671
    iget p2, p0, Lph/a;->f:I

    .line 672
    .line 673
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 674
    .line 675
    .line 676
    move-result p2

    .line 677
    or-int/lit8 p2, p2, 0x1

    .line 678
    .line 679
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 680
    .line 681
    iget-object p0, p0, Lph/a;->h:Ljava/lang/Object;

    .line 682
    .line 683
    invoke-virtual {v0, v1, p0, p1, p2}, Lt2/b;->c(Ljava/lang/Object;Ljava/lang/Object;Ll2/o;I)Ljava/lang/Object;

    .line 684
    .line 685
    .line 686
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 687
    .line 688
    return-object p0

    .line 689
    :pswitch_14
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 690
    .line 691
    move-object v1, v0

    .line 692
    check-cast v1, Ls10/c0;

    .line 693
    .line 694
    iget-object v0, p0, Lph/a;->h:Ljava/lang/Object;

    .line 695
    .line 696
    move-object v2, v0

    .line 697
    check-cast v2, Lx2/s;

    .line 698
    .line 699
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 700
    .line 701
    move-object v3, v0

    .line 702
    check-cast v3, Lay0/a;

    .line 703
    .line 704
    move-object v4, p1

    .line 705
    check-cast v4, Ll2/o;

    .line 706
    .line 707
    check-cast p2, Ljava/lang/Integer;

    .line 708
    .line 709
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 710
    .line 711
    .line 712
    const/4 p1, 0x1

    .line 713
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 714
    .line 715
    .line 716
    move-result v5

    .line 717
    iget v6, p0, Lph/a;->f:I

    .line 718
    .line 719
    invoke-static/range {v1 .. v6}, Lt10/a;->q(Ls10/c0;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 720
    .line 721
    .line 722
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 723
    .line 724
    return-object p0

    .line 725
    :pswitch_15
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 726
    .line 727
    check-cast v0, Ls10/b;

    .line 728
    .line 729
    iget-object v1, p0, Lph/a;->h:Ljava/lang/Object;

    .line 730
    .line 731
    check-cast v1, Lay0/k;

    .line 732
    .line 733
    iget-object v2, p0, Lph/a;->e:Ljava/lang/Object;

    .line 734
    .line 735
    check-cast v2, Lay0/a;

    .line 736
    .line 737
    check-cast p1, Ll2/o;

    .line 738
    .line 739
    check-cast p2, Ljava/lang/Integer;

    .line 740
    .line 741
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 742
    .line 743
    .line 744
    iget p0, p0, Lph/a;->f:I

    .line 745
    .line 746
    or-int/lit8 p0, p0, 0x1

    .line 747
    .line 748
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 749
    .line 750
    .line 751
    move-result p0

    .line 752
    invoke-static {v0, v1, v2, p1, p0}, Lt10/a;->v(Ls10/b;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 753
    .line 754
    .line 755
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 756
    .line 757
    return-object p0

    .line 758
    :pswitch_16
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 759
    .line 760
    check-cast v0, Lt1/k1;

    .line 761
    .line 762
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 763
    .line 764
    check-cast v1, [Ljava/lang/Object;

    .line 765
    .line 766
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 767
    .line 768
    check-cast v2, Lay0/k;

    .line 769
    .line 770
    check-cast p1, Ll2/o;

    .line 771
    .line 772
    check-cast p2, Ljava/lang/Integer;

    .line 773
    .line 774
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 775
    .line 776
    .line 777
    iget p0, p0, Lph/a;->f:I

    .line 778
    .line 779
    or-int/lit8 p0, p0, 0x1

    .line 780
    .line 781
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 782
    .line 783
    .line 784
    move-result p0

    .line 785
    invoke-virtual {v0, v1, v2, p1, p0}, Lt1/k1;->b([Ljava/lang/Object;Lay0/k;Ll2/o;I)V

    .line 786
    .line 787
    .line 788
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 789
    .line 790
    return-object p0

    .line 791
    :pswitch_17
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 792
    .line 793
    check-cast v0, Lay0/k;

    .line 794
    .line 795
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 796
    .line 797
    check-cast v1, Ljava/lang/String;

    .line 798
    .line 799
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 800
    .line 801
    check-cast v2, Lx2/s;

    .line 802
    .line 803
    check-cast p1, Ll2/o;

    .line 804
    .line 805
    check-cast p2, Ljava/lang/Integer;

    .line 806
    .line 807
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 808
    .line 809
    .line 810
    iget p0, p0, Lph/a;->f:I

    .line 811
    .line 812
    or-int/lit8 p0, p0, 0x1

    .line 813
    .line 814
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 815
    .line 816
    .line 817
    move-result p0

    .line 818
    invoke-static {v0, v1, v2, p1, p0}, Ls80/a;->i(Lay0/k;Ljava/lang/String;Lx2/s;Ll2/o;I)V

    .line 819
    .line 820
    .line 821
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 822
    .line 823
    return-object p0

    .line 824
    :pswitch_18
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v0, Ljava/util/List;

    .line 827
    .line 828
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 829
    .line 830
    check-cast v1, Lay0/k;

    .line 831
    .line 832
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 833
    .line 834
    check-cast v2, Lay0/k;

    .line 835
    .line 836
    check-cast p1, Ll2/o;

    .line 837
    .line 838
    check-cast p2, Ljava/lang/Integer;

    .line 839
    .line 840
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 841
    .line 842
    .line 843
    iget p0, p0, Lph/a;->f:I

    .line 844
    .line 845
    or-int/lit8 p0, p0, 0x1

    .line 846
    .line 847
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 848
    .line 849
    .line 850
    move-result p0

    .line 851
    invoke-static {v0, v1, v2, p1, p0}, Ls60/j;->j(Ljava/util/List;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 852
    .line 853
    .line 854
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 855
    .line 856
    return-object p0

    .line 857
    :pswitch_19
    iget-object v0, p0, Lph/a;->g:Ljava/lang/Object;

    .line 858
    .line 859
    check-cast v0, Lay0/k;

    .line 860
    .line 861
    iget-object v1, p0, Lph/a;->e:Ljava/lang/Object;

    .line 862
    .line 863
    check-cast v1, Lay0/a;

    .line 864
    .line 865
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 866
    .line 867
    check-cast v2, Lrh/s;

    .line 868
    .line 869
    check-cast p1, Ll2/o;

    .line 870
    .line 871
    check-cast p2, Ljava/lang/Integer;

    .line 872
    .line 873
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 874
    .line 875
    .line 876
    iget p0, p0, Lph/a;->f:I

    .line 877
    .line 878
    or-int/lit8 p0, p0, 0x1

    .line 879
    .line 880
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 881
    .line 882
    .line 883
    move-result p0

    .line 884
    invoke-static {v0, v1, v2, p1, p0}, Lkp/f0;->a(Lay0/k;Lay0/a;Lrh/s;Ll2/o;I)V

    .line 885
    .line 886
    .line 887
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 888
    .line 889
    return-object p0

    .line 890
    :pswitch_1a
    iget-object v0, p0, Lph/a;->h:Ljava/lang/Object;

    .line 891
    .line 892
    check-cast v0, Lq40/d;

    .line 893
    .line 894
    iget-object v1, p0, Lph/a;->e:Ljava/lang/Object;

    .line 895
    .line 896
    check-cast v1, Lay0/a;

    .line 897
    .line 898
    iget-object v2, p0, Lph/a;->g:Ljava/lang/Object;

    .line 899
    .line 900
    check-cast v2, Lay0/a;

    .line 901
    .line 902
    check-cast p1, Ll2/o;

    .line 903
    .line 904
    check-cast p2, Ljava/lang/Integer;

    .line 905
    .line 906
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 907
    .line 908
    .line 909
    iget p0, p0, Lph/a;->f:I

    .line 910
    .line 911
    or-int/lit8 p0, p0, 0x1

    .line 912
    .line 913
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 914
    .line 915
    .line 916
    move-result p0

    .line 917
    invoke-static {v0, v1, v2, p1, p0}, Lr40/a;->v(Lq40/d;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 918
    .line 919
    .line 920
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 921
    .line 922
    return-object p0

    .line 923
    :pswitch_1b
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 924
    .line 925
    check-cast v0, Lay0/a;

    .line 926
    .line 927
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 928
    .line 929
    check-cast v1, Llh/g;

    .line 930
    .line 931
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 932
    .line 933
    check-cast v2, Lay0/k;

    .line 934
    .line 935
    check-cast p1, Ll2/o;

    .line 936
    .line 937
    check-cast p2, Ljava/lang/Integer;

    .line 938
    .line 939
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 940
    .line 941
    .line 942
    iget p0, p0, Lph/a;->f:I

    .line 943
    .line 944
    or-int/lit8 p0, p0, 0x1

    .line 945
    .line 946
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 947
    .line 948
    .line 949
    move-result p0

    .line 950
    invoke-static {v0, v1, v2, p1, p0}, Ljp/qf;->a(Lay0/a;Llh/g;Lay0/k;Ll2/o;I)V

    .line 951
    .line 952
    .line 953
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 954
    .line 955
    return-object p0

    .line 956
    :pswitch_1c
    iget-object v0, p0, Lph/a;->e:Ljava/lang/Object;

    .line 957
    .line 958
    check-cast v0, Lay0/a;

    .line 959
    .line 960
    iget-object v1, p0, Lph/a;->g:Ljava/lang/Object;

    .line 961
    .line 962
    check-cast v1, Lay0/a;

    .line 963
    .line 964
    iget-object v2, p0, Lph/a;->h:Ljava/lang/Object;

    .line 965
    .line 966
    check-cast v2, Lph/g;

    .line 967
    .line 968
    check-cast p1, Ll2/o;

    .line 969
    .line 970
    check-cast p2, Ljava/lang/Integer;

    .line 971
    .line 972
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 973
    .line 974
    .line 975
    iget p0, p0, Lph/a;->f:I

    .line 976
    .line 977
    or-int/lit8 p0, p0, 0x1

    .line 978
    .line 979
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 980
    .line 981
    .line 982
    move-result p0

    .line 983
    invoke-static {v0, v1, v2, p1, p0}, Ljp/od;->a(Lay0/a;Lay0/a;Lph/g;Ll2/o;I)V

    .line 984
    .line 985
    .line 986
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 987
    .line 988
    return-object p0

    .line 989
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
