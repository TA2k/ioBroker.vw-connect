.class public final synthetic Lqv0/f;
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
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lqv0/f;->d:I

    iput-object p3, p0, Lqv0/f;->e:Ljava/lang/Object;

    iput-object p4, p0, Lqv0/f;->f:Ljava/lang/Object;

    iput-object p5, p0, Lqv0/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Llx0/e;)V
    .locals 0

    .line 2
    iput p1, p0, Lqv0/f;->d:I

    iput-object p2, p0, Lqv0/f;->e:Ljava/lang/Object;

    iput-object p4, p0, Lqv0/f;->f:Ljava/lang/Object;

    iput-object p3, p0, Lqv0/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/k;)V
    .locals 1

    .line 3
    const/16 v0, 0xe

    iput v0, p0, Lqv0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lqv0/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lqv0/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lqv0/f;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Lay0/a;II)V
    .locals 0

    .line 4
    iput p5, p0, Lqv0/f;->d:I

    iput-object p1, p0, Lqv0/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lqv0/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lqv0/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ly1/i;Lug/a;Ljava/lang/String;I)V
    .locals 0

    .line 5
    const/16 p4, 0xc

    iput p4, p0, Lqv0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lqv0/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lqv0/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lqv0/f;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lqv0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luj/b0;

    .line 9
    .line 10
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lmd/b;

    .line 13
    .line 14
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lay0/k;

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
    const/4 p2, 0x1

    .line 26
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/b0;->t0(Lmd/b;Lay0/k;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Luj/b0;

    .line 39
    .line 40
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Ldf/c;

    .line 43
    .line 44
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lay0/k;

    .line 47
    .line 48
    check-cast p1, Ll2/o;

    .line 49
    .line 50
    check-cast p2, Ljava/lang/Integer;

    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const/4 p2, 0x1

    .line 56
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/b0;->w(Ldf/c;Lay0/k;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_1
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Luj/s;

    .line 69
    .line 70
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v1, Lig/e;

    .line 73
    .line 74
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lay0/k;

    .line 77
    .line 78
    check-cast p1, Ll2/o;

    .line 79
    .line 80
    check-cast p2, Ljava/lang/Integer;

    .line 81
    .line 82
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    const/4 p2, 0x1

    .line 86
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/s;->G(Lig/e;Lay0/k;Ll2/o;I)V

    .line 91
    .line 92
    .line 93
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_2
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Luj/s;

    .line 99
    .line 100
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v1, Lhg/m;

    .line 103
    .line 104
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p0, Lay0/k;

    .line 107
    .line 108
    check-cast p1, Ll2/o;

    .line 109
    .line 110
    check-cast p2, Ljava/lang/Integer;

    .line 111
    .line 112
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    const/4 p2, 0x1

    .line 116
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/s;->e0(Lhg/m;Lay0/k;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_3
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v0, Luj/r;

    .line 129
    .line 130
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v1, Llc/q;

    .line 133
    .line 134
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast p0, Lay0/k;

    .line 137
    .line 138
    check-cast p1, Ll2/o;

    .line 139
    .line 140
    check-cast p2, Ljava/lang/Integer;

    .line 141
    .line 142
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    const/16 p2, 0x9

    .line 146
    .line 147
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 148
    .line 149
    .line 150
    move-result p2

    .line 151
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/r;->V(Llc/q;Lay0/k;Ll2/o;I)V

    .line 152
    .line 153
    .line 154
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    return-object p0

    .line 157
    :pswitch_4
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v0, Luj/r;

    .line 160
    .line 161
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v1, Lmd/b;

    .line 164
    .line 165
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p0, Lay0/k;

    .line 168
    .line 169
    check-cast p1, Ll2/o;

    .line 170
    .line 171
    check-cast p2, Ljava/lang/Integer;

    .line 172
    .line 173
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    const/4 p2, 0x1

    .line 177
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/r;->t0(Lmd/b;Lay0/k;Ll2/o;I)V

    .line 182
    .line 183
    .line 184
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    return-object p0

    .line 187
    :pswitch_5
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v0, Luj/o;

    .line 190
    .line 191
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 192
    .line 193
    check-cast v1, Llc/q;

    .line 194
    .line 195
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast p0, Lay0/k;

    .line 198
    .line 199
    check-cast p1, Ll2/o;

    .line 200
    .line 201
    check-cast p2, Ljava/lang/Integer;

    .line 202
    .line 203
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    const/16 p2, 0x9

    .line 207
    .line 208
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/o;->N(Llc/q;Lay0/k;Ll2/o;I)V

    .line 213
    .line 214
    .line 215
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_6
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v0, Luj/n;

    .line 221
    .line 222
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast v1, Lne/i;

    .line 225
    .line 226
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p0, Lay0/k;

    .line 229
    .line 230
    check-cast p1, Ll2/o;

    .line 231
    .line 232
    check-cast p2, Ljava/lang/Integer;

    .line 233
    .line 234
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    const/4 p2, 0x1

    .line 238
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 239
    .line 240
    .line 241
    move-result p2

    .line 242
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/n;->p(Lne/i;Lay0/k;Ll2/o;I)V

    .line 243
    .line 244
    .line 245
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 246
    .line 247
    return-object p0

    .line 248
    :pswitch_7
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v0, Luj/n;

    .line 251
    .line 252
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v1, Lcf/d;

    .line 255
    .line 256
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p0, Lay0/k;

    .line 259
    .line 260
    check-cast p1, Ll2/o;

    .line 261
    .line 262
    check-cast p2, Ljava/lang/Integer;

    .line 263
    .line 264
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 265
    .line 266
    .line 267
    const/4 p2, 0x1

    .line 268
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 269
    .line 270
    .line 271
    move-result p2

    .line 272
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/n;->x(Lcf/d;Lay0/k;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 276
    .line 277
    return-object p0

    .line 278
    :pswitch_8
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast v0, Luj/n;

    .line 281
    .line 282
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v1, Lwe/d;

    .line 285
    .line 286
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast p0, Lay0/k;

    .line 289
    .line 290
    check-cast p1, Ll2/o;

    .line 291
    .line 292
    check-cast p2, Ljava/lang/Integer;

    .line 293
    .line 294
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    const/4 p2, 0x1

    .line 298
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 299
    .line 300
    .line 301
    move-result p2

    .line 302
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/n;->q(Lwe/d;Lay0/k;Ll2/o;I)V

    .line 303
    .line 304
    .line 305
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 306
    .line 307
    return-object p0

    .line 308
    :pswitch_9
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 309
    .line 310
    check-cast v0, Luj/n;

    .line 311
    .line 312
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 313
    .line 314
    check-cast v1, Lre/i;

    .line 315
    .line 316
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast p0, Lay0/k;

    .line 319
    .line 320
    check-cast p1, Ll2/o;

    .line 321
    .line 322
    check-cast p2, Ljava/lang/Integer;

    .line 323
    .line 324
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 325
    .line 326
    .line 327
    const/4 p2, 0x1

    .line 328
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 329
    .line 330
    .line 331
    move-result p2

    .line 332
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/n;->M(Lre/i;Lay0/k;Ll2/o;I)V

    .line 333
    .line 334
    .line 335
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 336
    .line 337
    return-object p0

    .line 338
    :pswitch_a
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v0, Luj/l;

    .line 341
    .line 342
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v1, Llc/q;

    .line 345
    .line 346
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast p0, Lay0/k;

    .line 349
    .line 350
    check-cast p1, Ll2/o;

    .line 351
    .line 352
    check-cast p2, Ljava/lang/Integer;

    .line 353
    .line 354
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 355
    .line 356
    .line 357
    const/16 p2, 0x9

    .line 358
    .line 359
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 360
    .line 361
    .line 362
    move-result p2

    .line 363
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/l;->t(Llc/q;Lay0/k;Ll2/o;I)V

    .line 364
    .line 365
    .line 366
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 367
    .line 368
    return-object p0

    .line 369
    :pswitch_b
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v0, Luj/g;

    .line 372
    .line 373
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 374
    .line 375
    check-cast v1, Llc/q;

    .line 376
    .line 377
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast p0, Lay0/k;

    .line 380
    .line 381
    check-cast p1, Ll2/o;

    .line 382
    .line 383
    check-cast p2, Ljava/lang/Integer;

    .line 384
    .line 385
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 386
    .line 387
    .line 388
    const/16 p2, 0x9

    .line 389
    .line 390
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 391
    .line 392
    .line 393
    move-result p2

    .line 394
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/g;->u0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 395
    .line 396
    .line 397
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 398
    .line 399
    return-object p0

    .line 400
    :pswitch_c
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast v0, Luj/d;

    .line 403
    .line 404
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 405
    .line 406
    check-cast v1, Llc/q;

    .line 407
    .line 408
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 409
    .line 410
    check-cast p0, Lay0/k;

    .line 411
    .line 412
    check-cast p1, Ll2/o;

    .line 413
    .line 414
    check-cast p2, Ljava/lang/Integer;

    .line 415
    .line 416
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    const/16 p2, 0x9

    .line 420
    .line 421
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 422
    .line 423
    .line 424
    move-result p2

    .line 425
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/d;->c(Llc/q;Lay0/k;Ll2/o;I)V

    .line 426
    .line 427
    .line 428
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 429
    .line 430
    return-object p0

    .line 431
    :pswitch_d
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 432
    .line 433
    check-cast v0, Luj/b;

    .line 434
    .line 435
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v1, Lwc/f;

    .line 438
    .line 439
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast p0, Lay0/k;

    .line 442
    .line 443
    check-cast p1, Ll2/o;

    .line 444
    .line 445
    check-cast p2, Ljava/lang/Integer;

    .line 446
    .line 447
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 448
    .line 449
    .line 450
    const/4 p2, 0x1

    .line 451
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 452
    .line 453
    .line 454
    move-result p2

    .line 455
    invoke-virtual {v0, p2, p0, p1, v1}, Luj/b;->h0(ILay0/k;Ll2/o;Lwc/f;)V

    .line 456
    .line 457
    .line 458
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 459
    .line 460
    return-object p0

    .line 461
    :pswitch_e
    iget-object v0, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 462
    .line 463
    check-cast v0, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 464
    .line 465
    iget-object v1, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast v1, Ljava/lang/String;

    .line 468
    .line 469
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 470
    .line 471
    check-cast p0, Lay0/k;

    .line 472
    .line 473
    check-cast p1, Ll2/o;

    .line 474
    .line 475
    check-cast p2, Ljava/lang/Integer;

    .line 476
    .line 477
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 478
    .line 479
    .line 480
    move-result p2

    .line 481
    invoke-static {v0, v1, p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->D(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Ljava/lang/String;Lay0/k;Ll2/o;I)Llx0/b0;

    .line 482
    .line 483
    .line 484
    move-result-object p0

    .line 485
    return-object p0

    .line 486
    :pswitch_f
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v0, Lay0/k;

    .line 489
    .line 490
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 491
    .line 492
    check-cast v1, Lth/g;

    .line 493
    .line 494
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 495
    .line 496
    check-cast p0, Lay0/k;

    .line 497
    .line 498
    check-cast p1, Ll2/o;

    .line 499
    .line 500
    check-cast p2, Ljava/lang/Integer;

    .line 501
    .line 502
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 503
    .line 504
    .line 505
    const/4 p2, 0x1

    .line 506
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 507
    .line 508
    .line 509
    move-result p2

    .line 510
    invoke-static {v0, v1, p0, p1, p2}, Lkp/aa;->a(Lay0/k;Lth/g;Lay0/k;Ll2/o;I)V

    .line 511
    .line 512
    .line 513
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 514
    .line 515
    return-object p0

    .line 516
    :pswitch_10
    iget-object v0, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast v0, Ly1/i;

    .line 519
    .line 520
    iget-object v1, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v1, Lug/a;

    .line 523
    .line 524
    iget-object p0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 525
    .line 526
    check-cast p0, Ljava/lang/String;

    .line 527
    .line 528
    check-cast p1, Ll2/o;

    .line 529
    .line 530
    check-cast p2, Ljava/lang/Integer;

    .line 531
    .line 532
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 533
    .line 534
    .line 535
    const/4 p2, 0x1

    .line 536
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 537
    .line 538
    .line 539
    move-result p2

    .line 540
    invoke-static {v0, v1, p0, p1, p2}, Lkp/z9;->a(Ly1/i;Lug/a;Ljava/lang/String;Ll2/o;I)V

    .line 541
    .line 542
    .line 543
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 544
    .line 545
    return-object p0

    .line 546
    :pswitch_11
    iget-object v0, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 547
    .line 548
    check-cast v0, Luf/p;

    .line 549
    .line 550
    iget-object v1, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 551
    .line 552
    check-cast v1, Ljava/lang/String;

    .line 553
    .line 554
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 555
    .line 556
    check-cast p0, Lyj/b;

    .line 557
    .line 558
    check-cast p1, Ll2/o;

    .line 559
    .line 560
    check-cast p2, Ljava/lang/Integer;

    .line 561
    .line 562
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 563
    .line 564
    .line 565
    const/4 p2, 0x1

    .line 566
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 567
    .line 568
    .line 569
    move-result p2

    .line 570
    invoke-static {v0, v1, p0, p1, p2}, Lkp/y9;->a(Luf/p;Ljava/lang/String;Lyj/b;Ll2/o;I)V

    .line 571
    .line 572
    .line 573
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 574
    .line 575
    return-object p0

    .line 576
    :pswitch_12
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 577
    .line 578
    check-cast v0, Lsa0/j;

    .line 579
    .line 580
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 581
    .line 582
    check-cast v1, Lay0/k;

    .line 583
    .line 584
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 585
    .line 586
    check-cast p0, Lay0/a;

    .line 587
    .line 588
    check-cast p1, Ll2/o;

    .line 589
    .line 590
    check-cast p2, Ljava/lang/Integer;

    .line 591
    .line 592
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 593
    .line 594
    .line 595
    const/4 p2, 0x1

    .line 596
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 597
    .line 598
    .line 599
    move-result p2

    .line 600
    invoke-static {v0, v1, p0, p1, p2}, Lkp/u9;->c(Lsa0/j;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 601
    .line 602
    .line 603
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 604
    .line 605
    return-object p0

    .line 606
    :pswitch_13
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast v0, Lx2/s;

    .line 609
    .line 610
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 611
    .line 612
    check-cast v1, Le2/w0;

    .line 613
    .line 614
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 615
    .line 616
    check-cast p0, Lt2/b;

    .line 617
    .line 618
    check-cast p1, Ll2/o;

    .line 619
    .line 620
    check-cast p2, Ljava/lang/Integer;

    .line 621
    .line 622
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 623
    .line 624
    .line 625
    const/16 p2, 0x181

    .line 626
    .line 627
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 628
    .line 629
    .line 630
    move-result p2

    .line 631
    invoke-static {v0, v1, p0, p1, p2}, Lt1/l0;->h(Lx2/s;Le2/w0;Lt2/b;Ll2/o;I)V

    .line 632
    .line 633
    .line 634
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 635
    .line 636
    return-object p0

    .line 637
    :pswitch_14
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 638
    .line 639
    check-cast v0, Lx2/s;

    .line 640
    .line 641
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 642
    .line 643
    check-cast v1, Lw0/g;

    .line 644
    .line 645
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 646
    .line 647
    check-cast p0, Lay0/k;

    .line 648
    .line 649
    check-cast p1, Ll2/o;

    .line 650
    .line 651
    check-cast p2, Ljava/lang/Integer;

    .line 652
    .line 653
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 654
    .line 655
    .line 656
    const/4 p2, 0x7

    .line 657
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 658
    .line 659
    .line 660
    move-result p2

    .line 661
    invoke-static {v0, v1, p0, p1, p2}, Lkp/s7;->b(Lx2/s;Lw0/g;Lay0/k;Ll2/o;I)V

    .line 662
    .line 663
    .line 664
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 665
    .line 666
    return-object p0

    .line 667
    :pswitch_15
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 668
    .line 669
    check-cast v0, Lrb/b;

    .line 670
    .line 671
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 672
    .line 673
    check-cast v1, Lb0/r;

    .line 674
    .line 675
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 676
    .line 677
    check-cast p0, Ll2/b1;

    .line 678
    .line 679
    check-cast p1, Ll2/o;

    .line 680
    .line 681
    check-cast p2, Ljava/lang/Integer;

    .line 682
    .line 683
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 684
    .line 685
    .line 686
    const/4 p2, 0x1

    .line 687
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 688
    .line 689
    .line 690
    move-result p2

    .line 691
    invoke-static {v0, v1, p0, p1, p2}, Lkp/s7;->a(Lrb/b;Lb0/r;Ll2/b1;Ll2/o;I)V

    .line 692
    .line 693
    .line 694
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 695
    .line 696
    return-object p0

    .line 697
    :pswitch_16
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 698
    .line 699
    check-cast v0, Lay0/a;

    .line 700
    .line 701
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 702
    .line 703
    check-cast v1, Lay0/a;

    .line 704
    .line 705
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 706
    .line 707
    check-cast p0, Lr60/z;

    .line 708
    .line 709
    check-cast p1, Ll2/o;

    .line 710
    .line 711
    check-cast p2, Ljava/lang/Integer;

    .line 712
    .line 713
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 714
    .line 715
    .line 716
    move-result p2

    .line 717
    and-int/lit8 v2, p2, 0x3

    .line 718
    .line 719
    const/4 v3, 0x2

    .line 720
    const/4 v4, 0x1

    .line 721
    if-eq v2, v3, :cond_0

    .line 722
    .line 723
    move v2, v4

    .line 724
    goto :goto_0

    .line 725
    :cond_0
    const/4 v2, 0x0

    .line 726
    :goto_0
    and-int/2addr p2, v4

    .line 727
    move-object v7, p1

    .line 728
    check-cast v7, Ll2/t;

    .line 729
    .line 730
    invoke-virtual {v7, p2, v2}, Ll2/t;->O(IZ)Z

    .line 731
    .line 732
    .line 733
    move-result p1

    .line 734
    if-eqz p1, :cond_1

    .line 735
    .line 736
    new-instance p1, Li40/n2;

    .line 737
    .line 738
    const/16 p2, 0x17

    .line 739
    .line 740
    invoke-direct {p1, p2, v0, v1, p0}, Li40/n2;-><init>(ILay0/a;Lay0/a;Lql0/h;)V

    .line 741
    .line 742
    .line 743
    const p0, -0x2dc734d9

    .line 744
    .line 745
    .line 746
    invoke-static {p0, v7, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 747
    .line 748
    .line 749
    move-result-object v6

    .line 750
    const/16 v8, 0x180

    .line 751
    .line 752
    const/4 v9, 0x3

    .line 753
    const/4 v3, 0x0

    .line 754
    const-wide/16 v4, 0x0

    .line 755
    .line 756
    invoke-static/range {v3 .. v9}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 757
    .line 758
    .line 759
    goto :goto_1

    .line 760
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 761
    .line 762
    .line 763
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 764
    .line 765
    return-object p0

    .line 766
    :pswitch_17
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 767
    .line 768
    check-cast v0, Lay0/a;

    .line 769
    .line 770
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 771
    .line 772
    check-cast v1, Lay0/a;

    .line 773
    .line 774
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 775
    .line 776
    check-cast p0, Lr60/i;

    .line 777
    .line 778
    check-cast p1, Ll2/o;

    .line 779
    .line 780
    check-cast p2, Ljava/lang/Integer;

    .line 781
    .line 782
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 783
    .line 784
    .line 785
    move-result p2

    .line 786
    and-int/lit8 v2, p2, 0x3

    .line 787
    .line 788
    const/4 v3, 0x2

    .line 789
    const/4 v4, 0x1

    .line 790
    if-eq v2, v3, :cond_2

    .line 791
    .line 792
    move v2, v4

    .line 793
    goto :goto_2

    .line 794
    :cond_2
    const/4 v2, 0x0

    .line 795
    :goto_2
    and-int/2addr p2, v4

    .line 796
    move-object v7, p1

    .line 797
    check-cast v7, Ll2/t;

    .line 798
    .line 799
    invoke-virtual {v7, p2, v2}, Ll2/t;->O(IZ)Z

    .line 800
    .line 801
    .line 802
    move-result p1

    .line 803
    if-eqz p1, :cond_3

    .line 804
    .line 805
    new-instance p1, Li40/n2;

    .line 806
    .line 807
    const/16 p2, 0x15

    .line 808
    .line 809
    invoke-direct {p1, p2, v0, v1, p0}, Li40/n2;-><init>(ILay0/a;Lay0/a;Lql0/h;)V

    .line 810
    .line 811
    .line 812
    const p0, -0xa8ae315

    .line 813
    .line 814
    .line 815
    invoke-static {p0, v7, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 816
    .line 817
    .line 818
    move-result-object v6

    .line 819
    const/16 v8, 0x180

    .line 820
    .line 821
    const/4 v9, 0x3

    .line 822
    const/4 v3, 0x0

    .line 823
    const-wide/16 v4, 0x0

    .line 824
    .line 825
    invoke-static/range {v3 .. v9}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 826
    .line 827
    .line 828
    goto :goto_3

    .line 829
    :cond_3
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 830
    .line 831
    .line 832
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 833
    .line 834
    return-object p0

    .line 835
    :pswitch_18
    iget-object v0, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 836
    .line 837
    check-cast v0, Lr60/b;

    .line 838
    .line 839
    iget-object v1, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 840
    .line 841
    check-cast v1, Ljava/lang/String;

    .line 842
    .line 843
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 844
    .line 845
    check-cast p0, Lay0/a;

    .line 846
    .line 847
    check-cast p1, Ll2/o;

    .line 848
    .line 849
    check-cast p2, Ljava/lang/Integer;

    .line 850
    .line 851
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 852
    .line 853
    .line 854
    const/4 p2, 0x1

    .line 855
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 856
    .line 857
    .line 858
    move-result p2

    .line 859
    invoke-static {v0, v1, p0, p1, p2}, Ls60/j;->e(Lr60/b;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 860
    .line 861
    .line 862
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 863
    .line 864
    return-object p0

    .line 865
    :pswitch_19
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 866
    .line 867
    check-cast v0, Lay0/k;

    .line 868
    .line 869
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 870
    .line 871
    check-cast v1, Lqg/k;

    .line 872
    .line 873
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 874
    .line 875
    check-cast p0, Lay0/a;

    .line 876
    .line 877
    check-cast p1, Ll2/o;

    .line 878
    .line 879
    check-cast p2, Ljava/lang/Integer;

    .line 880
    .line 881
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 882
    .line 883
    .line 884
    const/16 p2, 0x1c1

    .line 885
    .line 886
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 887
    .line 888
    .line 889
    move-result p2

    .line 890
    invoke-static {v0, v1, p0, p1, p2}, Lrk/a;->a(Lay0/k;Lqg/k;Lay0/a;Ll2/o;I)V

    .line 891
    .line 892
    .line 893
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 894
    .line 895
    return-object p0

    .line 896
    :pswitch_1a
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 897
    .line 898
    check-cast v0, Ljava/lang/String;

    .line 899
    .line 900
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 901
    .line 902
    check-cast v1, Luf/n;

    .line 903
    .line 904
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 905
    .line 906
    check-cast p0, Lyj/b;

    .line 907
    .line 908
    check-cast p1, Ll2/o;

    .line 909
    .line 910
    check-cast p2, Ljava/lang/Integer;

    .line 911
    .line 912
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 913
    .line 914
    .line 915
    const/4 p2, 0x1

    .line 916
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 917
    .line 918
    .line 919
    move-result p2

    .line 920
    invoke-static {v0, v1, p0, p1, p2}, Lkp/c0;->a(Ljava/lang/String;Luf/n;Lyj/b;Ll2/o;I)V

    .line 921
    .line 922
    .line 923
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 924
    .line 925
    return-object p0

    .line 926
    :pswitch_1b
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 927
    .line 928
    check-cast v0, Lq40/p;

    .line 929
    .line 930
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 931
    .line 932
    check-cast v1, Lay0/k;

    .line 933
    .line 934
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 935
    .line 936
    check-cast p0, Lay0/a;

    .line 937
    .line 938
    check-cast p1, Ll2/o;

    .line 939
    .line 940
    check-cast p2, Ljava/lang/Integer;

    .line 941
    .line 942
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 943
    .line 944
    .line 945
    move-result p2

    .line 946
    and-int/lit8 v2, p2, 0x3

    .line 947
    .line 948
    const/4 v3, 0x2

    .line 949
    const/4 v4, 0x1

    .line 950
    if-eq v2, v3, :cond_4

    .line 951
    .line 952
    move v2, v4

    .line 953
    goto :goto_4

    .line 954
    :cond_4
    const/4 v2, 0x0

    .line 955
    :goto_4
    and-int/2addr p2, v4

    .line 956
    move-object v7, p1

    .line 957
    check-cast v7, Ll2/t;

    .line 958
    .line 959
    invoke-virtual {v7, p2, v2}, Ll2/t;->O(IZ)Z

    .line 960
    .line 961
    .line 962
    move-result p1

    .line 963
    if-eqz p1, :cond_5

    .line 964
    .line 965
    new-instance p1, Li40/n2;

    .line 966
    .line 967
    const/16 p2, 0x13

    .line 968
    .line 969
    invoke-direct {p1, v0, v1, p0, p2}, Li40/n2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 970
    .line 971
    .line 972
    const p0, 0x576e00a2

    .line 973
    .line 974
    .line 975
    invoke-static {p0, v7, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 976
    .line 977
    .line 978
    move-result-object v6

    .line 979
    const/16 v8, 0x180

    .line 980
    .line 981
    const/4 v9, 0x3

    .line 982
    const/4 v3, 0x0

    .line 983
    const-wide/16 v4, 0x0

    .line 984
    .line 985
    invoke-static/range {v3 .. v9}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 986
    .line 987
    .line 988
    goto :goto_5

    .line 989
    :cond_5
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 990
    .line 991
    .line 992
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 993
    .line 994
    return-object p0

    .line 995
    :pswitch_1c
    iget-object v0, p0, Lqv0/f;->e:Ljava/lang/Object;

    .line 996
    .line 997
    check-cast v0, Ljava/lang/String;

    .line 998
    .line 999
    iget-object v1, p0, Lqv0/f;->f:Ljava/lang/Object;

    .line 1000
    .line 1001
    check-cast v1, Ljava/lang/String;

    .line 1002
    .line 1003
    iget-object p0, p0, Lqv0/f;->g:Ljava/lang/Object;

    .line 1004
    .line 1005
    check-cast p0, Ljava/lang/String;

    .line 1006
    .line 1007
    check-cast p1, Ll2/o;

    .line 1008
    .line 1009
    check-cast p2, Ljava/lang/Integer;

    .line 1010
    .line 1011
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1012
    .line 1013
    .line 1014
    const/16 p2, 0x181

    .line 1015
    .line 1016
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 1017
    .line 1018
    .line 1019
    move-result p2

    .line 1020
    invoke-static {v0, v1, p0, p1, p2}, Lqv0/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 1021
    .line 1022
    .line 1023
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1024
    .line 1025
    return-object p0

    .line 1026
    nop

    .line 1027
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
