.class public final Lw3/a0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw3/a0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lw3/a0;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lw3/a0;->f:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "it"

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object p0, p0, Lw3/a0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p1, Le3/k0;

    .line 16
    .line 17
    check-cast p0, Le5/l;

    .line 18
    .line 19
    iget v0, p0, Le5/l;->d:F

    .line 20
    .line 21
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget v0, p0, Le5/l;->e:F

    .line 28
    .line 29
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    :cond_0
    iget v0, p0, Le5/l;->d:F

    .line 36
    .line 37
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    const/high16 v1, 0x3f000000    # 0.5f

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    move v0, v1

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    iget v0, p0, Le5/l;->d:F

    .line 48
    .line 49
    :goto_0
    iget v2, p0, Le5/l;->e:F

    .line 50
    .line 51
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-eqz v2, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    iget v1, p0, Le5/l;->e:F

    .line 59
    .line 60
    :goto_1
    invoke-static {v0, v1}, Le3/j0;->i(FF)J

    .line 61
    .line 62
    .line 63
    move-result-wide v0

    .line 64
    invoke-virtual {p1, v0, v1}, Le3/k0;->A(J)V

    .line 65
    .line 66
    .line 67
    :cond_3
    iget v0, p0, Le5/l;->f:F

    .line 68
    .line 69
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_4

    .line 74
    .line 75
    iget v0, p0, Le5/l;->f:F

    .line 76
    .line 77
    invoke-virtual {p1, v0}, Le3/k0;->g(F)V

    .line 78
    .line 79
    .line 80
    :cond_4
    iget v0, p0, Le5/l;->g:F

    .line 81
    .line 82
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-nez v0, :cond_5

    .line 87
    .line 88
    iget v0, p0, Le5/l;->g:F

    .line 89
    .line 90
    invoke-virtual {p1, v0}, Le3/k0;->h(F)V

    .line 91
    .line 92
    .line 93
    :cond_5
    iget v0, p0, Le5/l;->h:F

    .line 94
    .line 95
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-nez v0, :cond_6

    .line 100
    .line 101
    iget v0, p0, Le5/l;->h:F

    .line 102
    .line 103
    invoke-virtual {p1, v0}, Le3/k0;->i(F)V

    .line 104
    .line 105
    .line 106
    :cond_6
    iget v0, p0, Le5/l;->i:F

    .line 107
    .line 108
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-nez v0, :cond_7

    .line 113
    .line 114
    iget v0, p0, Le5/l;->i:F

    .line 115
    .line 116
    invoke-virtual {p1, v0}, Le3/k0;->B(F)V

    .line 117
    .line 118
    .line 119
    :cond_7
    iget v0, p0, Le5/l;->j:F

    .line 120
    .line 121
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-nez v0, :cond_8

    .line 126
    .line 127
    iget v0, p0, Le5/l;->j:F

    .line 128
    .line 129
    invoke-virtual {p1, v0}, Le3/k0;->D(F)V

    .line 130
    .line 131
    .line 132
    :cond_8
    iget v0, p0, Le5/l;->k:F

    .line 133
    .line 134
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-nez v0, :cond_9

    .line 139
    .line 140
    iget v0, p0, Le5/l;->k:F

    .line 141
    .line 142
    invoke-virtual {p1, v0}, Le3/k0;->t(F)V

    .line 143
    .line 144
    .line 145
    :cond_9
    iget v0, p0, Le5/l;->l:F

    .line 146
    .line 147
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    if-eqz v0, :cond_a

    .line 152
    .line 153
    iget v0, p0, Le5/l;->m:F

    .line 154
    .line 155
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    if-nez v0, :cond_d

    .line 160
    .line 161
    :cond_a
    iget v0, p0, Le5/l;->l:F

    .line 162
    .line 163
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    const/high16 v1, 0x3f800000    # 1.0f

    .line 168
    .line 169
    if-eqz v0, :cond_b

    .line 170
    .line 171
    move v0, v1

    .line 172
    goto :goto_2

    .line 173
    :cond_b
    iget v0, p0, Le5/l;->l:F

    .line 174
    .line 175
    :goto_2
    invoke-virtual {p1, v0}, Le3/k0;->l(F)V

    .line 176
    .line 177
    .line 178
    iget v0, p0, Le5/l;->m:F

    .line 179
    .line 180
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-eqz v0, :cond_c

    .line 185
    .line 186
    goto :goto_3

    .line 187
    :cond_c
    iget v1, p0, Le5/l;->m:F

    .line 188
    .line 189
    :goto_3
    invoke-virtual {p1, v1}, Le3/k0;->p(F)V

    .line 190
    .line 191
    .line 192
    :cond_d
    iget v0, p0, Le5/l;->n:F

    .line 193
    .line 194
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 195
    .line 196
    .line 197
    move-result v0

    .line 198
    if-nez v0, :cond_e

    .line 199
    .line 200
    iget p0, p0, Le5/l;->n:F

    .line 201
    .line 202
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 203
    .line 204
    .line 205
    :cond_e
    return-object v5

    .line 206
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 207
    .line 208
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 209
    .line 210
    invoke-interface {p0, v4}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 211
    .line 212
    .line 213
    return-object v5

    .line 214
    :pswitch_1
    check-cast p1, Lg4/e;

    .line 215
    .line 216
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    sget-object v0, Lxv/n;->b:Ljava/lang/String;

    .line 220
    .line 221
    iget-object p1, p1, Lg4/e;->a:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast p1, Ljava/lang/String;

    .line 224
    .line 225
    check-cast p0, Ljava/util/Map;

    .line 226
    .line 227
    invoke-static {p1, p0}, Llp/ef;->c(Ljava/lang/String;Ljava/util/Map;)Lxv/n;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    instance-of p1, p0, Lxv/i;

    .line 232
    .line 233
    if-eqz p1, :cond_f

    .line 234
    .line 235
    move-object v1, p0

    .line 236
    check-cast v1, Lxv/i;

    .line 237
    .line 238
    :cond_f
    return-object v1

    .line 239
    :pswitch_2
    check-cast p1, Lx21/x;

    .line 240
    .line 241
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {p1}, Lx21/x;->a()I

    .line 245
    .line 246
    .line 247
    move-result p1

    .line 248
    check-cast p0, Lx21/x;

    .line 249
    .line 250
    invoke-virtual {p0}, Lx21/x;->a()I

    .line 251
    .line 252
    .line 253
    move-result p0

    .line 254
    if-eq p1, p0, :cond_10

    .line 255
    .line 256
    goto :goto_4

    .line 257
    :cond_10
    move v3, v4

    .line 258
    :goto_4
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    return-object p0

    .line 263
    :pswitch_3
    check-cast p1, Lt4/c;

    .line 264
    .line 265
    check-cast p0, Lv3/h0;

    .line 266
    .line 267
    invoke-virtual {p0, p1}, Lv3/h0;->d0(Lt4/c;)V

    .line 268
    .line 269
    .line 270
    return-object v5

    .line 271
    :pswitch_4
    check-cast p1, Ll4/m;

    .line 272
    .line 273
    iget-object v0, p1, Ll4/m;->b:Lc2/q;

    .line 274
    .line 275
    if-eqz v0, :cond_11

    .line 276
    .line 277
    invoke-virtual {p1, v0}, Ll4/m;->a(Lc2/q;)V

    .line 278
    .line 279
    .line 280
    iput-object v1, p1, Ll4/m;->b:Lc2/q;

    .line 281
    .line 282
    :cond_11
    check-cast p0, Lw3/p1;

    .line 283
    .line 284
    iget-object v0, p0, Lw3/p1;->d:Ln2/b;

    .line 285
    .line 286
    iget-object v1, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 287
    .line 288
    iget v2, v0, Ln2/b;->f:I

    .line 289
    .line 290
    :goto_5
    if-ge v4, v2, :cond_13

    .line 291
    .line 292
    aget-object v3, v1, v4

    .line 293
    .line 294
    check-cast v3, Lv3/e2;

    .line 295
    .line 296
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v3

    .line 300
    if-eqz v3, :cond_12

    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_12
    add-int/lit8 v4, v4, 0x1

    .line 304
    .line 305
    goto :goto_5

    .line 306
    :cond_13
    const/4 v4, -0x1

    .line 307
    :goto_6
    if-ltz v4, :cond_14

    .line 308
    .line 309
    invoke-virtual {v0, v4}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    :cond_14
    iget p1, v0, Ln2/b;->f:I

    .line 313
    .line 314
    if-nez p1, :cond_15

    .line 315
    .line 316
    iget-object p0, p0, Lw3/p1;->b:La7/j;

    .line 317
    .line 318
    invoke-virtual {p0}, La7/j;->invoke()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    :cond_15
    return-object v5

    .line 322
    :pswitch_5
    check-cast p1, Lg3/d;

    .line 323
    .line 324
    check-cast p0, Lw3/o1;

    .line 325
    .line 326
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 327
    .line 328
    .line 329
    move-result-object v0

    .line 330
    invoke-virtual {v0}, Lgw0/c;->h()Le3/r;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    iget-object p0, p0, Lw3/o1;->g:Lay0/n;

    .line 335
    .line 336
    if-eqz p0, :cond_16

    .line 337
    .line 338
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 339
    .line 340
    .line 341
    move-result-object p1

    .line 342
    iget-object p1, p1, Lgw0/c;->f:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast p1, Lh3/c;

    .line 345
    .line 346
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    :cond_16
    return-object v5

    .line 350
    :pswitch_6
    sget-object p1, Lw3/n1;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 351
    .line 352
    invoke-virtual {p1, v4, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 353
    .line 354
    .line 355
    move-result p1

    .line 356
    if-eqz p1, :cond_17

    .line 357
    .line 358
    check-cast p0, Lxy0/j;

    .line 359
    .line 360
    invoke-interface {p0, v5}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    :cond_17
    return-object v5

    .line 364
    :pswitch_7
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 365
    .line 366
    check-cast p0, Lw3/j1;

    .line 367
    .line 368
    new-instance p1, La2/j;

    .line 369
    .line 370
    const/16 v0, 0x11

    .line 371
    .line 372
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 373
    .line 374
    .line 375
    return-object p1

    .line 376
    :pswitch_8
    check-cast p1, Ld4/q;

    .line 377
    .line 378
    check-cast p0, Landroid/content/res/Resources;

    .line 379
    .line 380
    invoke-static {p1, p0}, Lw3/h0;->k(Ld4/q;Landroid/content/res/Resources;)Z

    .line 381
    .line 382
    .line 383
    move-result p0

    .line 384
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 385
    .line 386
    .line 387
    move-result-object p0

    .line 388
    return-object p0

    .line 389
    :pswitch_9
    check-cast p1, Ld4/q;

    .line 390
    .line 391
    check-cast p0, Landroidx/collection/p;

    .line 392
    .line 393
    iget p1, p1, Ld4/q;->g:I

    .line 394
    .line 395
    invoke-virtual {p0, p1}, Landroidx/collection/p;->a(I)Z

    .line 396
    .line 397
    .line 398
    move-result p0

    .line 399
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 400
    .line 401
    .line 402
    move-result-object p0

    .line 403
    return-object p0

    .line 404
    nop

    .line 405
    :pswitch_data_0
    .packed-switch 0x0
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
