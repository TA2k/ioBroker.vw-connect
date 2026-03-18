.class public final La7/l;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Landroid/content/Context;

.field public final synthetic h:La7/n;


# direct methods
.method public constructor <init>(La7/n;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La7/l;->f:I

    .line 1
    iput-object p1, p0, La7/l;->h:La7/n;

    iput-object p2, p0, La7/l;->g:Landroid/content/Context;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;La7/n;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La7/l;->f:I

    .line 2
    iput-object p1, p0, La7/l;->g:Landroid/content/Context;

    iput-object p2, p0, La7/l;->h:La7/n;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, La7/l;->f:I

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
    and-int/lit8 p2, p2, 0x3

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-ne p2, v0, :cond_1

    .line 18
    .line 19
    move-object p2, p1

    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    :goto_0
    sget-object p2, Ly6/k;->b:Ll2/u2;

    .line 34
    .line 35
    iget-object v0, p0, La7/l;->g:Landroid/content/Context;

    .line 36
    .line 37
    invoke-virtual {p2, v0}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    sget-object v1, Ly6/k;->d:Ll2/u2;

    .line 42
    .line 43
    iget-object p0, p0, La7/l;->h:La7/n;

    .line 44
    .line 45
    iget-object v2, p0, La7/n;->e:La7/c;

    .line 46
    .line 47
    invoke-virtual {v1, v2}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    sget-object v2, La7/x;->a:Ll2/e0;

    .line 52
    .line 53
    iget-object v3, p0, La7/n;->j:Ll2/j1;

    .line 54
    .line 55
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Landroid/os/Bundle;

    .line 60
    .line 61
    if-nez v3, :cond_2

    .line 62
    .line 63
    sget-object v3, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 64
    .line 65
    :cond_2
    invoke-virtual {v2, v3}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    sget-object v3, Ly6/k;->c:Ll2/e0;

    .line 70
    .line 71
    iget-object v4, p0, La7/n;->i:Ll2/j1;

    .line 72
    .line 73
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-virtual {v3, v4}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    filled-new-array {p2, v1, v2, v3}, [Ll2/t1;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    new-instance v1, La7/l;

    .line 86
    .line 87
    invoke-direct {v1, p0, v0}, La7/l;-><init>(La7/n;Landroid/content/Context;)V

    .line 88
    .line 89
    .line 90
    const p0, 0x64aba82f

    .line 91
    .line 92
    .line 93
    invoke-static {p0, p1, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const/16 v0, 0x30

    .line 98
    .line 99
    invoke-static {p2, p0, p1, v0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 106
    .line 107
    check-cast p2, Ljava/lang/Number;

    .line 108
    .line 109
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    and-int/lit8 p2, p2, 0x3

    .line 114
    .line 115
    const/4 v0, 0x2

    .line 116
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    if-ne p2, v0, :cond_4

    .line 119
    .line 120
    move-object p2, p1

    .line 121
    check-cast p2, Ll2/t;

    .line 122
    .line 123
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    if-nez v0, :cond_3

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 131
    .line 132
    .line 133
    goto/16 :goto_5

    .line 134
    .line 135
    :cond_4
    :goto_2
    move-object v5, p1

    .line 136
    check-cast v5, Ll2/t;

    .line 137
    .line 138
    const p1, 0x702cf9dc

    .line 139
    .line 140
    .line 141
    invoke-virtual {v5, p1}, Ll2/t;->Z(I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 149
    .line 150
    if-ne p1, p2, :cond_5

    .line 151
    .line 152
    new-instance p1, Lt4/h;

    .line 153
    .line 154
    const-wide/16 v2, 0x0

    .line 155
    .line 156
    invoke-direct {p1, v2, v3}, Lt4/h;-><init>(J)V

    .line 157
    .line 158
    .line 159
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-virtual {v5, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    :cond_5
    move-object v10, p1

    .line 167
    check-cast v10, Ll2/b1;

    .line 168
    .line 169
    const/4 p1, 0x0

    .line 170
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 171
    .line 172
    .line 173
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 174
    .line 175
    const v2, 0x702d0a3f

    .line 176
    .line 177
    .line 178
    invoke-virtual {v5, v2}, Ll2/t;->Z(I)V

    .line 179
    .line 180
    .line 181
    iget-object v8, p0, La7/l;->h:La7/n;

    .line 182
    .line 183
    invoke-virtual {v5, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v2

    .line 187
    iget-object v9, p0, La7/l;->g:Landroid/content/Context;

    .line 188
    .line 189
    invoke-virtual {v5, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result p0

    .line 193
    or-int/2addr p0, v2

    .line 194
    invoke-virtual {v5, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v2

    .line 198
    or-int/2addr p0, v2

    .line 199
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    const/4 v11, 0x0

    .line 204
    if-nez p0, :cond_6

    .line 205
    .line 206
    if-ne v2, p2, :cond_7

    .line 207
    .line 208
    :cond_6
    new-instance v6, La7/k;

    .line 209
    .line 210
    const/4 v7, 0x0

    .line 211
    invoke-direct/range {v6 .. v11}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    move-object v2, v6

    .line 218
    :cond_7
    check-cast v2, Lay0/n;

    .line 219
    .line 220
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 221
    .line 222
    .line 223
    invoke-static {v2, v0, v5}, Ll2/b;->o(Lay0/n;Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    check-cast p0, Ljava/lang/Boolean;

    .line 232
    .line 233
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 234
    .line 235
    .line 236
    move-result p0

    .line 237
    if-eqz p0, :cond_b

    .line 238
    .line 239
    const p0, -0x6a792d13

    .line 240
    .line 241
    .line 242
    invoke-virtual {v5, p0}, Ll2/t;->Z(I)V

    .line 243
    .line 244
    .line 245
    const p0, 0x702da53e

    .line 246
    .line 247
    .line 248
    invoke-virtual {v5, p0}, Ll2/t;->Z(I)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    if-ne p0, p2, :cond_8

    .line 256
    .line 257
    iget-object p0, v8, La7/n;->d:La7/m0;

    .line 258
    .line 259
    iget-object v0, v8, La7/n;->e:La7/c;

    .line 260
    .line 261
    new-instance v2, La7/r;

    .line 262
    .line 263
    invoke-direct {v2, p0, v9, v0, v11}, La7/r;-><init>(La7/m0;Landroid/content/Context;La7/c;Lkotlin/coroutines/Continuation;)V

    .line 264
    .line 265
    .line 266
    new-instance p0, Lyy0/e;

    .line 267
    .line 268
    const/4 v0, -0x2

    .line 269
    sget-object v3, Lxy0/a;->d:Lxy0/a;

    .line 270
    .line 271
    sget-object v4, Lpx0/h;->d:Lpx0/h;

    .line 272
    .line 273
    invoke-direct {p0, v2, v4, v0, v3}, Lyy0/e;-><init>(Lay0/n;Lpx0/g;ILxy0/a;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v5, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    :cond_8
    move-object v2, p0

    .line 280
    check-cast v2, Lyy0/i;

    .line 281
    .line 282
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 283
    .line 284
    .line 285
    const/16 v6, 0x30

    .line 286
    .line 287
    const/4 v7, 0x2

    .line 288
    const/4 v3, 0x0

    .line 289
    const/4 v4, 0x0

    .line 290
    invoke-static/range {v2 .. v7}, Ll2/b;->e(Lyy0/i;Ljava/lang/Object;Lpx0/g;Ll2/o;II)Ll2/b1;

    .line 291
    .line 292
    .line 293
    move-result-object p0

    .line 294
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    move-object v6, p0

    .line 299
    check-cast v6, Lay0/n;

    .line 300
    .line 301
    const p0, 0x702db35e

    .line 302
    .line 303
    .line 304
    invoke-virtual {v5, p0}, Ll2/t;->Z(I)V

    .line 305
    .line 306
    .line 307
    if-nez v6, :cond_9

    .line 308
    .line 309
    goto :goto_3

    .line 310
    :cond_9
    move-object v7, v5

    .line 311
    iget-object v5, v8, La7/n;->g:La7/a2;

    .line 312
    .line 313
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    check-cast p0, Lt4/h;

    .line 318
    .line 319
    iget-wide v3, p0, Lt4/h;->a:J

    .line 320
    .line 321
    const/4 v2, 0x0

    .line 322
    invoke-static/range {v2 .. v7}, Lis0/b;->a(IJLa7/a2;Lay0/n;Ll2/o;)V

    .line 323
    .line 324
    .line 325
    move-object v5, v7

    .line 326
    move-object v11, v1

    .line 327
    :goto_3
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 328
    .line 329
    .line 330
    if-nez v11, :cond_a

    .line 331
    .line 332
    invoke-static {v5, p1}, Li0/d;->a(Ll2/o;I)V

    .line 333
    .line 334
    .line 335
    :cond_a
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 336
    .line 337
    .line 338
    goto :goto_4

    .line 339
    :cond_b
    const p0, -0x6a75c3a0

    .line 340
    .line 341
    .line 342
    invoke-virtual {v5, p0}, Ll2/t;->Z(I)V

    .line 343
    .line 344
    .line 345
    invoke-static {v5, p1}, Li0/d;->a(Ll2/o;I)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 349
    .line 350
    .line 351
    :goto_4
    const p0, 0x702ddd43

    .line 352
    .line 353
    .line 354
    invoke-virtual {v5, p0}, Ll2/t;->Z(I)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v5, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    move-result p0

    .line 361
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v0

    .line 365
    if-nez p0, :cond_c

    .line 366
    .line 367
    if-ne v0, p2, :cond_d

    .line 368
    .line 369
    :cond_c
    new-instance v0, La7/j;

    .line 370
    .line 371
    const/4 p0, 0x0

    .line 372
    invoke-direct {v0, v8, p0}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {v5, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    :cond_d
    check-cast v0, Lay0/a;

    .line 379
    .line 380
    invoke-virtual {v5, p1}, Ll2/t;->q(Z)V

    .line 381
    .line 382
    .line 383
    invoke-static {v0, v5}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 384
    .line 385
    .line 386
    :goto_5
    return-object v1

    .line 387
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
