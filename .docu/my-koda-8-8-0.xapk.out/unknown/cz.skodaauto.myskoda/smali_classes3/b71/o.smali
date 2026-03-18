.class public final synthetic Lb71/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZLjava/lang/Enum;I)V
    .locals 0

    .line 1
    iput p4, p0, Lb71/o;->d:I

    iput-object p1, p0, Lb71/o;->g:Ljava/lang/Object;

    iput-boolean p2, p0, Lb71/o;->f:Z

    iput-object p3, p0, Lb71/o;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Lay0/k;Z)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lb71/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/o;->e:Ljava/lang/Object;

    iput-object p2, p0, Lb71/o;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Lb71/o;->f:Z

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;ZLxf0/l2;)V
    .locals 1

    .line 3
    const/16 v0, 0x8

    iput v0, p0, Lb71/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/o;->e:Ljava/lang/Object;

    iput-boolean p2, p0, Lb71/o;->f:Z

    iput-object p3, p0, Lb71/o;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 4
    iput p4, p0, Lb71/o;->d:I

    iput-boolean p1, p0, Lb71/o;->f:Z

    iput-object p2, p0, Lb71/o;->g:Ljava/lang/Object;

    iput-object p3, p0, Lb71/o;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 15

    .line 1
    iget v0, p0, Lb71/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ll2/b1;

    .line 9
    .line 10
    iget-object v1, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lxf0/l2;

    .line 13
    .line 14
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    sget-object p0, Lxf0/m2;->d:Lxf0/m2;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sget-object p0, Lxf0/m2;->e:Lxf0/m2;

    .line 22
    .line 23
    :goto_0
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, v1, Lxf0/l2;->c:Lay0/a;

    .line 27
    .line 28
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lay0/a;

    .line 37
    .line 38
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lay0/a;

    .line 41
    .line 42
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 43
    .line 44
    if-eqz p0, :cond_1

    .line 45
    .line 46
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Lwk0/s1;

    .line 59
    .line 60
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Lvk0/j0;

    .line 63
    .line 64
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 65
    .line 66
    if-eqz p0, :cond_a

    .line 67
    .line 68
    iget-object p0, v0, Lwk0/s1;->p:Lgl0/f;

    .line 69
    .line 70
    new-instance v2, Lhl0/g;

    .line 71
    .line 72
    const-string v3, "<this>"

    .line 73
    .line 74
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    instance-of v3, v1, Lvk0/j;

    .line 78
    .line 79
    if-eqz v3, :cond_2

    .line 80
    .line 81
    new-instance v4, Lbl0/r;

    .line 82
    .line 83
    check-cast v1, Lvk0/j;

    .line 84
    .line 85
    iget-object v3, v1, Lvk0/j;->a:Lvk0/d;

    .line 86
    .line 87
    iget-object v5, v3, Lvk0/d;->a:Ljava/lang/String;

    .line 88
    .line 89
    iget-object v6, v3, Lvk0/d;->b:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v7, v3, Lvk0/d;->d:Lbl0/a;

    .line 92
    .line 93
    iget-object v8, v3, Lvk0/d;->e:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v9, v3, Lvk0/d;->f:Lxj0/f;

    .line 96
    .line 97
    iget-object v10, v3, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 98
    .line 99
    iget-object v1, v1, Lvk0/j;->e:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Ljava/util/Collection;

    .line 102
    .line 103
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 104
    .line 105
    .line 106
    move-result v13

    .line 107
    sget-object v14, Lbl0/q;->f:Lbl0/q;

    .line 108
    .line 109
    const/4 v11, 0x0

    .line 110
    const/4 v12, 0x0

    .line 111
    invoke-direct/range {v4 .. v14}, Lbl0/r;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;Lqr0/n;Ljava/lang/Integer;ILbl0/q;)V

    .line 112
    .line 113
    .line 114
    goto/16 :goto_2

    .line 115
    .line 116
    :cond_2
    instance-of v3, v1, Lvk0/q;

    .line 117
    .line 118
    if-eqz v3, :cond_3

    .line 119
    .line 120
    new-instance v4, Lbl0/t;

    .line 121
    .line 122
    check-cast v1, Lvk0/q;

    .line 123
    .line 124
    iget-object v1, v1, Lvk0/r;->a:Lvk0/d;

    .line 125
    .line 126
    iget-object v5, v1, Lvk0/d;->a:Ljava/lang/String;

    .line 127
    .line 128
    iget-object v6, v1, Lvk0/d;->b:Ljava/lang/String;

    .line 129
    .line 130
    iget-object v7, v1, Lvk0/d;->d:Lbl0/a;

    .line 131
    .line 132
    iget-object v8, v1, Lvk0/d;->e:Ljava/lang/String;

    .line 133
    .line 134
    iget-object v9, v1, Lvk0/d;->f:Lxj0/f;

    .line 135
    .line 136
    iget-object v10, v1, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 137
    .line 138
    invoke-direct/range {v4 .. v10}, Lbl0/t;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;)V

    .line 139
    .line 140
    .line 141
    goto/16 :goto_2

    .line 142
    .line 143
    :cond_3
    instance-of v3, v1, Lvk0/p;

    .line 144
    .line 145
    if-eqz v3, :cond_4

    .line 146
    .line 147
    new-instance v4, Lbl0/s;

    .line 148
    .line 149
    check-cast v1, Lvk0/p;

    .line 150
    .line 151
    iget-object v3, v1, Lvk0/r;->a:Lvk0/d;

    .line 152
    .line 153
    iget-object v5, v3, Lvk0/d;->a:Ljava/lang/String;

    .line 154
    .line 155
    iget-object v6, v3, Lvk0/d;->b:Ljava/lang/String;

    .line 156
    .line 157
    iget-object v7, v3, Lvk0/d;->d:Lbl0/a;

    .line 158
    .line 159
    iget-object v8, v3, Lvk0/d;->e:Ljava/lang/String;

    .line 160
    .line 161
    iget-object v9, v3, Lvk0/d;->f:Lxj0/f;

    .line 162
    .line 163
    iget-object v10, v3, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 164
    .line 165
    iget-object v11, v1, Lvk0/p;->c:Lol0/a;

    .line 166
    .line 167
    invoke-direct/range {v4 .. v11}, Lbl0/s;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;Lol0/a;)V

    .line 168
    .line 169
    .line 170
    goto/16 :goto_2

    .line 171
    .line 172
    :cond_4
    instance-of v3, v1, Lvk0/t;

    .line 173
    .line 174
    if-eqz v3, :cond_5

    .line 175
    .line 176
    new-instance v4, Lbl0/v;

    .line 177
    .line 178
    check-cast v1, Lvk0/t;

    .line 179
    .line 180
    iget-object v1, v1, Lvk0/t;->a:Lvk0/d;

    .line 181
    .line 182
    iget-object v5, v1, Lvk0/d;->a:Ljava/lang/String;

    .line 183
    .line 184
    iget-object v6, v1, Lvk0/d;->b:Ljava/lang/String;

    .line 185
    .line 186
    iget-object v7, v1, Lvk0/d;->d:Lbl0/a;

    .line 187
    .line 188
    iget-object v8, v1, Lvk0/d;->e:Ljava/lang/String;

    .line 189
    .line 190
    iget-object v9, v1, Lvk0/d;->f:Lxj0/f;

    .line 191
    .line 192
    iget-object v10, v1, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 193
    .line 194
    invoke-direct/range {v4 .. v10}, Lbl0/v;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;)V

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_5
    instance-of v3, v1, Lvk0/d0;

    .line 199
    .line 200
    sget-object v11, Lmx0/s;->d:Lmx0/s;

    .line 201
    .line 202
    if-eqz v3, :cond_6

    .line 203
    .line 204
    new-instance v4, Lbl0/c0;

    .line 205
    .line 206
    check-cast v1, Lvk0/d0;

    .line 207
    .line 208
    iget-object v3, v1, Lvk0/e0;->a:Lvk0/d;

    .line 209
    .line 210
    iget-object v5, v3, Lvk0/d;->a:Ljava/lang/String;

    .line 211
    .line 212
    iget-object v6, v3, Lvk0/d;->b:Ljava/lang/String;

    .line 213
    .line 214
    iget-object v7, v3, Lvk0/d;->d:Lbl0/a;

    .line 215
    .line 216
    iget-object v8, v3, Lvk0/d;->e:Ljava/lang/String;

    .line 217
    .line 218
    iget-object v9, v3, Lvk0/d;->f:Lxj0/f;

    .line 219
    .line 220
    iget-object v10, v3, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 221
    .line 222
    iget-boolean v12, v1, Lvk0/d0;->n:Z

    .line 223
    .line 224
    invoke-direct/range {v4 .. v12}, Lbl0/c0;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;Ljava/util/List;Z)V

    .line 225
    .line 226
    .line 227
    goto :goto_2

    .line 228
    :cond_6
    instance-of v3, v1, Lvk0/c0;

    .line 229
    .line 230
    if-eqz v3, :cond_7

    .line 231
    .line 232
    new-instance v4, Lbl0/x;

    .line 233
    .line 234
    check-cast v1, Lvk0/c0;

    .line 235
    .line 236
    iget-object v1, v1, Lvk0/e0;->a:Lvk0/d;

    .line 237
    .line 238
    iget-object v5, v1, Lvk0/d;->a:Ljava/lang/String;

    .line 239
    .line 240
    iget-object v6, v1, Lvk0/d;->b:Ljava/lang/String;

    .line 241
    .line 242
    iget-object v7, v1, Lvk0/d;->d:Lbl0/a;

    .line 243
    .line 244
    iget-object v8, v1, Lvk0/d;->e:Ljava/lang/String;

    .line 245
    .line 246
    iget-object v9, v1, Lvk0/d;->f:Lxj0/f;

    .line 247
    .line 248
    iget-object v10, v1, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 249
    .line 250
    invoke-direct/range {v4 .. v11}, Lbl0/x;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;Ljava/util/List;)V

    .line 251
    .line 252
    .line 253
    goto :goto_2

    .line 254
    :cond_7
    instance-of v3, v1, Lvk0/s0;

    .line 255
    .line 256
    if-eqz v3, :cond_8

    .line 257
    .line 258
    new-instance v4, Lbl0/e0;

    .line 259
    .line 260
    check-cast v1, Lvk0/s0;

    .line 261
    .line 262
    iget-object v1, v1, Lvk0/s0;->a:Lvk0/d;

    .line 263
    .line 264
    iget-object v5, v1, Lvk0/d;->a:Ljava/lang/String;

    .line 265
    .line 266
    iget-object v6, v1, Lvk0/d;->b:Ljava/lang/String;

    .line 267
    .line 268
    iget-object v7, v1, Lvk0/d;->d:Lbl0/a;

    .line 269
    .line 270
    iget-object v8, v1, Lvk0/d;->e:Ljava/lang/String;

    .line 271
    .line 272
    iget-object v9, v1, Lvk0/d;->f:Lxj0/f;

    .line 273
    .line 274
    iget-object v10, v1, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 275
    .line 276
    invoke-direct/range {v4 .. v10}, Lbl0/e0;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;)V

    .line 277
    .line 278
    .line 279
    goto :goto_2

    .line 280
    :cond_8
    instance-of v3, v1, Lvk0/t0;

    .line 281
    .line 282
    if-eqz v3, :cond_9

    .line 283
    .line 284
    new-instance v4, Lbl0/f0;

    .line 285
    .line 286
    check-cast v1, Lvk0/t0;

    .line 287
    .line 288
    iget-object v1, v1, Lvk0/t0;->a:Lvk0/d;

    .line 289
    .line 290
    iget-object v5, v1, Lvk0/d;->a:Ljava/lang/String;

    .line 291
    .line 292
    iget-object v6, v1, Lvk0/d;->b:Ljava/lang/String;

    .line 293
    .line 294
    iget-object v7, v1, Lvk0/d;->d:Lbl0/a;

    .line 295
    .line 296
    iget-object v8, v1, Lvk0/d;->e:Ljava/lang/String;

    .line 297
    .line 298
    iget-object v9, v1, Lvk0/d;->f:Lxj0/f;

    .line 299
    .line 300
    iget-object v10, v1, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 301
    .line 302
    invoke-direct/range {v4 .. v10}, Lbl0/f0;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;)V

    .line 303
    .line 304
    .line 305
    :goto_2
    invoke-direct {v2, v4}, Lhl0/g;-><init>(Lbl0/g0;)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {p0, v2}, Lgl0/f;->a(Lhl0/i;)V

    .line 309
    .line 310
    .line 311
    iget-object p0, v0, Lwk0/s1;->r:Luk0/u;

    .line 312
    .line 313
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    goto :goto_5

    .line 317
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 318
    .line 319
    new-instance v0, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 325
    .line 326
    .line 327
    const-string v1, " can\'t be converted to Poi"

    .line 328
    .line 329
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 330
    .line 331
    .line 332
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    throw p0

    .line 344
    :cond_a
    instance-of p0, v1, Lvk0/d0;

    .line 345
    .line 346
    const/4 v2, 0x0

    .line 347
    if-eqz p0, :cond_b

    .line 348
    .line 349
    move-object p0, v1

    .line 350
    check-cast p0, Lvk0/d0;

    .line 351
    .line 352
    goto :goto_3

    .line 353
    :cond_b
    move-object p0, v2

    .line 354
    :goto_3
    if-eqz p0, :cond_c

    .line 355
    .line 356
    iget-object p0, p0, Lvk0/d0;->j:Lon0/t;

    .line 357
    .line 358
    if-eqz p0, :cond_c

    .line 359
    .line 360
    iget-object p0, p0, Lon0/t;->b:Ljava/lang/String;

    .line 361
    .line 362
    goto :goto_4

    .line 363
    :cond_c
    move-object p0, v2

    .line 364
    :goto_4
    invoke-interface {v1}, Lvk0/j0;->getId()Ljava/lang/String;

    .line 365
    .line 366
    .line 367
    move-result-object v3

    .line 368
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    move-result p0

    .line 372
    if-eqz p0, :cond_d

    .line 373
    .line 374
    new-instance p0, Lwk0/g1;

    .line 375
    .line 376
    const/4 v2, 0x0

    .line 377
    invoke-direct {p0, v0, v2}, Lwk0/g1;-><init>(Lwk0/s1;I)V

    .line 378
    .line 379
    .line 380
    invoke-static {v1, p0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 381
    .line 382
    .line 383
    iget-object p0, v0, Lwk0/s1;->h:Luk0/h0;

    .line 384
    .line 385
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    goto :goto_5

    .line 389
    :cond_d
    new-instance p0, Lwk0/g1;

    .line 390
    .line 391
    const/4 v3, 0x1

    .line 392
    invoke-direct {p0, v0, v3}, Lwk0/g1;-><init>(Lwk0/s1;I)V

    .line 393
    .line 394
    .line 395
    invoke-static {v1, p0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 396
    .line 397
    .line 398
    invoke-static {v1}, Llp/rb;->b(Lvk0/j0;)Lqp0/b0;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 403
    .line 404
    .line 405
    move-result-object v1

    .line 406
    new-instance v3, Lvu/j;

    .line 407
    .line 408
    const/16 v4, 0x1c

    .line 409
    .line 410
    invoke-direct {v3, v4, v0, p0, v2}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 411
    .line 412
    .line 413
    const/4 p0, 0x3

    .line 414
    invoke-static {v1, v2, v2, v3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 415
    .line 416
    .line 417
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 418
    .line 419
    return-object p0

    .line 420
    :pswitch_2
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 423
    .line 424
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast v1, Ltechnology/cariad/cat/genx/ScanningTokenImpl;

    .line 427
    .line 428
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 429
    .line 430
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->M0(ZLtechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Llx0/o;

    .line 431
    .line 432
    .line 433
    move-result-object p0

    .line 434
    return-object p0

    .line 435
    :pswitch_3
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;

    .line 438
    .line 439
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast v1, Ltechnology/cariad/cat/genx/TransportType;

    .line 442
    .line 443
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 444
    .line 445
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->f(Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;ZLtechnology/cariad/cat/genx/TransportType;)I

    .line 446
    .line 447
    .line 448
    move-result p0

    .line 449
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 450
    .line 451
    .line 452
    move-result-object p0

    .line 453
    return-object p0

    .line 454
    :pswitch_4
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 455
    .line 456
    check-cast v0, Landroidx/lifecycle/q;

    .line 457
    .line 458
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 459
    .line 460
    check-cast v1, Ln71/c;

    .line 461
    .line 462
    new-instance v2, Ljava/lang/StringBuilder;

    .line 463
    .line 464
    const-string v3, "updateRPALifecycle(): windowHasFocus = "

    .line 465
    .line 466
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 470
    .line 471
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 472
    .line 473
    .line 474
    const-string p0, ", appLifecycle = "

    .line 475
    .line 476
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 477
    .line 478
    .line 479
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 480
    .line 481
    .line 482
    const-string p0, " => "

    .line 483
    .line 484
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 488
    .line 489
    .line 490
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 491
    .line 492
    .line 493
    move-result-object p0

    .line 494
    return-object p0

    .line 495
    :pswitch_5
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 496
    .line 497
    check-cast v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 498
    .line 499
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast v1, Lg61/h;

    .line 502
    .line 503
    new-instance v2, Ljava/lang/StringBuilder;

    .line 504
    .line 505
    const-string v3, "observeBleTransportStatusAndErrors(): car2PhoneMode = "

    .line 506
    .line 507
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 508
    .line 509
    .line 510
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 511
    .line 512
    .line 513
    const-string v0, ", isConnectable = "

    .line 514
    .line 515
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 516
    .line 517
    .line 518
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 519
    .line 520
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 521
    .line 522
    .line 523
    const-string p0, ", disabledReasonStatus = "

    .line 524
    .line 525
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 526
    .line 527
    .line 528
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 529
    .line 530
    .line 531
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 532
    .line 533
    .line 534
    move-result-object p0

    .line 535
    return-object p0

    .line 536
    :pswitch_6
    iget-object v0, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v0, Ll2/b1;

    .line 539
    .line 540
    iget-object v1, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 541
    .line 542
    check-cast v1, Lay0/k;

    .line 543
    .line 544
    new-instance v2, Lh2/t4;

    .line 545
    .line 546
    const-string v3, "PrimaryEditable"

    .line 547
    .line 548
    invoke-direct {v2, v3}, Lh2/t4;-><init>(Ljava/lang/String;)V

    .line 549
    .line 550
    .line 551
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 552
    .line 553
    .line 554
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 555
    .line 556
    xor-int/lit8 p0, p0, 0x1

    .line 557
    .line 558
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 559
    .line 560
    .line 561
    move-result-object p0

    .line 562
    invoke-interface {v1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 566
    .line 567
    return-object p0

    .line 568
    :pswitch_7
    iget-object v0, p0, Lb71/o;->g:Ljava/lang/Object;

    .line 569
    .line 570
    check-cast v0, Lay0/a;

    .line 571
    .line 572
    iget-object v1, p0, Lb71/o;->e:Ljava/lang/Object;

    .line 573
    .line 574
    check-cast v1, Ll2/b1;

    .line 575
    .line 576
    iget-boolean p0, p0, Lb71/o;->f:Z

    .line 577
    .line 578
    if-eqz p0, :cond_e

    .line 579
    .line 580
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 581
    .line 582
    invoke-interface {v1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 583
    .line 584
    .line 585
    :cond_e
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 589
    .line 590
    return-object p0

    .line 591
    :pswitch_data_0
    .packed-switch 0x0
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
