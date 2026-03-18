.class public final synthetic Lio0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio0/f;->e:Ll2/b1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lio0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 7
    .line 8
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lt3/y;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    const-string p0, "Required value was null."

    .line 18
    .line 19
    invoke-static {p0}, Lj1/b;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 20
    .line 21
    .line 22
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :pswitch_0
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 29
    .line 30
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lt3/y;

    .line 35
    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_1
    const-string p0, "Required value was null."

    .line 40
    .line 41
    invoke-static {p0}, Lj1/b;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 42
    .line 43
    .line 44
    new-instance p0, La8/r0;

    .line 45
    .line 46
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :pswitch_1
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 51
    .line 52
    const/4 v0, 0x0

    .line 53
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_2
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 60
    .line 61
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    check-cast v0, Ljava/lang/Boolean;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    xor-int/lit8 v0, v0, 0x1

    .line 72
    .line 73
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_3
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 84
    .line 85
    sget-object v0, Lqe/a;->d:Lqe/a;

    .line 86
    .line 87
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_4
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 94
    .line 95
    sget-object v0, Lqe/a;->e:Lqe/a;

    .line 96
    .line 97
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_5
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 104
    .line 105
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 106
    .line 107
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_6
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 114
    .line 115
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 116
    .line 117
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_7
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 124
    .line 125
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :pswitch_8
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 134
    .line 135
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_9
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 144
    .line 145
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    check-cast v0, Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    xor-int/lit8 v0, v0, 0x1

    .line 156
    .line 157
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_a
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 168
    .line 169
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    check-cast v0, Ljava/lang/Boolean;

    .line 174
    .line 175
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    xor-int/lit8 v0, v0, 0x1

    .line 180
    .line 181
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_b
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 192
    .line 193
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    check-cast p0, Ljava/lang/Iterable;

    .line 198
    .line 199
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    return-object p0

    .line 204
    :pswitch_c
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 205
    .line 206
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    check-cast p0, Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 213
    .line 214
    .line 215
    return-object p0

    .line 216
    :pswitch_d
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 217
    .line 218
    if-eqz p0, :cond_2

    .line 219
    .line 220
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    check-cast p0, Ljava/util/List;

    .line 225
    .line 226
    goto :goto_0

    .line 227
    :cond_2
    const/4 p0, 0x0

    .line 228
    :goto_0
    return-object p0

    .line 229
    :pswitch_e
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 230
    .line 231
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 232
    .line 233
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_f
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 240
    .line 241
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 242
    .line 243
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 247
    .line 248
    return-object p0

    .line 249
    :pswitch_10
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 250
    .line 251
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 252
    .line 253
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 257
    .line 258
    return-object p0

    .line 259
    :pswitch_11
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 260
    .line 261
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 262
    .line 263
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 267
    .line 268
    return-object p0

    .line 269
    :pswitch_12
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 270
    .line 271
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 272
    .line 273
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_13
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 280
    .line 281
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 282
    .line 283
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object p0

    .line 289
    :pswitch_14
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 290
    .line 291
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    check-cast p0, Lay0/a;

    .line 296
    .line 297
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object p0

    .line 301
    check-cast p0, Lo1/b0;

    .line 302
    .line 303
    return-object p0

    .line 304
    :pswitch_15
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 305
    .line 306
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 307
    .line 308
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 312
    .line 313
    return-object p0

    .line 314
    :pswitch_16
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 315
    .line 316
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 317
    .line 318
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 322
    .line 323
    return-object p0

    .line 324
    :pswitch_17
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 325
    .line 326
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 327
    .line 328
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 332
    .line 333
    return-object p0

    .line 334
    :pswitch_18
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 335
    .line 336
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 337
    .line 338
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 339
    .line 340
    .line 341
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 342
    .line 343
    return-object p0

    .line 344
    :pswitch_19
    new-instance v0, Ln1/g;

    .line 345
    .line 346
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 347
    .line 348
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    check-cast p0, Lay0/k;

    .line 353
    .line 354
    invoke-direct {v0, p0}, Ln1/g;-><init>(Lay0/k;)V

    .line 355
    .line 356
    .line 357
    return-object v0

    .line 358
    :pswitch_1a
    new-instance v0, Lm1/f;

    .line 359
    .line 360
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 361
    .line 362
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object p0

    .line 366
    check-cast p0, Lay0/k;

    .line 367
    .line 368
    invoke-direct {v0, p0}, Lm1/f;-><init>(Lay0/k;)V

    .line 369
    .line 370
    .line 371
    return-object v0

    .line 372
    :pswitch_1b
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 373
    .line 374
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 375
    .line 376
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 380
    .line 381
    return-object p0

    .line 382
    :pswitch_1c
    iget-object p0, p0, Lio0/f;->e:Ll2/b1;

    .line 383
    .line 384
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v0

    .line 388
    check-cast v0, Ljava/lang/Boolean;

    .line 389
    .line 390
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 391
    .line 392
    .line 393
    move-result v0

    .line 394
    xor-int/lit8 v0, v0, 0x1

    .line 395
    .line 396
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 397
    .line 398
    .line 399
    move-result-object v0

    .line 400
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 401
    .line 402
    .line 403
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 404
    .line 405
    return-object p0

    .line 406
    nop

    .line 407
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
