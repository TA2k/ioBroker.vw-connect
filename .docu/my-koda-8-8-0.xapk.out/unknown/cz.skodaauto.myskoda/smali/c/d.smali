.class public final synthetic Lc/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lc/d;->d:I

    iput-object p1, p0, Lc/d;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lc/d;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p3, p0, Lc/d;->d:I

    iput-boolean p1, p0, Lc/d;->e:Z

    iput-object p2, p0, Lc/d;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lc/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 9
    .line 10
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 11
    .line 12
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Z)Llx0/b0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Ll2/b1;

    .line 20
    .line 21
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    sget-object p0, Lxf0/m2;->d:Lxf0/m2;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    sget-object p0, Lxf0/m2;->e:Lxf0/m2;

    .line 29
    .line 30
    :goto_0
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_1
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 39
    .line 40
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 41
    .line 42
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->C0(ZLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Ltechnology/cariad/cat/genx/Channel;

    .line 50
    .line 51
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 52
    .line 53
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->a(Ltechnology/cariad/cat/genx/Channel;Z)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_3
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 61
    .line 62
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 63
    .line 64
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$onCar2PhoneConnectionAllowanceChanged(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Z)V

    .line 65
    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0

    .line 70
    :pswitch_4
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Lc2/b;

    .line 73
    .line 74
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 75
    .line 76
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    if-eqz p0, :cond_1

    .line 79
    .line 80
    invoke-virtual {v0}, Lc2/b;->i()Lyy0/i1;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    if-eqz p0, :cond_1

    .line 85
    .line 86
    check-cast p0, Lyy0/q1;

    .line 87
    .line 88
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    :cond_1
    return-object v1

    .line 92
    :pswitch_5
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Ls10/l;

    .line 95
    .line 96
    new-instance v1, Llj0/e;

    .line 97
    .line 98
    iget-object v0, v0, Ls10/l;->l:Lij0/a;

    .line 99
    .line 100
    const v2, 0x7f120f4e

    .line 101
    .line 102
    .line 103
    check-cast v0, Ljj0/f;

    .line 104
    .line 105
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 110
    .line 111
    invoke-direct {v1, v0, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 112
    .line 113
    .line 114
    return-object v1

    .line 115
    :pswitch_6
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v0, Lql0/j;

    .line 118
    .line 119
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 120
    .line 121
    if-nez p0, :cond_2

    .line 122
    .line 123
    invoke-virtual {v0}, Lql0/j;->f()V

    .line 124
    .line 125
    .line 126
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_7
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v0, Lay0/a;

    .line 132
    .line 133
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 134
    .line 135
    if-eqz p0, :cond_3

    .line 136
    .line 137
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_8
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 144
    .line 145
    move-object v1, v0

    .line 146
    check-cast v1, Lna/f;

    .line 147
    .line 148
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 149
    .line 150
    if-eqz p0, :cond_4

    .line 151
    .line 152
    const-string p0, "reader"

    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_4
    const-string p0, "writer"

    .line 156
    .line 157
    :goto_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 158
    .line 159
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 160
    .line 161
    .line 162
    new-instance v2, Ljava/lang/StringBuilder;

    .line 163
    .line 164
    const-string v3, "Timed out attempting to acquire a "

    .line 165
    .line 166
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string p0, " connection."

    .line 173
    .line 174
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    const-string p0, "\n\nWriter pool:\n"

    .line 185
    .line 186
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    iget-object p0, v1, Lna/f;->e:Lna/t;

    .line 190
    .line 191
    invoke-virtual {p0, v0}, Lna/t;->d(Ljava/lang/StringBuilder;)V

    .line 192
    .line 193
    .line 194
    const-string p0, "Reader pool:"

    .line 195
    .line 196
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    const/16 p0, 0xa

    .line 200
    .line 201
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    iget-object p0, v1, Lna/f;->d:Lna/t;

    .line 205
    .line 206
    invoke-virtual {p0, v0}, Lna/t;->d(Ljava/lang/StringBuilder;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    const/4 v0, 0x5

    .line 214
    :try_start_0
    invoke-static {v0, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 215
    .line 216
    .line 217
    const/4 p0, 0x0

    .line 218
    throw p0
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 219
    :catch_0
    move-exception v0

    .line 220
    move-object p0, v0

    .line 221
    iget v0, v1, Lna/f;->j:I

    .line 222
    .line 223
    const/4 v1, 0x1

    .line 224
    if-eq v0, v1, :cond_6

    .line 225
    .line 226
    const/4 v1, 0x2

    .line 227
    if-eq v0, v1, :cond_5

    .line 228
    .line 229
    goto :goto_2

    .line 230
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 231
    .line 232
    .line 233
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 234
    .line 235
    return-object p0

    .line 236
    :cond_6
    throw p0

    .line 237
    :pswitch_9
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Ll60/b;

    .line 240
    .line 241
    new-instance v1, Llj0/e;

    .line 242
    .line 243
    iget-object v0, v0, Ll60/b;->f:Ljava/lang/String;

    .line 244
    .line 245
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 246
    .line 247
    invoke-direct {v1, v0, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 248
    .line 249
    .line 250
    return-object v1

    .line 251
    :pswitch_a
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v0, Lym/g;

    .line 254
    .line 255
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 256
    .line 257
    if-eqz p0, :cond_7

    .line 258
    .line 259
    const/high16 p0, 0x3f800000    # 1.0f

    .line 260
    .line 261
    goto :goto_3

    .line 262
    :cond_7
    invoke-virtual {v0}, Lym/g;->getValue()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    check-cast p0, Ljava/lang/Number;

    .line 267
    .line 268
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 269
    .line 270
    .line 271
    move-result p0

    .line 272
    :goto_3
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 273
    .line 274
    .line 275
    move-result-object p0

    .line 276
    return-object p0

    .line 277
    :pswitch_b
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v0, Lc3/q;

    .line 280
    .line 281
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 282
    .line 283
    if-eqz p0, :cond_8

    .line 284
    .line 285
    invoke-static {v0}, Lc3/q;->b(Lc3/q;)V

    .line 286
    .line 287
    .line 288
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 289
    .line 290
    return-object p0

    .line 291
    :pswitch_c
    sget-object v2, Lkw/a;->b:Lkw/j;

    .line 292
    .line 293
    sget-object v4, Lkw/a;->a:Lj9/d;

    .line 294
    .line 295
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 296
    .line 297
    move-object v5, v0

    .line 298
    check-cast v5, Lc1/f1;

    .line 299
    .line 300
    new-instance v0, Lew/i;

    .line 301
    .line 302
    const/4 v6, 0x0

    .line 303
    const/4 v7, 0x0

    .line 304
    iget-boolean v1, p0, Lc/d;->e:Z

    .line 305
    .line 306
    move-object v3, v2

    .line 307
    invoke-direct/range {v0 .. v7}, Lew/i;-><init>(ZLkw/j;Lkw/l;Lj9/d;Lc1/j;FZ)V

    .line 308
    .line 309
    .line 310
    return-object v0

    .line 311
    :pswitch_d
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v0, Lc00/t;

    .line 314
    .line 315
    new-instance v1, Llj0/e;

    .line 316
    .line 317
    iget-object v0, v0, Lc00/t;->o:Lij0/a;

    .line 318
    .line 319
    const v2, 0x7f1200ad

    .line 320
    .line 321
    .line 322
    check-cast v0, Ljj0/f;

    .line 323
    .line 324
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 329
    .line 330
    invoke-direct {v1, v0, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 331
    .line 332
    .line 333
    return-object v1

    .line 334
    :pswitch_e
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v0, Lc00/p;

    .line 337
    .line 338
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 339
    .line 340
    if-eqz p0, :cond_9

    .line 341
    .line 342
    const v1, 0x7f120079

    .line 343
    .line 344
    .line 345
    goto :goto_4

    .line 346
    :cond_9
    const v1, 0x7f12007a

    .line 347
    .line 348
    .line 349
    :goto_4
    new-instance v2, Llj0/e;

    .line 350
    .line 351
    iget-object v0, v0, Lc00/p;->l:Lij0/a;

    .line 352
    .line 353
    check-cast v0, Ljj0/f;

    .line 354
    .line 355
    invoke-virtual {v0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-direct {v2, v0, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 360
    .line 361
    .line 362
    return-object v2

    .line 363
    :pswitch_f
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v0, Lc00/h;

    .line 366
    .line 367
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 368
    .line 369
    if-eqz p0, :cond_a

    .line 370
    .line 371
    const v1, 0x7f120079

    .line 372
    .line 373
    .line 374
    goto :goto_5

    .line 375
    :cond_a
    const v1, 0x7f12007a

    .line 376
    .line 377
    .line 378
    :goto_5
    new-instance v2, Llj0/e;

    .line 379
    .line 380
    iget-object v0, v0, Lc00/h;->l:Lij0/a;

    .line 381
    .line 382
    check-cast v0, Ljj0/f;

    .line 383
    .line 384
    invoke-virtual {v0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 385
    .line 386
    .line 387
    move-result-object v0

    .line 388
    invoke-direct {v2, v0, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 389
    .line 390
    .line 391
    return-object v2

    .line 392
    :pswitch_10
    iget-object v0, p0, Lc/d;->f:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v0, Lc/f;

    .line 395
    .line 396
    iget-boolean p0, p0, Lc/d;->e:Z

    .line 397
    .line 398
    invoke-virtual {v0, p0}, Lb/a0;->setEnabled(Z)V

    .line 399
    .line 400
    .line 401
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 402
    .line 403
    return-object p0

    .line 404
    nop

    .line 405
    :pswitch_data_0
    .packed-switch 0x0
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
