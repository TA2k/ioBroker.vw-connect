.class public final synthetic Lz20/j;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Lz20/j;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz20/j;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ly70/e0;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    new-instance v1, Ly70/p;

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    invoke-direct {v1, v0, v2}, Ly70/p;-><init>(Ly70/e0;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    move-object v2, v1

    .line 29
    check-cast v2, Ly70/z;

    .line 30
    .line 31
    const/4 v10, 0x1

    .line 32
    const/16 v11, 0x7f

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x0

    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x0

    .line 39
    const/4 v8, 0x0

    .line 40
    const/4 v9, 0x0

    .line 41
    invoke-static/range {v2 .. v11}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 46
    .line 47
    .line 48
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object v0

    .line 51
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Ly70/e0;

    .line 54
    .line 55
    iget-object v0, v0, Ly70/e0;->k:Lfg0/e;

    .line 56
    .line 57
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object v0

    .line 63
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Ly70/o;

    .line 66
    .line 67
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    move-object v2, v1

    .line 72
    check-cast v2, Ly70/k;

    .line 73
    .line 74
    const/4 v9, 0x0

    .line 75
    const/16 v10, 0x7e

    .line 76
    .line 77
    const/4 v3, 0x0

    .line 78
    const/4 v4, 0x0

    .line 79
    const/4 v5, 0x0

    .line 80
    const/4 v6, 0x0

    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v8, 0x0

    .line 83
    invoke-static/range {v2 .. v10}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 88
    .line 89
    .line 90
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object v0

    .line 93
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Ly70/o;

    .line 96
    .line 97
    iget-object v0, v0, Ly70/o;->k:Lw70/d0;

    .line 98
    .line 99
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object v0

    .line 105
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v0, Ly70/o;

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    new-instance v2, Lbp0/g;

    .line 117
    .line 118
    const/16 v3, 0xb

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    invoke-direct {v2, v0, v4, v3}, Lbp0/g;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 122
    .line 123
    .line 124
    const/4 v0, 0x3

    .line 125
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 126
    .line 127
    .line 128
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object v0

    .line 131
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v0, Ly70/o;

    .line 134
    .line 135
    iget-object v0, v0, Ly70/o;->h:Ltr0/b;

    .line 136
    .line 137
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object v0

    .line 143
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v0, Ly70/f;

    .line 146
    .line 147
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    new-instance v2, Ly70/b;

    .line 155
    .line 156
    const/4 v3, 0x1

    .line 157
    const/4 v4, 0x0

    .line 158
    invoke-direct {v2, v0, v4, v3}, Ly70/b;-><init>(Ly70/f;Lkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    const/4 v0, 0x3

    .line 162
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 163
    .line 164
    .line 165
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object v0

    .line 168
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Ly70/f;

    .line 171
    .line 172
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    move-object v2, v1

    .line 177
    check-cast v2, Ly70/d;

    .line 178
    .line 179
    const/4 v11, 0x0

    .line 180
    const/16 v12, 0x1fe

    .line 181
    .line 182
    const/4 v3, 0x0

    .line 183
    const/4 v4, 0x0

    .line 184
    const/4 v5, 0x0

    .line 185
    const/4 v6, 0x0

    .line 186
    const/4 v7, 0x0

    .line 187
    const/4 v8, 0x0

    .line 188
    const/4 v9, 0x0

    .line 189
    const/4 v10, 0x0

    .line 190
    invoke-static/range {v2 .. v12}, Ly70/d;->a(Ly70/d;Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/ArrayList;ZLqr0/d;Ljava/util/List;I)Ly70/d;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 195
    .line 196
    .line 197
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object v0

    .line 200
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v0, Ly70/f;

    .line 203
    .line 204
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    new-instance v1, Ly1/i;

    .line 208
    .line 209
    const/4 v2, 0x3

    .line 210
    invoke-direct {v1, v0, v2}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 211
    .line 212
    .line 213
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 214
    .line 215
    .line 216
    iget-object v0, v0, Ly70/f;->h:Ltr0/b;

    .line 217
    .line 218
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 222
    .line 223
    return-object v0

    .line 224
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 227
    .line 228
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->cancelUnlock()V

    .line 229
    .line 230
    .line 231
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 232
    .line 233
    return-object v0

    .line 234
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 237
    .line 238
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->finishUnlock()V

    .line 239
    .line 240
    .line 241
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 242
    .line 243
    return-object v0

    .line 244
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 247
    .line 248
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->startUnlock()V

    .line 249
    .line 250
    .line 251
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 252
    .line 253
    return-object v0

    .line 254
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 257
    .line 258
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->closeRPAModule()V

    .line 259
    .line 260
    .line 261
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    return-object v0

    .line 264
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 267
    .line 268
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;->closeRPAModule()V

    .line 269
    .line 270
    .line 271
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object v0

    .line 274
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 277
    .line 278
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;->closeRPAModule()V

    .line 279
    .line 280
    .line 281
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 282
    .line 283
    return-object v0

    .line 284
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 287
    .line 288
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;->reconnect()V

    .line 289
    .line 290
    .line 291
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object v0

    .line 294
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 297
    .line 298
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->closeRPAModule()V

    .line 299
    .line 300
    .line 301
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 302
    .line 303
    return-object v0

    .line 304
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 307
    .line 308
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->stopActivation()V

    .line 309
    .line 310
    .line 311
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 312
    .line 313
    return-object v0

    .line 314
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 317
    .line 318
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;->startActivation()V

    .line 319
    .line 320
    .line 321
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 322
    .line 323
    return-object v0

    .line 324
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;

    .line 327
    .line 328
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;->closeRPAModule()V

    .line 329
    .line 330
    .line 331
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 332
    .line 333
    return-object v0

    .line 334
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v0, Ly20/p;

    .line 337
    .line 338
    iget-object v0, v0, Ly20/p;->h:Lw20/c;

    .line 339
    .line 340
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 344
    .line 345
    return-object v0

    .line 346
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast v0, Ly20/m;

    .line 349
    .line 350
    invoke-virtual {v0}, Ly20/m;->q()V

    .line 351
    .line 352
    .line 353
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 354
    .line 355
    return-object v0

    .line 356
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 357
    .line 358
    check-cast v0, Ly20/m;

    .line 359
    .line 360
    iget-object v0, v0, Ly20/m;->s:Lw20/b;

    .line 361
    .line 362
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object v0

    .line 368
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast v0, Ly20/m;

    .line 371
    .line 372
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 373
    .line 374
    .line 375
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 376
    .line 377
    .line 378
    move-result-object v1

    .line 379
    new-instance v2, Lci0/a;

    .line 380
    .line 381
    const/16 v3, 0x9

    .line 382
    .line 383
    const/4 v4, 0x0

    .line 384
    invoke-direct {v2, v0, v4, v3}, Lci0/a;-><init>(Landroidx/lifecycle/b1;Lkotlin/coroutines/Continuation;I)V

    .line 385
    .line 386
    .line 387
    const/4 v0, 0x3

    .line 388
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 389
    .line 390
    .line 391
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    return-object v0

    .line 394
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v0, Ly20/m;

    .line 397
    .line 398
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 399
    .line 400
    .line 401
    new-instance v1, Ly20/a;

    .line 402
    .line 403
    const/4 v2, 0x1

    .line 404
    invoke-direct {v1, v0, v2}, Ly20/a;-><init>(Ly20/m;I)V

    .line 405
    .line 406
    .line 407
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    check-cast v1, Ly20/h;

    .line 415
    .line 416
    iget-object v1, v1, Ly20/h;->j:Ljava/lang/String;

    .line 417
    .line 418
    if-eqz v1, :cond_0

    .line 419
    .line 420
    iget-object v0, v0, Ly20/m;->u:Lw20/e;

    .line 421
    .line 422
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 423
    .line 424
    .line 425
    iget-object v2, v0, Lw20/e;->b:Lkf0/h0;

    .line 426
    .line 427
    iget-object v2, v2, Lkf0/h0;->a:Lif0/t;

    .line 428
    .line 429
    iput-object v1, v2, Lif0/t;->a:Ljava/lang/String;

    .line 430
    .line 431
    iget-object v0, v0, Lw20/e;->a:Lw20/a;

    .line 432
    .line 433
    check-cast v0, Liy/b;

    .line 434
    .line 435
    sget-object v1, Lly/b;->q1:Lly/b;

    .line 436
    .line 437
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 438
    .line 439
    .line 440
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 441
    .line 442
    return-object v0

    .line 443
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v0, Ly20/m;

    .line 446
    .line 447
    iget-object v0, v0, Ly20/m;->p:Ltr0/b;

    .line 448
    .line 449
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 453
    .line 454
    return-object v0

    .line 455
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v0, Ly20/m;

    .line 458
    .line 459
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 460
    .line 461
    .line 462
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    new-instance v2, Ly20/j;

    .line 467
    .line 468
    const/4 v3, 0x1

    .line 469
    const/4 v4, 0x0

    .line 470
    invoke-direct {v2, v0, v4, v3}, Ly20/j;-><init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V

    .line 471
    .line 472
    .line 473
    const/4 v0, 0x3

    .line 474
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 475
    .line 476
    .line 477
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 478
    .line 479
    return-object v0

    .line 480
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast v0, Ly20/m;

    .line 483
    .line 484
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 485
    .line 486
    .line 487
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 488
    .line 489
    .line 490
    move-result-object v1

    .line 491
    new-instance v2, Ly20/j;

    .line 492
    .line 493
    const/4 v3, 0x0

    .line 494
    const/4 v4, 0x0

    .line 495
    invoke-direct {v2, v0, v4, v3}, Ly20/j;-><init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V

    .line 496
    .line 497
    .line 498
    const/4 v0, 0x3

    .line 499
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 500
    .line 501
    .line 502
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 503
    .line 504
    return-object v0

    .line 505
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 506
    .line 507
    check-cast v0, Ly20/m;

    .line 508
    .line 509
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 510
    .line 511
    .line 512
    new-instance v1, Ly20/a;

    .line 513
    .line 514
    const/4 v2, 0x2

    .line 515
    invoke-direct {v1, v0, v2}, Ly20/a;-><init>(Ly20/m;I)V

    .line 516
    .line 517
    .line 518
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 522
    .line 523
    .line 524
    move-result-object v1

    .line 525
    move-object v2, v1

    .line 526
    check-cast v2, Ly20/h;

    .line 527
    .line 528
    const/16 v18, 0x0

    .line 529
    .line 530
    const v19, 0xf3ff

    .line 531
    .line 532
    .line 533
    const/4 v3, 0x0

    .line 534
    const/4 v4, 0x0

    .line 535
    const/4 v5, 0x0

    .line 536
    const/4 v6, 0x0

    .line 537
    const/4 v7, 0x0

    .line 538
    const/4 v8, 0x0

    .line 539
    const/4 v9, 0x0

    .line 540
    const/4 v10, 0x0

    .line 541
    const/4 v11, 0x0

    .line 542
    const/4 v12, 0x0

    .line 543
    const/4 v13, 0x0

    .line 544
    const/4 v14, 0x0

    .line 545
    const/4 v15, 0x0

    .line 546
    const/16 v16, 0x0

    .line 547
    .line 548
    const/16 v17, 0x0

    .line 549
    .line 550
    invoke-static/range {v2 .. v19}, Ly20/h;->a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;

    .line 551
    .line 552
    .line 553
    move-result-object v1

    .line 554
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 555
    .line 556
    .line 557
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 558
    .line 559
    return-object v0

    .line 560
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 561
    .line 562
    check-cast v0, Ly20/m;

    .line 563
    .line 564
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 565
    .line 566
    .line 567
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 568
    .line 569
    .line 570
    move-result-object v1

    .line 571
    new-instance v2, Ly20/j;

    .line 572
    .line 573
    const/4 v3, 0x0

    .line 574
    const/4 v4, 0x0

    .line 575
    invoke-direct {v2, v0, v4, v3}, Ly20/j;-><init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V

    .line 576
    .line 577
    .line 578
    const/4 v0, 0x3

    .line 579
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 580
    .line 581
    .line 582
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 583
    .line 584
    return-object v0

    .line 585
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
