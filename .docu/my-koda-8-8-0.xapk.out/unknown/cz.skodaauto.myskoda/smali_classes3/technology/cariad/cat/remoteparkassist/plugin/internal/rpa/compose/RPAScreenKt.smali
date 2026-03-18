.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0002\u001a3\u0010\t\u001a\u00020\u00082\u0008\u0008\u0002\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0006H\u0001\u00a2\u0006\u0004\u0008\t\u0010\n\u001a\'\u0010\u000b\u001a\u00020\u00082\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0003\u00a2\u0006\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\u000f\u00b2\u0006\u000c\u0010\u000e\u001a\u00020\r8\nX\u008a\u0084\u0002"
    }
    d2 = {
        "Lx2/s;",
        "modifier",
        "Lx61/a;",
        "rpaScreenViewModel",
        "Lg61/g;",
        "rpaScreenCreator",
        "Lg61/a;",
        "backgroundSceneConfig",
        "Llx0/b0;",
        "RPAScreen",
        "(Lx2/s;Lx61/a;Lg61/g;Lg61/a;Ll2/o;II)V",
        "RPAForegroundScreen",
        "(Lx2/s;Lx61/a;Lg61/g;Ll2/o;I)V",
        "",
        "isClosable",
        "remoteparkassistplugin_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private static final RPAForegroundScreen(Lx2/s;Lx61/a;Lg61/g;Ll2/o;I)V
    .locals 9

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x3d638bf8

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_4

    .line 28
    .line 29
    and-int/lit8 v1, p4, 0x40

    .line 30
    .line 31
    if-nez v1, :cond_2

    .line 32
    .line 33
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    :goto_2
    if-eqz v1, :cond_3

    .line 43
    .line 44
    const/16 v1, 0x20

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_3
    const/16 v1, 0x10

    .line 48
    .line 49
    :goto_3
    or-int/2addr v0, v1

    .line 50
    :cond_4
    and-int/lit16 v1, p4, 0x180

    .line 51
    .line 52
    if-nez v1, :cond_7

    .line 53
    .line 54
    and-int/lit16 v1, p4, 0x200

    .line 55
    .line 56
    if-nez v1, :cond_5

    .line 57
    .line 58
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    goto :goto_4

    .line 63
    :cond_5
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    :goto_4
    if-eqz v1, :cond_6

    .line 68
    .line 69
    const/16 v1, 0x100

    .line 70
    .line 71
    goto :goto_5

    .line 72
    :cond_6
    const/16 v1, 0x80

    .line 73
    .line 74
    :goto_5
    or-int/2addr v0, v1

    .line 75
    :cond_7
    and-int/lit16 v1, v0, 0x93

    .line 76
    .line 77
    const/16 v2, 0x92

    .line 78
    .line 79
    const/4 v3, 0x1

    .line 80
    const/4 v4, 0x0

    .line 81
    if-eq v1, v2, :cond_8

    .line 82
    .line 83
    move v1, v3

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move v1, v4

    .line 86
    :goto_6
    and-int/lit8 v2, v0, 0x1

    .line 87
    .line 88
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_13

    .line 93
    .line 94
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 95
    .line 96
    invoke-static {v1, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iget-wide v5, p3, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    invoke-virtual {p3}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    invoke-static {p3, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {p3}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v8, p3, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v8, :cond_9

    .line 127
    .line 128
    invoke-virtual {p3, v7}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_9
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_7
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v7, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v1, v5, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v5, p3, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v5, :cond_a

    .line 150
    .line 151
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    if-nez v5, :cond_b

    .line 164
    .line 165
    :cond_a
    invoke-static {v2, p3, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_b
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v1, v6, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;

    .line 174
    .line 175
    if-eqz v1, :cond_c

    .line 176
    .line 177
    const v1, -0x18bb10d5    # -9.299957E23f

    .line 178
    .line 179
    .line 180
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 181
    .line 182
    .line 183
    const-string v1, "RPA_CONNECTION_ESTABLISHMENT_SCREEN"

    .line 184
    .line 185
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    move-object v2, p1

    .line 190
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;

    .line 191
    .line 192
    and-int/lit16 v0, v0, 0x3f0

    .line 193
    .line 194
    move-object v5, p2

    .line 195
    check-cast v5, Ly61/g;

    .line 196
    .line 197
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->a(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    goto/16 :goto_8

    .line 204
    .line 205
    :cond_c
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 206
    .line 207
    if-eqz v1, :cond_d

    .line 208
    .line 209
    const v1, -0x18baf227

    .line 210
    .line 211
    .line 212
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 213
    .line 214
    .line 215
    const-string v1, "RPA_TOUCH_DIAGNOSIS_SCREEN"

    .line 216
    .line 217
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    move-object v2, p1

    .line 222
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 223
    .line 224
    and-int/lit16 v0, v0, 0x3f0

    .line 225
    .line 226
    move-object v5, p2

    .line 227
    check-cast v5, Ly61/g;

    .line 228
    .line 229
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->h(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;Ll2/o;I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 233
    .line 234
    .line 235
    goto/16 :goto_8

    .line 236
    .line 237
    :cond_d
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 238
    .line 239
    if-eqz v1, :cond_e

    .line 240
    .line 241
    const v1, -0x18bad585

    .line 242
    .line 243
    .line 244
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 245
    .line 246
    .line 247
    const-string v1, "RPA_DRIVE_ACTIVATION_SCREEN"

    .line 248
    .line 249
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    move-object v2, p1

    .line 254
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 255
    .line 256
    and-int/lit16 v0, v0, 0x3f0

    .line 257
    .line 258
    move-object v5, p2

    .line 259
    check-cast v5, Ly61/g;

    .line 260
    .line 261
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->b(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;Ll2/o;I)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 265
    .line 266
    .line 267
    goto/16 :goto_8

    .line 268
    .line 269
    :cond_e
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 270
    .line 271
    if-eqz v1, :cond_f

    .line 272
    .line 273
    const v1, -0x18bab8a5

    .line 274
    .line 275
    .line 276
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 277
    .line 278
    .line 279
    const-string v1, "RPA_DRIVE_CORRECTION_SCREEN"

    .line 280
    .line 281
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    move-object v2, p1

    .line 286
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 287
    .line 288
    and-int/lit16 v0, v0, 0x3f0

    .line 289
    .line 290
    move-object v5, p2

    .line 291
    check-cast v5, Ly61/g;

    .line 292
    .line 293
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->c(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;Ll2/o;I)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    goto :goto_8

    .line 300
    :cond_f
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 301
    .line 302
    if-eqz v1, :cond_10

    .line 303
    .line 304
    const v1, -0x18ba9a6f

    .line 305
    .line 306
    .line 307
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 308
    .line 309
    .line 310
    const-string v1, "RPA_SCENARIO_SELECTION_AND_DRIVE_SCREEN"

    .line 311
    .line 312
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    move-object v2, p1

    .line 317
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 318
    .line 319
    and-int/lit16 v0, v0, 0x3f0

    .line 320
    .line 321
    move-object v5, p2

    .line 322
    check-cast v5, Ly61/g;

    .line 323
    .line 324
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->g(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;Ll2/o;I)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 328
    .line 329
    .line 330
    goto :goto_8

    .line 331
    :cond_10
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 332
    .line 333
    if-eqz v1, :cond_11

    .line 334
    .line 335
    const v1, -0x18ba7aed

    .line 336
    .line 337
    .line 338
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 339
    .line 340
    .line 341
    const-string v1, "RPA_FINISHED_SCREEN"

    .line 342
    .line 343
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    move-object v2, p1

    .line 348
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 349
    .line 350
    and-int/lit16 v0, v0, 0x3f0

    .line 351
    .line 352
    move-object v5, p2

    .line 353
    check-cast v5, Ly61/g;

    .line 354
    .line 355
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->e(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;Ll2/o;I)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 359
    .line 360
    .line 361
    goto :goto_8

    .line 362
    :cond_11
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 363
    .line 364
    if-eqz v1, :cond_12

    .line 365
    .line 366
    const v1, -0x18ba5f51

    .line 367
    .line 368
    .line 369
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 370
    .line 371
    .line 372
    const-string v1, "RPA_FAILED_SCREEN"

    .line 373
    .line 374
    invoke-static {p0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    move-object v2, p1

    .line 379
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 380
    .line 381
    and-int/lit16 v0, v0, 0x3f0

    .line 382
    .line 383
    move-object v5, p2

    .line 384
    check-cast v5, Ly61/g;

    .line 385
    .line 386
    invoke-virtual {v5, v1, v2, p3, v0}, Ly61/g;->d(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;Ll2/o;I)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 390
    .line 391
    .line 392
    :goto_8
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 393
    .line 394
    .line 395
    goto :goto_9

    .line 396
    :cond_12
    const p0, -0x18bb16fa

    .line 397
    .line 398
    .line 399
    invoke-static {p0, p3, v4}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 400
    .line 401
    .line 402
    move-result-object p0

    .line 403
    throw p0

    .line 404
    :cond_13
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 405
    .line 406
    .line 407
    :goto_9
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 408
    .line 409
    .line 410
    move-result-object p3

    .line 411
    if-eqz p3, :cond_14

    .line 412
    .line 413
    new-instance v0, Li50/j0;

    .line 414
    .line 415
    const/16 v2, 0x1d

    .line 416
    .line 417
    move-object v3, p0

    .line 418
    move-object v4, p1

    .line 419
    move-object v5, p2

    .line 420
    move v1, p4

    .line 421
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 425
    .line 426
    :cond_14
    return-void
.end method

.method private static final RPAForegroundScreen$lambda$1(Lx2/s;Lx61/a;Lg61/g;ILl2/o;I)Llx0/b0;
    .locals 0

    .line 1
    or-int/lit8 p3, p3, 0x1

    .line 2
    .line 3
    invoke-static {p3}, Ll2/b;->x(I)I

    .line 4
    .line 5
    .line 6
    move-result p3

    .line 7
    invoke-static {p0, p1, p2, p4, p3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAForegroundScreen(Lx2/s;Lx61/a;Lg61/g;Ll2/o;I)V

    .line 8
    .line 9
    .line 10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method

.method public static final RPAScreen(Lx2/s;Lx61/a;Lg61/g;Lg61/a;Ll2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p5

    .line 6
    .line 7
    const-string v0, "rpaScreenViewModel"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "rpaScreenCreator"

    .line 13
    .line 14
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v0, p4

    .line 18
    .line 19
    check-cast v0, Ll2/t;

    .line 20
    .line 21
    const v1, -0x1e573eb1

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    and-int/lit8 v1, p6, 0x1

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    or-int/lit8 v5, v4, 0x6

    .line 32
    .line 33
    move v6, v5

    .line 34
    move-object/from16 v5, p0

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_0
    and-int/lit8 v5, v4, 0x6

    .line 38
    .line 39
    if-nez v5, :cond_2

    .line 40
    .line 41
    move-object/from16 v5, p0

    .line 42
    .line 43
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    if-eqz v6, :cond_1

    .line 48
    .line 49
    const/4 v6, 0x4

    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const/4 v6, 0x2

    .line 52
    :goto_0
    or-int/2addr v6, v4

    .line 53
    goto :goto_1

    .line 54
    :cond_2
    move-object/from16 v5, p0

    .line 55
    .line 56
    move v6, v4

    .line 57
    :goto_1
    and-int/lit8 v7, v4, 0x30

    .line 58
    .line 59
    const/16 v8, 0x20

    .line 60
    .line 61
    if-nez v7, :cond_5

    .line 62
    .line 63
    and-int/lit8 v7, v4, 0x40

    .line 64
    .line 65
    if-nez v7, :cond_3

    .line 66
    .line 67
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v7

    .line 71
    goto :goto_2

    .line 72
    :cond_3
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    :goto_2
    if-eqz v7, :cond_4

    .line 77
    .line 78
    move v7, v8

    .line 79
    goto :goto_3

    .line 80
    :cond_4
    const/16 v7, 0x10

    .line 81
    .line 82
    :goto_3
    or-int/2addr v6, v7

    .line 83
    :cond_5
    and-int/lit16 v7, v4, 0x180

    .line 84
    .line 85
    if-nez v7, :cond_8

    .line 86
    .line 87
    and-int/lit16 v7, v4, 0x200

    .line 88
    .line 89
    if-nez v7, :cond_6

    .line 90
    .line 91
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v7

    .line 95
    goto :goto_4

    .line 96
    :cond_6
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    :goto_4
    if-eqz v7, :cond_7

    .line 101
    .line 102
    const/16 v7, 0x100

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_7
    const/16 v7, 0x80

    .line 106
    .line 107
    :goto_5
    or-int/2addr v6, v7

    .line 108
    :cond_8
    and-int/lit16 v7, v4, 0xc00

    .line 109
    .line 110
    if-nez v7, :cond_a

    .line 111
    .line 112
    move-object/from16 v7, p3

    .line 113
    .line 114
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    if-eqz v7, :cond_9

    .line 119
    .line 120
    const/16 v7, 0x800

    .line 121
    .line 122
    goto :goto_6

    .line 123
    :cond_9
    const/16 v7, 0x400

    .line 124
    .line 125
    :goto_6
    or-int/2addr v6, v7

    .line 126
    :cond_a
    and-int/lit16 v7, v6, 0x493

    .line 127
    .line 128
    const/16 v9, 0x492

    .line 129
    .line 130
    const/4 v10, 0x0

    .line 131
    const/4 v11, 0x1

    .line 132
    if-eq v7, v9, :cond_b

    .line 133
    .line 134
    move v7, v11

    .line 135
    goto :goto_7

    .line 136
    :cond_b
    move v7, v10

    .line 137
    :goto_7
    and-int/lit8 v9, v6, 0x1

    .line 138
    .line 139
    invoke-virtual {v0, v9, v7}, Ll2/t;->O(IZ)Z

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-eqz v7, :cond_18

    .line 144
    .line 145
    if-eqz v1, :cond_c

    .line 146
    .line 147
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 148
    .line 149
    goto :goto_8

    .line 150
    :cond_c
    move-object v1, v5

    .line 151
    :goto_8
    and-int/lit8 v5, v6, 0x70

    .line 152
    .line 153
    if-eq v5, v8, :cond_e

    .line 154
    .line 155
    and-int/lit8 v7, v6, 0x40

    .line 156
    .line 157
    if-eqz v7, :cond_d

    .line 158
    .line 159
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v7

    .line 163
    if-eqz v7, :cond_d

    .line 164
    .line 165
    goto :goto_9

    .line 166
    :cond_d
    move v7, v10

    .line 167
    goto :goto_a

    .line 168
    :cond_e
    :goto_9
    move v7, v11

    .line 169
    :goto_a
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 174
    .line 175
    if-nez v7, :cond_f

    .line 176
    .line 177
    if-ne v9, v12, :cond_10

    .line 178
    .line 179
    :cond_f
    new-instance v9, Lp61/d;

    .line 180
    .line 181
    const/4 v7, 0x0

    .line 182
    invoke-direct {v9, v2, v7}, Lp61/d;-><init>(Ljava/lang/Object;I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    :cond_10
    check-cast v9, Lay0/k;

    .line 189
    .line 190
    invoke-static {v2, v9, v0}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 191
    .line 192
    .line 193
    invoke-interface {v2}, Lx61/a;->isClosable()Lyy0/a2;

    .line 194
    .line 195
    .line 196
    move-result-object v7

    .line 197
    invoke-static {v7, v0}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 198
    .line 199
    .line 200
    move-result-object v7

    .line 201
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v9

    .line 205
    if-eq v5, v8, :cond_12

    .line 206
    .line 207
    and-int/lit8 v8, v6, 0x40

    .line 208
    .line 209
    if-eqz v8, :cond_11

    .line 210
    .line 211
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v8

    .line 215
    if-eqz v8, :cond_11

    .line 216
    .line 217
    goto :goto_b

    .line 218
    :cond_11
    move v8, v10

    .line 219
    goto :goto_c

    .line 220
    :cond_12
    :goto_b
    move v8, v11

    .line 221
    :goto_c
    or-int/2addr v8, v9

    .line 222
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v9

    .line 226
    if-nez v8, :cond_13

    .line 227
    .line 228
    if-ne v9, v12, :cond_14

    .line 229
    .line 230
    :cond_13
    new-instance v9, Lo51/c;

    .line 231
    .line 232
    const/4 v8, 0x7

    .line 233
    invoke-direct {v9, v8, v2, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    :cond_14
    check-cast v9, Lay0/a;

    .line 240
    .line 241
    const/4 v7, 0x6

    .line 242
    invoke-static {v11, v9, v0, v7, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 243
    .line 244
    .line 245
    sget-object v8, Lx2/c;->d:Lx2/j;

    .line 246
    .line 247
    invoke-static {v8, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 248
    .line 249
    .line 250
    move-result-object v8

    .line 251
    iget-wide v12, v0, Ll2/t;->T:J

    .line 252
    .line 253
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 254
    .line 255
    .line 256
    move-result v9

    .line 257
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 258
    .line 259
    .line 260
    move-result-object v12

    .line 261
    invoke-static {v0, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 262
    .line 263
    .line 264
    move-result-object v13

    .line 265
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 266
    .line 267
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 268
    .line 269
    .line 270
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 271
    .line 272
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 273
    .line 274
    .line 275
    iget-boolean v15, v0, Ll2/t;->S:Z

    .line 276
    .line 277
    if-eqz v15, :cond_15

    .line 278
    .line 279
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 280
    .line 281
    .line 282
    goto :goto_d

    .line 283
    :cond_15
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 284
    .line 285
    .line 286
    :goto_d
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 287
    .line 288
    invoke-static {v14, v8, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 289
    .line 290
    .line 291
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 292
    .line 293
    invoke-static {v8, v12, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 294
    .line 295
    .line 296
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 297
    .line 298
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 299
    .line 300
    if-nez v12, :cond_16

    .line 301
    .line 302
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 307
    .line 308
    .line 309
    move-result-object v14

    .line 310
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v12

    .line 314
    if-nez v12, :cond_17

    .line 315
    .line 316
    :cond_16
    invoke-static {v9, v0, v9, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 317
    .line 318
    .line 319
    :cond_17
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 320
    .line 321
    invoke-static {v8, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 322
    .line 323
    .line 324
    const v8, -0x610637fe

    .line 325
    .line 326
    .line 327
    invoke-virtual {v0, v8}, Ll2/t;->Y(I)V

    .line 328
    .line 329
    .line 330
    sget-object v8, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 331
    .line 332
    or-int/2addr v5, v7

    .line 333
    invoke-static {v8, v2, v0, v5}, Llp/af;->c(Lx2/s;Lx61/a;Ll2/o;I)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v0, v10}, Ll2/t;->q(Z)V

    .line 337
    .line 338
    .line 339
    and-int/lit16 v6, v6, 0x380

    .line 340
    .line 341
    or-int/2addr v5, v6

    .line 342
    invoke-static {v8, v2, v3, v0, v5}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAForegroundScreen(Lx2/s;Lx61/a;Lg61/g;Ll2/o;I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v0, v11}, Ll2/t;->q(Z)V

    .line 346
    .line 347
    .line 348
    goto :goto_e

    .line 349
    :cond_18
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 350
    .line 351
    .line 352
    move-object v1, v5

    .line 353
    :goto_e
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 354
    .line 355
    .line 356
    move-result-object v7

    .line 357
    if-eqz v7, :cond_19

    .line 358
    .line 359
    new-instance v0, Lc71/c;

    .line 360
    .line 361
    const/16 v6, 0x11

    .line 362
    .line 363
    move/from16 v5, p6

    .line 364
    .line 365
    invoke-direct/range {v0 .. v6}, Lc71/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 366
    .line 367
    .line 368
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 369
    .line 370
    :cond_19
    return-void
.end method

.method private static final RPAScreen$lambda$0$0(Lx61/a;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;
    .locals 2

    .line 1
    const-string v0, "$this$DisposableEffect"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lp61/e;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Lp61/e;-><init>(Lx61/a;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Laa/t;

    .line 16
    .line 17
    const/16 v1, 0xd

    .line 18
    .line 19
    invoke-direct {v0, v1, p1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method private static final RPAScreen$lambda$0$0$0(Lx61/a;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RPAScreen(): rpaScreenViewModel = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final RPAScreen$lambda$1(Ll2/t2;)Z
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ll2/t2;",
            ")Z"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ljava/lang/Boolean;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private static final RPAScreen$lambda$2$0(Lx61/a;Ll2/t2;)Llx0/b0;
    .locals 1

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$1(Ll2/t2;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Lx61/a;->closeRPAModule()V

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance p0, Laa/a0;

    .line 12
    .line 13
    const/4 v0, 0x7

    .line 14
    invoke-direct {p0, p1, v0}, Laa/a0;-><init>(Ll2/t2;I)V

    .line 15
    .line 16
    .line 17
    const-string p1, "RemoteParkAssistPlugin"

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-static {p1, v0, p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logDebug(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method

.method private static final RPAScreen$lambda$2$0$0(Ll2/t2;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$1(Ll2/t2;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "RPAScreen(): suppress onBack, because isClosable = "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static final RPAScreen$lambda$4(Lx2/s;Lx61/a;Lg61/g;Lg61/a;IILl2/o;I)Llx0/b0;
    .locals 7

    .line 1
    or-int/lit8 p4, p4, 0x1

    .line 2
    .line 3
    invoke-static {p4}, Ll2/b;->x(I)I

    .line 4
    .line 5
    .line 6
    move-result v5

    .line 7
    move-object v0, p0

    .line 8
    move-object v1, p1

    .line 9
    move-object v2, p2

    .line 10
    move-object v3, p3

    .line 11
    move v6, p5

    .line 12
    move-object v4, p6

    .line 13
    invoke-static/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen(Lx2/s;Lx61/a;Lg61/g;Lg61/a;Ll2/o;II)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method

.method public static synthetic a(Lx2/s;Lx61/a;Lg61/g;IILl2/o;I)Llx0/b0;
    .locals 8

    .line 1
    const/4 v3, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move-object v2, p2

    .line 5
    move v4, p3

    .line 6
    move v5, p4

    .line 7
    move-object v6, p5

    .line 8
    move v7, p6

    .line 9
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$4(Lx2/s;Lx61/a;Lg61/g;Lg61/a;IILl2/o;I)Llx0/b0;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public static synthetic b(Lx61/a;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$0$0(Lx61/a;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Lx61/a;Ll2/t2;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$2$0(Lx61/a;Ll2/t2;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lx61/a;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$0$0$0(Lx61/a;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lx2/s;Lx61/a;Lg61/g;ILl2/o;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAForegroundScreen$lambda$1(Lx2/s;Lx61/a;Lg61/g;ILl2/o;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ll2/t2;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen$lambda$2$0$0(Ll2/t2;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
