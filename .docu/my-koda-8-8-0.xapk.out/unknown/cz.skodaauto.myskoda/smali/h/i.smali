.class public abstract Lh/i;
.super Landroidx/fragment/app/o0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh/j;


# instance fields
.field public k:Lh/z;


# virtual methods
.method public final addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lb/r;->initializeViewTreeOwners()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->A()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 14
    .line 15
    const v1, 0x1020002

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Landroid/view/ViewGroup;

    .line 23
    .line 24
    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lh/z;->p:Lh/u;

    .line 28
    .line 29
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p1, p0}, Lh/u;->a(Landroid/view/Window$Callback;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final attachBaseContext(Landroid/content/Context;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lh/z;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iput-boolean v1, v0, Lh/z;->R:Z

    .line 9
    .line 10
    iget v2, v0, Lh/z;->V:I

    .line 11
    .line 12
    const/16 v3, -0x64

    .line 13
    .line 14
    if-eq v2, v3, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget v2, Lh/n;->e:I

    .line 18
    .line 19
    :goto_0
    invoke-virtual {v0, p1, v2}, Lh/z;->G(Landroid/content/Context;I)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-static {p1}, Lh/n;->f(Landroid/content/Context;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    invoke-static {p1}, Lh/n;->q(Landroid/content/Context;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    invoke-static {p1}, Lh/z;->t(Landroid/content/Context;)Ly5/c;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    instance-of v3, p1, Landroid/view/ContextThemeWrapper;

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    invoke-static {p1, v0, v2, v5, v4}, Lh/z;->x(Landroid/content/Context;ILy5/c;Landroid/content/res/Configuration;Z)Landroid/content/res/Configuration;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    :try_start_0
    move-object v6, p1

    .line 47
    check-cast v6, Landroid/view/ContextThemeWrapper;

    .line 48
    .line 49
    invoke-virtual {v6, v3}, Landroid/view/ContextThemeWrapper;->applyOverrideConfiguration(Landroid/content/res/Configuration;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    .line 51
    .line 52
    goto/16 :goto_2

    .line 53
    .line 54
    :catch_0
    :cond_2
    instance-of v3, p1, Lk/c;

    .line 55
    .line 56
    if-eqz v3, :cond_3

    .line 57
    .line 58
    invoke-static {p1, v0, v2, v5, v4}, Lh/z;->x(Landroid/content/Context;ILy5/c;Landroid/content/res/Configuration;Z)Landroid/content/res/Configuration;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    :try_start_1
    move-object v4, p1

    .line 63
    check-cast v4, Lk/c;

    .line 64
    .line 65
    invoke-virtual {v4, v3}, Lk/c;->a(Landroid/content/res/Configuration;)V
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_1

    .line 66
    .line 67
    .line 68
    goto/16 :goto_2

    .line 69
    .line 70
    :catch_1
    :cond_3
    sget-boolean v3, Lh/z;->v1:Z

    .line 71
    .line 72
    if-nez v3, :cond_4

    .line 73
    .line 74
    goto/16 :goto_2

    .line 75
    .line 76
    :cond_4
    new-instance v3, Landroid/content/res/Configuration;

    .line 77
    .line 78
    invoke-direct {v3}, Landroid/content/res/Configuration;-><init>()V

    .line 79
    .line 80
    .line 81
    const/4 v4, -0x1

    .line 82
    iput v4, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 83
    .line 84
    const/4 v4, 0x0

    .line 85
    iput v4, v3, Landroid/content/res/Configuration;->fontScale:F

    .line 86
    .line 87
    invoke-virtual {p1, v3}, Landroid/content/Context;->createConfigurationContext(Landroid/content/res/Configuration;)Landroid/content/Context;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    invoke-virtual {v6}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    iget v7, v6, Landroid/content/res/Configuration;->uiMode:I

    .line 108
    .line 109
    iput v7, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 110
    .line 111
    invoke-virtual {v3, v6}, Landroid/content/res/Configuration;->equals(Landroid/content/res/Configuration;)Z

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    if-nez v7, :cond_1a

    .line 116
    .line 117
    new-instance v5, Landroid/content/res/Configuration;

    .line 118
    .line 119
    invoke-direct {v5}, Landroid/content/res/Configuration;-><init>()V

    .line 120
    .line 121
    .line 122
    iput v4, v5, Landroid/content/res/Configuration;->fontScale:F

    .line 123
    .line 124
    invoke-virtual {v3, v6}, Landroid/content/res/Configuration;->diff(Landroid/content/res/Configuration;)I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    if-nez v4, :cond_5

    .line 129
    .line 130
    goto/16 :goto_1

    .line 131
    .line 132
    :cond_5
    iget v4, v3, Landroid/content/res/Configuration;->fontScale:F

    .line 133
    .line 134
    iget v7, v6, Landroid/content/res/Configuration;->fontScale:F

    .line 135
    .line 136
    cmpl-float v4, v4, v7

    .line 137
    .line 138
    if-eqz v4, :cond_6

    .line 139
    .line 140
    iput v7, v5, Landroid/content/res/Configuration;->fontScale:F

    .line 141
    .line 142
    :cond_6
    iget v4, v3, Landroid/content/res/Configuration;->mcc:I

    .line 143
    .line 144
    iget v7, v6, Landroid/content/res/Configuration;->mcc:I

    .line 145
    .line 146
    if-eq v4, v7, :cond_7

    .line 147
    .line 148
    iput v7, v5, Landroid/content/res/Configuration;->mcc:I

    .line 149
    .line 150
    :cond_7
    iget v4, v3, Landroid/content/res/Configuration;->mnc:I

    .line 151
    .line 152
    iget v7, v6, Landroid/content/res/Configuration;->mnc:I

    .line 153
    .line 154
    if-eq v4, v7, :cond_8

    .line 155
    .line 156
    iput v7, v5, Landroid/content/res/Configuration;->mnc:I

    .line 157
    .line 158
    :cond_8
    invoke-static {v3, v6, v5}, Lh/s;->a(Landroid/content/res/Configuration;Landroid/content/res/Configuration;Landroid/content/res/Configuration;)V

    .line 159
    .line 160
    .line 161
    iget v4, v3, Landroid/content/res/Configuration;->touchscreen:I

    .line 162
    .line 163
    iget v7, v6, Landroid/content/res/Configuration;->touchscreen:I

    .line 164
    .line 165
    if-eq v4, v7, :cond_9

    .line 166
    .line 167
    iput v7, v5, Landroid/content/res/Configuration;->touchscreen:I

    .line 168
    .line 169
    :cond_9
    iget v4, v3, Landroid/content/res/Configuration;->keyboard:I

    .line 170
    .line 171
    iget v7, v6, Landroid/content/res/Configuration;->keyboard:I

    .line 172
    .line 173
    if-eq v4, v7, :cond_a

    .line 174
    .line 175
    iput v7, v5, Landroid/content/res/Configuration;->keyboard:I

    .line 176
    .line 177
    :cond_a
    iget v4, v3, Landroid/content/res/Configuration;->keyboardHidden:I

    .line 178
    .line 179
    iget v7, v6, Landroid/content/res/Configuration;->keyboardHidden:I

    .line 180
    .line 181
    if-eq v4, v7, :cond_b

    .line 182
    .line 183
    iput v7, v5, Landroid/content/res/Configuration;->keyboardHidden:I

    .line 184
    .line 185
    :cond_b
    iget v4, v3, Landroid/content/res/Configuration;->navigation:I

    .line 186
    .line 187
    iget v7, v6, Landroid/content/res/Configuration;->navigation:I

    .line 188
    .line 189
    if-eq v4, v7, :cond_c

    .line 190
    .line 191
    iput v7, v5, Landroid/content/res/Configuration;->navigation:I

    .line 192
    .line 193
    :cond_c
    iget v4, v3, Landroid/content/res/Configuration;->navigationHidden:I

    .line 194
    .line 195
    iget v7, v6, Landroid/content/res/Configuration;->navigationHidden:I

    .line 196
    .line 197
    if-eq v4, v7, :cond_d

    .line 198
    .line 199
    iput v7, v5, Landroid/content/res/Configuration;->navigationHidden:I

    .line 200
    .line 201
    :cond_d
    iget v4, v3, Landroid/content/res/Configuration;->orientation:I

    .line 202
    .line 203
    iget v7, v6, Landroid/content/res/Configuration;->orientation:I

    .line 204
    .line 205
    if-eq v4, v7, :cond_e

    .line 206
    .line 207
    iput v7, v5, Landroid/content/res/Configuration;->orientation:I

    .line 208
    .line 209
    :cond_e
    iget v4, v3, Landroid/content/res/Configuration;->screenLayout:I

    .line 210
    .line 211
    and-int/lit8 v4, v4, 0xf

    .line 212
    .line 213
    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    .line 214
    .line 215
    and-int/lit8 v7, v7, 0xf

    .line 216
    .line 217
    if-eq v4, v7, :cond_f

    .line 218
    .line 219
    iget v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 220
    .line 221
    or-int/2addr v4, v7

    .line 222
    iput v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 223
    .line 224
    :cond_f
    iget v4, v3, Landroid/content/res/Configuration;->screenLayout:I

    .line 225
    .line 226
    and-int/lit16 v4, v4, 0xc0

    .line 227
    .line 228
    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    .line 229
    .line 230
    and-int/lit16 v7, v7, 0xc0

    .line 231
    .line 232
    if-eq v4, v7, :cond_10

    .line 233
    .line 234
    iget v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 235
    .line 236
    or-int/2addr v4, v7

    .line 237
    iput v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 238
    .line 239
    :cond_10
    iget v4, v3, Landroid/content/res/Configuration;->screenLayout:I

    .line 240
    .line 241
    and-int/lit8 v4, v4, 0x30

    .line 242
    .line 243
    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    .line 244
    .line 245
    and-int/lit8 v7, v7, 0x30

    .line 246
    .line 247
    if-eq v4, v7, :cond_11

    .line 248
    .line 249
    iget v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 250
    .line 251
    or-int/2addr v4, v7

    .line 252
    iput v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 253
    .line 254
    :cond_11
    iget v4, v3, Landroid/content/res/Configuration;->screenLayout:I

    .line 255
    .line 256
    and-int/lit16 v4, v4, 0x300

    .line 257
    .line 258
    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    .line 259
    .line 260
    and-int/lit16 v7, v7, 0x300

    .line 261
    .line 262
    if-eq v4, v7, :cond_12

    .line 263
    .line 264
    iget v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 265
    .line 266
    or-int/2addr v4, v7

    .line 267
    iput v4, v5, Landroid/content/res/Configuration;->screenLayout:I

    .line 268
    .line 269
    :cond_12
    iget v4, v3, Landroid/content/res/Configuration;->colorMode:I

    .line 270
    .line 271
    and-int/lit8 v4, v4, 0x3

    .line 272
    .line 273
    iget v7, v6, Landroid/content/res/Configuration;->colorMode:I

    .line 274
    .line 275
    and-int/lit8 v7, v7, 0x3

    .line 276
    .line 277
    if-eq v4, v7, :cond_13

    .line 278
    .line 279
    iget v4, v5, Landroid/content/res/Configuration;->colorMode:I

    .line 280
    .line 281
    or-int/2addr v4, v7

    .line 282
    iput v4, v5, Landroid/content/res/Configuration;->colorMode:I

    .line 283
    .line 284
    :cond_13
    iget v4, v3, Landroid/content/res/Configuration;->colorMode:I

    .line 285
    .line 286
    and-int/lit8 v4, v4, 0xc

    .line 287
    .line 288
    iget v7, v6, Landroid/content/res/Configuration;->colorMode:I

    .line 289
    .line 290
    and-int/lit8 v7, v7, 0xc

    .line 291
    .line 292
    if-eq v4, v7, :cond_14

    .line 293
    .line 294
    iget v4, v5, Landroid/content/res/Configuration;->colorMode:I

    .line 295
    .line 296
    or-int/2addr v4, v7

    .line 297
    iput v4, v5, Landroid/content/res/Configuration;->colorMode:I

    .line 298
    .line 299
    :cond_14
    iget v4, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 300
    .line 301
    and-int/lit8 v4, v4, 0xf

    .line 302
    .line 303
    iget v7, v6, Landroid/content/res/Configuration;->uiMode:I

    .line 304
    .line 305
    and-int/lit8 v7, v7, 0xf

    .line 306
    .line 307
    if-eq v4, v7, :cond_15

    .line 308
    .line 309
    iget v4, v5, Landroid/content/res/Configuration;->uiMode:I

    .line 310
    .line 311
    or-int/2addr v4, v7

    .line 312
    iput v4, v5, Landroid/content/res/Configuration;->uiMode:I

    .line 313
    .line 314
    :cond_15
    iget v4, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 315
    .line 316
    and-int/lit8 v4, v4, 0x30

    .line 317
    .line 318
    iget v7, v6, Landroid/content/res/Configuration;->uiMode:I

    .line 319
    .line 320
    and-int/lit8 v7, v7, 0x30

    .line 321
    .line 322
    if-eq v4, v7, :cond_16

    .line 323
    .line 324
    iget v4, v5, Landroid/content/res/Configuration;->uiMode:I

    .line 325
    .line 326
    or-int/2addr v4, v7

    .line 327
    iput v4, v5, Landroid/content/res/Configuration;->uiMode:I

    .line 328
    .line 329
    :cond_16
    iget v4, v3, Landroid/content/res/Configuration;->screenWidthDp:I

    .line 330
    .line 331
    iget v7, v6, Landroid/content/res/Configuration;->screenWidthDp:I

    .line 332
    .line 333
    if-eq v4, v7, :cond_17

    .line 334
    .line 335
    iput v7, v5, Landroid/content/res/Configuration;->screenWidthDp:I

    .line 336
    .line 337
    :cond_17
    iget v4, v3, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 338
    .line 339
    iget v7, v6, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 340
    .line 341
    if-eq v4, v7, :cond_18

    .line 342
    .line 343
    iput v7, v5, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 344
    .line 345
    :cond_18
    iget v4, v3, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    .line 346
    .line 347
    iget v7, v6, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    .line 348
    .line 349
    if-eq v4, v7, :cond_19

    .line 350
    .line 351
    iput v7, v5, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    .line 352
    .line 353
    :cond_19
    iget v3, v3, Landroid/content/res/Configuration;->densityDpi:I

    .line 354
    .line 355
    iget v4, v6, Landroid/content/res/Configuration;->densityDpi:I

    .line 356
    .line 357
    if-eq v3, v4, :cond_1a

    .line 358
    .line 359
    iput v4, v5, Landroid/content/res/Configuration;->densityDpi:I

    .line 360
    .line 361
    :cond_1a
    :goto_1
    invoke-static {p1, v0, v2, v5, v1}, Lh/z;->x(Landroid/content/Context;ILy5/c;Landroid/content/res/Configuration;Z)Landroid/content/res/Configuration;

    .line 362
    .line 363
    .line 364
    move-result-object v0

    .line 365
    new-instance v1, Lk/c;

    .line 366
    .line 367
    const v2, 0x7f1302fa

    .line 368
    .line 369
    .line 370
    invoke-direct {v1, p1, v2}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 371
    .line 372
    .line 373
    invoke-virtual {v1, v0}, Lk/c;->a(Landroid/content/res/Configuration;)V

    .line 374
    .line 375
    .line 376
    :try_start_2
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 377
    .line 378
    .line 379
    move-result-object p1
    :try_end_2
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_2

    .line 380
    if-eqz p1, :cond_1b

    .line 381
    .line 382
    invoke-virtual {v1}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    .line 383
    .line 384
    .line 385
    move-result-object p1

    .line 386
    invoke-virtual {p1}, Landroid/content/res/Resources$Theme;->rebase()V

    .line 387
    .line 388
    .line 389
    :catch_2
    :cond_1b
    move-object p1, v1

    .line 390
    :goto_2
    invoke-super {p0, p1}, Landroid/content/ContextWrapper;->attachBaseContext(Landroid/content/Context;)V

    .line 391
    .line 392
    .line 393
    return-void
.end method

.method public final closeOptionsMenu()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lh/z;

    .line 6
    .line 7
    invoke-virtual {v0}, Lh/z;->E()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, v1}, Landroid/view/Window;->hasFeature(I)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-super {p0}, Landroid/app/Activity;->closeOptionsMenu()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {v0}, Lh/z;->E()V

    .line 11
    .line 12
    .line 13
    invoke-super {p0, p1}, Landroidx/core/app/e;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final findViewById(I)Landroid/view/View;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lh/z;

    .line 6
    .line 7
    invoke-virtual {p0}, Lh/z;->A()V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final getMenuInflater()Landroid/view/MenuInflater;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lh/z;

    .line 6
    .line 7
    iget-object v0, p0, Lh/z;->s:Lk/h;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Lh/z;->E()V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lk/h;

    .line 15
    .line 16
    iget-object v1, p0, Lh/z;->r:Lh/i0;

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    invoke-virtual {v1}, Lh/i0;->d()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object v1, p0, Lh/z;->n:Landroid/content/Context;

    .line 26
    .line 27
    :goto_0
    invoke-direct {v0, v1}, Lk/h;-><init>(Landroid/content/Context;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lh/z;->s:Lk/h;

    .line 31
    .line 32
    :cond_1
    iget-object p0, p0, Lh/z;->s:Lk/h;

    .line 33
    .line 34
    return-object p0
.end method

.method public final getResources()Landroid/content/res/Resources;
    .locals 1

    .line 1
    sget v0, Lm/y2;->b:I

    .line 2
    .line 3
    invoke-super {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final i()Lh/n;
    .locals 2

    .line 1
    iget-object v0, p0, Lh/i;->k:Lh/z;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lh/n;->d:Lfv/o;

    .line 6
    .line 7
    new-instance v0, Lh/z;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, p0, v1, p0, p0}, Lh/z;-><init>(Landroid/content/Context;Landroid/view/Window;Lh/j;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lh/i;->k:Lh/z;

    .line 14
    .line 15
    :cond_0
    iget-object p0, p0, Lh/i;->k:Lh/z;

    .line 16
    .line 17
    return-object p0
.end method

.method public final invalidateOptionsMenu()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lh/n;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lb/r;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    iget-boolean p1, p0, Lh/z;->I:Z

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-boolean p1, p0, Lh/z;->C:Z

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lh/z;->E()V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lh/z;->r:Lh/i0;

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object v0, p1, Lh/i0;->a:Landroid/content/Context;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const/high16 v1, 0x7f050000

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Landroid/content/res/Resources;->getBoolean(I)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    invoke-virtual {p1, v0}, Lh/i0;->g(Z)V

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-static {}, Lm/s;->a()Lm/s;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 45
    .line 46
    monitor-enter p1

    .line 47
    :try_start_0
    iget-object v1, p1, Lm/s;->a:Lm/h2;

    .line 48
    .line 49
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 50
    :try_start_1
    iget-object v2, v1, Lm/h2;->b:Ljava/util/WeakHashMap;

    .line 51
    .line 52
    invoke-virtual {v2, v0}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    check-cast v0, Landroidx/collection/u;

    .line 57
    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    invoke-virtual {v0}, Landroidx/collection/u;->a()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    :goto_0
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 67
    monitor-exit p1

    .line 68
    new-instance p1, Landroid/content/res/Configuration;

    .line 69
    .line 70
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 71
    .line 72
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-direct {p1, v0}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 81
    .line 82
    .line 83
    iput-object p1, p0, Lh/z;->U:Landroid/content/res/Configuration;

    .line 84
    .line 85
    const/4 p1, 0x0

    .line 86
    invoke-virtual {p0, p1, p1}, Lh/z;->r(ZZ)Z

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :goto_1
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 91
    :try_start_4
    throw p0

    .line 92
    :catchall_1
    move-exception p0

    .line 93
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 94
    throw p0
.end method

.method public final onContentChanged()V
    .locals 0

    .line 1
    return-void
.end method

.method public onDestroy()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onDestroy()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Lh/n;->h()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final onMenuItemSelected(ILandroid/view/MenuItem;)Z
    .locals 2

    .line 1
    invoke-super {p0, p1, p2}, Landroidx/fragment/app/o0;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x1

    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lh/z;

    .line 14
    .line 15
    invoke-virtual {p1}, Lh/z;->E()V

    .line 16
    .line 17
    .line 18
    iget-object p1, p1, Lh/z;->r:Lh/i0;

    .line 19
    .line 20
    invoke-interface {p2}, Landroid/view/MenuItem;->getItemId()I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    const v1, 0x102002c

    .line 25
    .line 26
    .line 27
    if-ne p2, v1, :cond_5

    .line 28
    .line 29
    if-eqz p1, :cond_5

    .line 30
    .line 31
    iget-object p1, p1, Lh/i0;->e:Lm/f1;

    .line 32
    .line 33
    check-cast p1, Lm/w2;

    .line 34
    .line 35
    iget p1, p1, Lm/w2;->b:I

    .line 36
    .line 37
    and-int/lit8 p1, p1, 0x4

    .line 38
    .line 39
    if-eqz p1, :cond_5

    .line 40
    .line 41
    invoke-static {p0}, Landroidx/core/app/c;->b(Lh/i;)Landroid/content/Intent;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    if-eqz p1, :cond_5

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Landroid/app/Activity;->shouldUpRecreateTask(Landroid/content/Intent;)Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_4

    .line 52
    .line 53
    new-instance p1, Landroidx/core/app/m0;

    .line 54
    .line 55
    invoke-direct {p1, p0}, Landroidx/core/app/m0;-><init>(Landroid/content/Context;)V

    .line 56
    .line 57
    .line 58
    invoke-static {p0}, Landroidx/core/app/c;->b(Lh/i;)Landroid/content/Intent;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    if-nez p2, :cond_1

    .line 63
    .line 64
    invoke-static {p0}, Landroidx/core/app/c;->b(Lh/i;)Landroid/content/Intent;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    :cond_1
    if-eqz p2, :cond_3

    .line 69
    .line 70
    invoke-virtual {p2}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    if-nez v1, :cond_2

    .line 75
    .line 76
    iget-object v1, p1, Landroidx/core/app/m0;->e:Landroid/content/Context;

    .line 77
    .line 78
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {p2, v1}, Landroid/content/Intent;->resolveActivity(Landroid/content/pm/PackageManager;)Landroid/content/ComponentName;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    :cond_2
    invoke-virtual {p1, v1}, Landroidx/core/app/m0;->e(Landroid/content/ComponentName;)V

    .line 87
    .line 88
    .line 89
    iget-object v1, p1, Landroidx/core/app/m0;->d:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    :cond_3
    invoke-virtual {p1}, Landroidx/core/app/m0;->i()V

    .line 95
    .line 96
    .line 97
    :try_start_0
    invoke-virtual {p0}, Landroid/app/Activity;->finishAffinity()V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 98
    .line 99
    .line 100
    goto :goto_0

    .line 101
    :catch_0
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    .line 102
    .line 103
    .line 104
    :goto_0
    return v0

    .line 105
    :cond_4
    invoke-virtual {p0, p1}, Landroid/app/Activity;->navigateUpTo(Landroid/content/Intent;)Z

    .line 106
    .line 107
    .line 108
    return v0

    .line 109
    :cond_5
    const/4 p0, 0x0

    .line 110
    return p0
.end method

.method public final onPostCreate(Landroid/os/Bundle;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/app/Activity;->onPostCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->A()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final onPostResume()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onPostResume()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->E()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    iput-boolean v0, p0, Lh/i0;->t:Z

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public onStart()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onStart()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {p0, v0, v1}, Lh/z;->r(ZZ)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public onStop()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/o0;->onStop()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->E()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lh/i0;->t:Z

    .line 19
    .line 20
    iget-object p0, p0, Lh/i0;->s:Lk/j;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lk/j;->a()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final onTitleChanged(Ljava/lang/CharSequence;I)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Landroid/app/Activity;->onTitleChanged(Ljava/lang/CharSequence;I)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0, p1}, Lh/n;->p(Ljava/lang/CharSequence;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final openOptionsMenu()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lh/z;

    .line 6
    .line 7
    invoke-virtual {v0}, Lh/z;->E()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, v1}, Landroid/view/Window;->hasFeature(I)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-super {p0}, Landroid/app/Activity;->openOptionsMenu()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public final setContentView(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb/r;->initializeViewTreeOwners()V

    .line 2
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1}, Lh/n;->k(I)V

    return-void
.end method

.method public setContentView(Landroid/view/View;)V
    .locals 0

    .line 3
    invoke-virtual {p0}, Lb/r;->initializeViewTreeOwners()V

    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1}, Lh/n;->n(Landroid/view/View;)V

    return-void
.end method

.method public final setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    .line 5
    invoke-virtual {p0}, Lb/r;->initializeViewTreeOwners()V

    .line 6
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1, p2}, Lh/n;->o(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public final setTheme(I)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/content/Context;->setTheme(I)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    iput p1, p0, Lh/z;->W:I

    .line 11
    .line 12
    return-void
.end method

.method public final supportInvalidateOptionsMenu()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lh/n;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method
