.class public final Lx60/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx60/o;


# direct methods
.method public synthetic constructor <init>(Lx60/o;I)V
    .locals 0

    .line 1
    iput p2, p0, Lx60/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lx60/k;->e:Lx60/o;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lx60/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    iget-object v0, v0, Lx60/k;->e:Lx60/o;

    .line 13
    .line 14
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    move-object v3, v2

    .line 19
    check-cast v3, Lx60/n;

    .line 20
    .line 21
    instance-of v6, v1, Lne0/d;

    .line 22
    .line 23
    instance-of v2, v1, Lne0/c;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    check-cast v1, Lne0/c;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move-object v1, v4

    .line 32
    :goto_0
    if-eqz v1, :cond_1

    .line 33
    .line 34
    iget-object v2, v0, Lx60/o;->n:Lij0/a;

    .line 35
    .line 36
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    :cond_1
    move-object/from16 v20, v4

    .line 41
    .line 42
    const v21, 0x1fffb

    .line 43
    .line 44
    .line 45
    const/4 v4, 0x0

    .line 46
    const/4 v5, 0x0

    .line 47
    const/4 v7, 0x0

    .line 48
    const/4 v8, 0x0

    .line 49
    const/4 v9, 0x0

    .line 50
    const/4 v10, 0x0

    .line 51
    const/4 v11, 0x0

    .line 52
    const/4 v12, 0x0

    .line 53
    const/4 v13, 0x0

    .line 54
    const/4 v14, 0x0

    .line 55
    const/4 v15, 0x0

    .line 56
    const/16 v16, 0x0

    .line 57
    .line 58
    const/16 v17, 0x0

    .line 59
    .line 60
    const/16 v18, 0x0

    .line 61
    .line 62
    const/16 v19, 0x0

    .line 63
    .line 64
    invoke-static/range {v3 .. v21}, Lx60/n;->a(Lx60/n;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;I)Lx60/n;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object v0

    .line 74
    :pswitch_0
    move-object/from16 v1, p1

    .line 75
    .line 76
    check-cast v1, Lne0/s;

    .line 77
    .line 78
    iget-object v0, v0, Lx60/k;->e:Lx60/o;

    .line 79
    .line 80
    iget-object v2, v0, Lx60/o;->n:Lij0/a;

    .line 81
    .line 82
    instance-of v3, v1, Lne0/d;

    .line 83
    .line 84
    if-eqz v3, :cond_2

    .line 85
    .line 86
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    move-object v2, v1

    .line 91
    check-cast v2, Lx60/n;

    .line 92
    .line 93
    const/16 v19, 0x0

    .line 94
    .line 95
    const v20, 0x3fffd

    .line 96
    .line 97
    .line 98
    const/4 v3, 0x0

    .line 99
    const/4 v4, 0x1

    .line 100
    const/4 v5, 0x0

    .line 101
    const/4 v6, 0x0

    .line 102
    const/4 v7, 0x0

    .line 103
    const/4 v8, 0x0

    .line 104
    const/4 v9, 0x0

    .line 105
    const/4 v10, 0x0

    .line 106
    const/4 v11, 0x0

    .line 107
    const/4 v12, 0x0

    .line 108
    const/4 v13, 0x0

    .line 109
    const/4 v14, 0x0

    .line 110
    const/4 v15, 0x0

    .line 111
    const/16 v16, 0x0

    .line 112
    .line 113
    const/16 v17, 0x0

    .line 114
    .line 115
    const/16 v18, 0x0

    .line 116
    .line 117
    invoke-static/range {v2 .. v20}, Lx60/n;->a(Lx60/n;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;I)Lx60/n;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    goto/16 :goto_6

    .line 122
    .line 123
    :cond_2
    instance-of v3, v1, Lne0/e;

    .line 124
    .line 125
    if-eqz v3, :cond_b

    .line 126
    .line 127
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    move-object v4, v3

    .line 132
    check-cast v4, Lx60/n;

    .line 133
    .line 134
    check-cast v1, Lne0/e;

    .line 135
    .line 136
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v1, Lyr0/e;

    .line 139
    .line 140
    iget-object v8, v1, Lyr0/e;->o:Ljava/lang/String;

    .line 141
    .line 142
    iget-object v3, v1, Lyr0/e;->l:Lyr0/c;

    .line 143
    .line 144
    iget-object v9, v1, Lyr0/e;->e:Ljava/lang/String;

    .line 145
    .line 146
    iget-object v10, v1, Lyr0/e;->b:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v11, v1, Lyr0/e;->j:Ljava/lang/String;

    .line 149
    .line 150
    iget-object v5, v1, Lyr0/e;->i:Ljava/time/LocalDate;

    .line 151
    .line 152
    const/4 v6, 0x0

    .line 153
    if-eqz v5, :cond_3

    .line 154
    .line 155
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    move-object v12, v5

    .line 160
    goto :goto_1

    .line 161
    :cond_3
    move-object v12, v6

    .line 162
    :goto_1
    iget-object v5, v1, Lyr0/e;->f:Ljava/lang/String;

    .line 163
    .line 164
    if-eqz v5, :cond_4

    .line 165
    .line 166
    invoke-static {v5}, Lcom/google/android/gms/internal/measurement/j4;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    move-object v13, v5

    .line 171
    goto :goto_2

    .line 172
    :cond_4
    move-object v13, v6

    .line 173
    :goto_2
    const/4 v5, 0x0

    .line 174
    if-eqz v3, :cond_7

    .line 175
    .line 176
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    const/4 v14, 0x4

    .line 181
    if-eq v7, v14, :cond_6

    .line 182
    .line 183
    const/16 v14, 0xb

    .line 184
    .line 185
    if-eq v7, v14, :cond_5

    .line 186
    .line 187
    const/16 v14, 0xc

    .line 188
    .line 189
    if-eq v7, v14, :cond_5

    .line 190
    .line 191
    const v7, 0x7f120ebc

    .line 192
    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_5
    const v7, 0x7f120ebb

    .line 196
    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_6
    const v7, 0x7f120eba

    .line 200
    .line 201
    .line 202
    :goto_3
    new-array v14, v5, [Ljava/lang/Object;

    .line 203
    .line 204
    move-object v15, v2

    .line 205
    check-cast v15, Ljj0/f;

    .line 206
    .line 207
    invoke-virtual {v15, v7, v14}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v7

    .line 211
    move-object v14, v7

    .line 212
    goto :goto_4

    .line 213
    :cond_7
    move-object v14, v6

    .line 214
    :goto_4
    iget-object v7, v1, Lyr0/e;->h:Ljava/lang/String;

    .line 215
    .line 216
    if-eqz v7, :cond_9

    .line 217
    .line 218
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 219
    .line 220
    const/16 v15, 0x24

    .line 221
    .line 222
    if-lt v6, v15, :cond_8

    .line 223
    .line 224
    invoke-static {v7}, Lgj0/a;->b(Ljava/lang/String;)Ljava/util/Locale;

    .line 225
    .line 226
    .line 227
    move-result-object v6

    .line 228
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    goto :goto_5

    .line 232
    :cond_8
    new-instance v6, Ljava/util/Locale;

    .line 233
    .line 234
    invoke-direct {v6, v7}, Ljava/util/Locale;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    :goto_5
    invoke-virtual {v6}, Ljava/util/Locale;->getDisplayLanguage()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v6

    .line 241
    const-string v7, "getDisplayLanguage(...)"

    .line 242
    .line 243
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    :cond_9
    move-object v15, v6

    .line 247
    iget-object v6, v1, Lyr0/e;->m:Ljava/lang/String;

    .line 248
    .line 249
    iget-object v7, v1, Lyr0/e;->b:Ljava/lang/String;

    .line 250
    .line 251
    iget-object v1, v1, Lyr0/e;->j:Ljava/lang/String;

    .line 252
    .line 253
    if-nez v1, :cond_a

    .line 254
    .line 255
    new-array v1, v5, [Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v2, Ljj0/f;

    .line 258
    .line 259
    const v5, 0x7f120eb9

    .line 260
    .line 261
    .line 262
    invoke-virtual {v2, v5, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    :cond_a
    new-instance v2, Lx60/m;

    .line 267
    .line 268
    invoke-direct {v2, v7, v1, v3}, Lx60/m;-><init>(Ljava/lang/String;Ljava/lang/String;Lyr0/c;)V

    .line 269
    .line 270
    .line 271
    const/16 v21, 0x0

    .line 272
    .line 273
    const v22, 0x2e00d

    .line 274
    .line 275
    .line 276
    const/4 v5, 0x0

    .line 277
    move-object/from16 v16, v6

    .line 278
    .line 279
    const/4 v6, 0x0

    .line 280
    const/4 v7, 0x0

    .line 281
    const/16 v17, 0x0

    .line 282
    .line 283
    const/16 v18, 0x0

    .line 284
    .line 285
    const/16 v19, 0x0

    .line 286
    .line 287
    move-object/from16 v20, v2

    .line 288
    .line 289
    invoke-static/range {v4 .. v22}, Lx60/n;->a(Lx60/n;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;I)Lx60/n;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    goto :goto_6

    .line 294
    :cond_b
    instance-of v3, v1, Lne0/c;

    .line 295
    .line 296
    if-eqz v3, :cond_d

    .line 297
    .line 298
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    check-cast v3, Lx60/n;

    .line 303
    .line 304
    iget-boolean v3, v3, Lx60/n;->d:Z

    .line 305
    .line 306
    if-eqz v3, :cond_c

    .line 307
    .line 308
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 309
    .line 310
    .line 311
    move-result-object v1

    .line 312
    check-cast v1, Lx60/n;

    .line 313
    .line 314
    goto :goto_6

    .line 315
    :cond_c
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 316
    .line 317
    .line 318
    move-result-object v3

    .line 319
    move-object v4, v3

    .line 320
    check-cast v4, Lx60/n;

    .line 321
    .line 322
    check-cast v1, Lne0/c;

    .line 323
    .line 324
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 325
    .line 326
    .line 327
    move-result-object v21

    .line 328
    const v22, 0x1fffd

    .line 329
    .line 330
    .line 331
    const/4 v5, 0x0

    .line 332
    const/4 v6, 0x0

    .line 333
    const/4 v7, 0x0

    .line 334
    const/4 v8, 0x0

    .line 335
    const/4 v9, 0x0

    .line 336
    const/4 v10, 0x0

    .line 337
    const/4 v11, 0x0

    .line 338
    const/4 v12, 0x0

    .line 339
    const/4 v13, 0x0

    .line 340
    const/4 v14, 0x0

    .line 341
    const/4 v15, 0x0

    .line 342
    const/16 v16, 0x0

    .line 343
    .line 344
    const/16 v17, 0x0

    .line 345
    .line 346
    const/16 v18, 0x0

    .line 347
    .line 348
    const/16 v19, 0x0

    .line 349
    .line 350
    const/16 v20, 0x0

    .line 351
    .line 352
    invoke-static/range {v4 .. v22}, Lx60/n;->a(Lx60/n;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;I)Lx60/n;

    .line 353
    .line 354
    .line 355
    move-result-object v1

    .line 356
    :goto_6
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 357
    .line 358
    .line 359
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 360
    .line 361
    return-object v0

    .line 362
    :cond_d
    new-instance v0, La8/r0;

    .line 363
    .line 364
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 365
    .line 366
    .line 367
    throw v0

    .line 368
    nop

    .line 369
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
