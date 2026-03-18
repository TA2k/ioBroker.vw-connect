.class public final Lm70/u0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public h:Lyy0/j;

.field public final synthetic i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm70/u0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lm70/u0;->i:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p2, 0x3

    .line 6
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lm70/u0;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lm70/u0;

    .line 11
    .line 12
    iget-object p0, p0, Lm70/u0;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lqd0/g;

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    invoke-direct {v0, p3, p0, v1}, Lm70/u0;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, v0, Lm70/u0;->f:Lyy0/j;

    .line 21
    .line 22
    iput-object p2, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {v0, p0}, Lm70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    new-instance v0, Lm70/u0;

    .line 32
    .line 33
    iget-object p0, p0, Lm70/u0;->i:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lm70/g1;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-direct {v0, p3, p0, v1}, Lm70/u0;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 39
    .line 40
    .line 41
    iput-object p1, v0, Lm70/u0;->f:Lyy0/j;

    .line 42
    .line 43
    iput-object p2, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 44
    .line 45
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Lm70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm70/u0;->d:I

    .line 4
    .line 5
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 6
    .line 7
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    iget-object v5, v0, Lm70/u0;->i:Ljava/lang/Object;

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    const/4 v7, 0x2

    .line 14
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    const/4 v9, 0x0

    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    check-cast v5, Lqd0/g;

    .line 21
    .line 22
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    iget v10, v0, Lm70/u0;->e:I

    .line 25
    .line 26
    if-eqz v10, :cond_3

    .line 27
    .line 28
    if-eq v10, v6, :cond_1

    .line 29
    .line 30
    if-ne v10, v7, :cond_0

    .line 31
    .line 32
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto/16 :goto_6

    .line 36
    .line 37
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :cond_1
    iget-object v2, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v2, Lod0/b0;

    .line 46
    .line 47
    iget-object v3, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v3, Ljava/lang/String;

    .line 50
    .line 51
    iget-object v9, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v9, Lss0/k;

    .line 54
    .line 55
    iget-object v10, v0, Lm70/u0;->h:Lyy0/j;

    .line 56
    .line 57
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object/from16 v11, p1

    .line 61
    .line 62
    :cond_2
    move-object v15, v3

    .line 63
    goto :goto_0

    .line 64
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object v10, v0, Lm70/u0;->f:Lyy0/j;

    .line 68
    .line 69
    iget-object v3, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v3, Lne0/s;

    .line 72
    .line 73
    instance-of v11, v3, Lne0/e;

    .line 74
    .line 75
    if-eqz v11, :cond_9

    .line 76
    .line 77
    check-cast v3, Lne0/e;

    .line 78
    .line 79
    iget-object v2, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 80
    .line 81
    move-object v9, v2

    .line 82
    check-cast v9, Lss0/k;

    .line 83
    .line 84
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    const-string v3, "ddMMyyyy_HHmmss"

    .line 89
    .line 90
    invoke-static {v3}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-virtual {v2, v3}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    iget-object v3, v9, Lss0/k;->a:Ljava/lang/String;

    .line 99
    .line 100
    filled-new-array {v3, v2}, [Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    invoke-static {v2, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    const-string v3, "chargingHistory_%s_%s.csv"

    .line 109
    .line 110
    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    iget-object v2, v5, Lqd0/g;->a:Lod0/b0;

    .line 115
    .line 116
    iget-object v11, v5, Lqd0/g;->d:Lam0/c;

    .line 117
    .line 118
    iput-object v4, v0, Lm70/u0;->f:Lyy0/j;

    .line 119
    .line 120
    iput-object v4, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 121
    .line 122
    iput-object v10, v0, Lm70/u0;->h:Lyy0/j;

    .line 123
    .line 124
    iput-object v9, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 125
    .line 126
    iput-object v3, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 127
    .line 128
    iput-object v2, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 129
    .line 130
    iput v6, v0, Lm70/u0;->e:I

    .line 131
    .line 132
    invoke-virtual {v11, v0}, Lam0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v11

    .line 136
    if-ne v11, v1, :cond_2

    .line 137
    .line 138
    goto/16 :goto_5

    .line 139
    .line 140
    :goto_0
    check-cast v11, Lcm0/b;

    .line 141
    .line 142
    iget-object v3, v9, Lss0/k;->a:Ljava/lang/String;

    .line 143
    .line 144
    iget-object v9, v5, Lqd0/g;->b:Lqd0/y;

    .line 145
    .line 146
    check-cast v9, Lod0/u;

    .line 147
    .line 148
    iget-object v9, v9, Lod0/u;->g:Lyy0/l1;

    .line 149
    .line 150
    iget-object v9, v9, Lyy0/l1;->d:Lyy0/a2;

    .line 151
    .line 152
    invoke-interface {v9}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    check-cast v9, Lrd0/n;

    .line 157
    .line 158
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    const-string v12, "environment"

    .line 162
    .line 163
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string v12, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 167
    .line 168
    invoke-static {v3, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const-string v12, "filter"

    .line 172
    .line 173
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object v12, v2, Lod0/b0;->c:Lxl0/g;

    .line 177
    .line 178
    invoke-interface {v12, v11}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v11

    .line 182
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 183
    .line 184
    .line 185
    move-result-object v12

    .line 186
    invoke-virtual {v12}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v13

    .line 190
    new-instance v14, Llx0/l;

    .line 191
    .line 192
    const-string v7, "userTimezone"

    .line 193
    .line 194
    invoke-direct {v14, v7, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    filled-new-array {v14}, [Llx0/l;

    .line 198
    .line 199
    .line 200
    move-result-object v7

    .line 201
    invoke-static {v7}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    iget-object v13, v9, Lrd0/n;->a:Lqr0/a;

    .line 206
    .line 207
    if-eqz v13, :cond_6

    .line 208
    .line 209
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 210
    .line 211
    .line 212
    move-result v13

    .line 213
    if-eqz v13, :cond_5

    .line 214
    .line 215
    if-ne v13, v6, :cond_4

    .line 216
    .line 217
    const-string v13, "DC"

    .line 218
    .line 219
    goto :goto_1

    .line 220
    :cond_4
    new-instance v0, La8/r0;

    .line 221
    .line 222
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 223
    .line 224
    .line 225
    throw v0

    .line 226
    :cond_5
    const-string v13, "AC"

    .line 227
    .line 228
    :goto_1
    new-instance v14, Llx0/l;

    .line 229
    .line 230
    const-string v4, "currentType"

    .line 231
    .line 232
    invoke-direct {v14, v4, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v7, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    :cond_6
    iget-object v4, v9, Lrd0/n;->b:Lrd0/c0;

    .line 239
    .line 240
    if-eqz v4, :cond_7

    .line 241
    .line 242
    invoke-static {v4, v12}, Ljp/rb;->b(Lrd0/c0;Ljava/time/ZoneId;)Llx0/l;

    .line 243
    .line 244
    .line 245
    move-result-object v4

    .line 246
    iget-object v9, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v9, Ljava/time/OffsetDateTime;

    .line 249
    .line 250
    iget-object v4, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v4, Ljava/time/OffsetDateTime;

    .line 253
    .line 254
    sget-object v12, Ljava/time/format/DateTimeFormatter;->ISO_OFFSET_DATE_TIME:Ljava/time/format/DateTimeFormatter;

    .line 255
    .line 256
    invoke-virtual {v12, v9}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object v9

    .line 260
    invoke-virtual {v12, v4}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    new-instance v12, Llx0/l;

    .line 265
    .line 266
    const-string v13, "from"

    .line 267
    .line 268
    invoke-direct {v12, v13, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v7, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    new-instance v9, Llx0/l;

    .line 275
    .line 276
    const-string v12, "to"

    .line 277
    .line 278
    invoke-direct {v9, v12, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    :cond_7
    iget-object v2, v2, Lod0/b0;->d:Lxl0/p;

    .line 285
    .line 286
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v3

    .line 290
    invoke-static {v3, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v3

    .line 294
    const-string v4, "api/v1/charging/%s/history/export"

    .line 295
    .line 296
    invoke-static {v4, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v3

    .line 300
    check-cast v2, Ldm0/a;

    .line 301
    .line 302
    invoke-virtual {v2, v11, v3, v7}, Ldm0/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v14

    .line 306
    sget-object v13, Llg0/b;->d:Llg0/b;

    .line 307
    .line 308
    iget-object v2, v5, Lqd0/g;->e:Lkc0/i;

    .line 309
    .line 310
    invoke-virtual {v2}, Lkc0/i;->invoke()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    check-cast v2, Ljava/lang/String;

    .line 315
    .line 316
    if-eqz v2, :cond_8

    .line 317
    .line 318
    const-string v3, "Bearer "

    .line 319
    .line 320
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v2

    .line 324
    new-instance v3, Llx0/l;

    .line 325
    .line 326
    const-string v4, "Authorization"

    .line 327
    .line 328
    invoke-direct {v3, v4, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    filled-new-array {v3}, [Llx0/l;

    .line 332
    .line 333
    .line 334
    move-result-object v2

    .line 335
    invoke-static {v2}, Lmx0/x;->j([Llx0/l;)Ljava/util/HashMap;

    .line 336
    .line 337
    .line 338
    move-result-object v2

    .line 339
    move-object/from16 v18, v2

    .line 340
    .line 341
    goto :goto_2

    .line 342
    :cond_8
    const/16 v18, 0x0

    .line 343
    .line 344
    :goto_2
    new-instance v12, Llg0/c;

    .line 345
    .line 346
    const-string v17, ""

    .line 347
    .line 348
    move-object/from16 v16, v15

    .line 349
    .line 350
    invoke-direct/range {v12 .. v18}, Llg0/c;-><init>(Llg0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/HashMap;)V

    .line 351
    .line 352
    .line 353
    iget-object v2, v5, Lqd0/g;->f:Lkg0/a;

    .line 354
    .line 355
    invoke-virtual {v2, v12}, Lkg0/a;->a(Llg0/c;)Lyy0/m1;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    :goto_3
    const/4 v3, 0x0

    .line 360
    goto :goto_4

    .line 361
    :cond_9
    instance-of v4, v3, Lne0/c;

    .line 362
    .line 363
    if-eqz v4, :cond_a

    .line 364
    .line 365
    new-instance v2, Lyy0/m;

    .line 366
    .line 367
    invoke-direct {v2, v3, v9}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 368
    .line 369
    .line 370
    goto :goto_3

    .line 371
    :cond_a
    instance-of v3, v3, Lne0/d;

    .line 372
    .line 373
    if-eqz v3, :cond_c

    .line 374
    .line 375
    new-instance v3, Lyy0/m;

    .line 376
    .line 377
    invoke-direct {v3, v2, v9}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 378
    .line 379
    .line 380
    move-object v2, v3

    .line 381
    goto :goto_3

    .line 382
    :goto_4
    iput-object v3, v0, Lm70/u0;->f:Lyy0/j;

    .line 383
    .line 384
    iput-object v3, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 385
    .line 386
    iput-object v3, v0, Lm70/u0;->h:Lyy0/j;

    .line 387
    .line 388
    iput-object v3, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 389
    .line 390
    iput-object v3, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 391
    .line 392
    iput-object v3, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 393
    .line 394
    const/4 v3, 0x2

    .line 395
    iput v3, v0, Lm70/u0;->e:I

    .line 396
    .line 397
    invoke-static {v10, v2, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    if-ne v0, v1, :cond_b

    .line 402
    .line 403
    :goto_5
    move-object v8, v1

    .line 404
    :cond_b
    :goto_6
    return-object v8

    .line 405
    :cond_c
    new-instance v0, La8/r0;

    .line 406
    .line 407
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 408
    .line 409
    .line 410
    throw v0

    .line 411
    :pswitch_0
    check-cast v5, Lm70/g1;

    .line 412
    .line 413
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 414
    .line 415
    iget v4, v0, Lm70/u0;->e:I

    .line 416
    .line 417
    if-eqz v4, :cond_f

    .line 418
    .line 419
    if-eq v4, v6, :cond_e

    .line 420
    .line 421
    const/4 v2, 0x2

    .line 422
    if-ne v4, v2, :cond_d

    .line 423
    .line 424
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 425
    .line 426
    .line 427
    goto/16 :goto_c

    .line 428
    .line 429
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 430
    .line 431
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 432
    .line 433
    .line 434
    throw v0

    .line 435
    :cond_e
    iget-object v2, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v2, Lm70/g1;

    .line 438
    .line 439
    iget-object v3, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast v3, Lm70/c1;

    .line 442
    .line 443
    iget-object v4, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v4, Lss0/b;

    .line 446
    .line 447
    iget-object v6, v0, Lm70/u0;->h:Lyy0/j;

    .line 448
    .line 449
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 450
    .line 451
    .line 452
    move-object v7, v6

    .line 453
    move-object/from16 v6, p1

    .line 454
    .line 455
    goto/16 :goto_8

    .line 456
    .line 457
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    iget-object v3, v0, Lm70/u0;->f:Lyy0/j;

    .line 461
    .line 462
    iget-object v4, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v4, Lne0/s;

    .line 465
    .line 466
    instance-of v7, v4, Lne0/e;

    .line 467
    .line 468
    if-eqz v7, :cond_13

    .line 469
    .line 470
    check-cast v4, Lne0/e;

    .line 471
    .line 472
    iget-object v2, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 473
    .line 474
    move-object v4, v2

    .line 475
    check-cast v4, Lss0/b;

    .line 476
    .line 477
    sget-object v2, Lss0/e;->L1:Lss0/e;

    .line 478
    .line 479
    invoke-static {v4, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 480
    .line 481
    .line 482
    move-result v7

    .line 483
    if-eqz v7, :cond_10

    .line 484
    .line 485
    goto :goto_7

    .line 486
    :cond_10
    sget-object v2, Lss0/e;->K1:Lss0/e;

    .line 487
    .line 488
    :goto_7
    invoke-static {v4, v2}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 489
    .line 490
    .line 491
    move-result-object v20

    .line 492
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 493
    .line 494
    .line 495
    move-result-object v7

    .line 496
    move-object/from16 v19, v7

    .line 497
    .line 498
    check-cast v19, Lm70/c1;

    .line 499
    .line 500
    invoke-static {v4, v2}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 501
    .line 502
    .line 503
    move-result-object v21

    .line 504
    const/16 v29, 0x0

    .line 505
    .line 506
    const/16 v30, 0x3fc

    .line 507
    .line 508
    const/16 v22, 0x0

    .line 509
    .line 510
    const/16 v23, 0x0

    .line 511
    .line 512
    const/16 v24, 0x0

    .line 513
    .line 514
    const/16 v25, 0x0

    .line 515
    .line 516
    const/16 v26, 0x0

    .line 517
    .line 518
    const/16 v27, 0x0

    .line 519
    .line 520
    const/16 v28, 0x0

    .line 521
    .line 522
    invoke-static/range {v19 .. v30}, Lm70/c1;->a(Lm70/c1;Llf0/i;Ler0/g;ZZZLjava/util/List;ZLl70/k;Ljava/lang/String;ZI)Lm70/c1;

    .line 523
    .line 524
    .line 525
    move-result-object v2

    .line 526
    invoke-virtual {v5, v2}, Lql0/j;->g(Lql0/h;)V

    .line 527
    .line 528
    .line 529
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    if-eq v2, v6, :cond_11

    .line 534
    .line 535
    const/4 v7, 0x2

    .line 536
    if-eq v2, v7, :cond_11

    .line 537
    .line 538
    const/4 v7, 0x3

    .line 539
    if-eq v2, v7, :cond_11

    .line 540
    .line 541
    new-instance v2, Lne0/e;

    .line 542
    .line 543
    invoke-direct {v2, v4}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 544
    .line 545
    .line 546
    new-instance v4, Lyy0/m;

    .line 547
    .line 548
    invoke-direct {v4, v2, v9}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 549
    .line 550
    .line 551
    goto :goto_9

    .line 552
    :cond_11
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 553
    .line 554
    .line 555
    move-result-object v2

    .line 556
    check-cast v2, Lm70/c1;

    .line 557
    .line 558
    iget-object v7, v5, Lm70/g1;->l:Lcs0/l;

    .line 559
    .line 560
    const/4 v9, 0x0

    .line 561
    iput-object v9, v0, Lm70/u0;->f:Lyy0/j;

    .line 562
    .line 563
    iput-object v9, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 564
    .line 565
    iput-object v3, v0, Lm70/u0;->h:Lyy0/j;

    .line 566
    .line 567
    iput-object v4, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 568
    .line 569
    iput-object v2, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 570
    .line 571
    iput-object v5, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 572
    .line 573
    iput v6, v0, Lm70/u0;->e:I

    .line 574
    .line 575
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 576
    .line 577
    .line 578
    invoke-virtual {v7, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v6

    .line 582
    if-ne v6, v1, :cond_12

    .line 583
    .line 584
    goto/16 :goto_b

    .line 585
    .line 586
    :cond_12
    move-object v7, v3

    .line 587
    move-object v3, v2

    .line 588
    move-object v2, v5

    .line 589
    :goto_8
    check-cast v6, Lqr0/s;

    .line 590
    .line 591
    sget-object v9, Lss0/e;->L1:Lss0/e;

    .line 592
    .line 593
    invoke-static {v4, v9}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 594
    .line 595
    .line 596
    move-result v4

    .line 597
    iget-object v5, v5, Lm70/g1;->h:Lij0/a;

    .line 598
    .line 599
    sget-object v9, Lm70/n0;->a:Ljava/util/List;

    .line 600
    .line 601
    const-string v9, "<this>"

    .line 602
    .line 603
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    const-string v9, "unitsType"

    .line 607
    .line 608
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    const-string v9, "stringResource"

    .line 612
    .line 613
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    sget-object v9, Lm70/n0;->a:Ljava/util/List;

    .line 617
    .line 618
    invoke-static {v3, v9, v6, v4, v5}, Lm70/s0;->a(Lm70/c1;Ljava/util/List;Lqr0/s;ZLij0/a;)Lm70/c1;

    .line 619
    .line 620
    .line 621
    move-result-object v19

    .line 622
    const/16 v29, 0x0

    .line 623
    .line 624
    const/16 v30, 0x233

    .line 625
    .line 626
    const/16 v20, 0x0

    .line 627
    .line 628
    const/16 v21, 0x0

    .line 629
    .line 630
    const/16 v22, 0x0

    .line 631
    .line 632
    const/16 v23, 0x0

    .line 633
    .line 634
    const/16 v24, 0x0

    .line 635
    .line 636
    const/16 v25, 0x0

    .line 637
    .line 638
    const/16 v26, 0x0

    .line 639
    .line 640
    const/16 v27, 0x0

    .line 641
    .line 642
    const/16 v28, 0x0

    .line 643
    .line 644
    invoke-static/range {v19 .. v30}, Lm70/c1;->a(Lm70/c1;Llf0/i;Ler0/g;ZZZLjava/util/List;ZLl70/k;Ljava/lang/String;ZI)Lm70/c1;

    .line 645
    .line 646
    .line 647
    move-result-object v3

    .line 648
    invoke-virtual {v2, v3}, Lql0/j;->g(Lql0/h;)V

    .line 649
    .line 650
    .line 651
    sget-object v4, Lyy0/h;->d:Lyy0/h;

    .line 652
    .line 653
    move-object v3, v7

    .line 654
    :goto_9
    const/4 v9, 0x0

    .line 655
    goto :goto_a

    .line 656
    :cond_13
    instance-of v5, v4, Lne0/c;

    .line 657
    .line 658
    if-eqz v5, :cond_14

    .line 659
    .line 660
    new-instance v2, Lyy0/m;

    .line 661
    .line 662
    invoke-direct {v2, v4, v9}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 663
    .line 664
    .line 665
    move-object v4, v2

    .line 666
    goto :goto_9

    .line 667
    :cond_14
    instance-of v4, v4, Lne0/d;

    .line 668
    .line 669
    if-eqz v4, :cond_16

    .line 670
    .line 671
    new-instance v4, Lyy0/m;

    .line 672
    .line 673
    invoke-direct {v4, v2, v9}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 674
    .line 675
    .line 676
    goto :goto_9

    .line 677
    :goto_a
    iput-object v9, v0, Lm70/u0;->f:Lyy0/j;

    .line 678
    .line 679
    iput-object v9, v0, Lm70/u0;->g:Ljava/lang/Object;

    .line 680
    .line 681
    iput-object v9, v0, Lm70/u0;->h:Lyy0/j;

    .line 682
    .line 683
    iput-object v9, v0, Lm70/u0;->k:Ljava/lang/Object;

    .line 684
    .line 685
    iput-object v9, v0, Lm70/u0;->l:Ljava/lang/Object;

    .line 686
    .line 687
    iput-object v9, v0, Lm70/u0;->j:Ljava/lang/Object;

    .line 688
    .line 689
    const/4 v2, 0x2

    .line 690
    iput v2, v0, Lm70/u0;->e:I

    .line 691
    .line 692
    invoke-static {v3, v4, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 693
    .line 694
    .line 695
    move-result-object v0

    .line 696
    if-ne v0, v1, :cond_15

    .line 697
    .line 698
    :goto_b
    move-object v8, v1

    .line 699
    :cond_15
    :goto_c
    return-object v8

    .line 700
    :cond_16
    new-instance v0, La8/r0;

    .line 701
    .line 702
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 703
    .line 704
    .line 705
    throw v0

    .line 706
    nop

    .line 707
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
