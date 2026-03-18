.class public final Ll2/k;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ll2/l;


# direct methods
.method public constructor <init>(Ll2/l;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll2/k;->j:Ll2/l;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Ll2/k;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/k;->j:Ll2/l;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Ll2/k;-><init>(Ll2/l;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Ll2/k;->i:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky0/k;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ll2/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ll2/k;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ll2/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Ll2/k;->j:Ll2/l;

    .line 2
    .line 3
    iget-object v1, v0, Ll2/l;->d:Landroidx/collection/l0;

    .line 4
    .line 5
    iget-object v2, v0, Ll2/l;->f:Landroidx/collection/a0;

    .line 6
    .line 7
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v4, p0, Ll2/k;->h:I

    .line 10
    .line 11
    const/4 v5, 0x1

    .line 12
    if-eqz v4, :cond_1

    .line 13
    .line 14
    if-ne v4, v5, :cond_0

    .line 15
    .line 16
    iget v4, p0, Ll2/k;->g:I

    .line 17
    .line 18
    iget v6, p0, Ll2/k;->f:I

    .line 19
    .line 20
    iget v7, p0, Ll2/k;->e:I

    .line 21
    .line 22
    iget-object v8, p0, Ll2/k;->i:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v8, Lky0/k;

    .line 25
    .line 26
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, p0, Ll2/k;->i:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v8, p1

    .line 44
    check-cast v8, Lky0/k;

    .line 45
    .line 46
    const/4 v4, 0x0

    .line 47
    move v6, v4

    .line 48
    move v7, v6

    .line 49
    :goto_0
    iget p1, v0, Ll2/l;->g:I

    .line 50
    .line 51
    iget v9, v2, Landroidx/collection/a0;->b:I

    .line 52
    .line 53
    invoke-static {p1, v9}, Ljava/lang/Math;->min(II)I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-ge v7, p1, :cond_2

    .line 58
    .line 59
    add-int/lit8 p1, v7, 0x1

    .line 60
    .line 61
    invoke-virtual {v2, v7}, Landroidx/collection/a0;->c(I)I

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    const/16 v10, 0x20

    .line 66
    .line 67
    packed-switch v9, :pswitch_data_0

    .line 68
    .line 69
    .line 70
    const-string v0, "unknown op: "

    .line 71
    .line 72
    invoke-static {v9, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    goto/16 :goto_2

    .line 77
    .line 78
    :pswitch_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v2, "reuse "

    .line 81
    .line 82
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object v0, v0, Ll2/l;->e:Landroidx/collection/l0;

    .line 86
    .line 87
    add-int/lit8 v2, v4, 0x1

    .line 88
    .line 89
    invoke-virtual {v0, v4}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    move v4, v2

    .line 101
    goto/16 :goto_2

    .line 102
    .line 103
    :pswitch_1
    add-int/lit8 v0, v6, 0x1

    .line 104
    .line 105
    invoke-virtual {v1, v6}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const-string v9, "null cannot be cast to non-null type @[ExtensionFunctionType] kotlin.Function2<kotlin.Any?, kotlin.Any?, kotlin.Unit>"

    .line 110
    .line 111
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    const/4 v9, 0x2

    .line 115
    invoke-static {v9, v2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    check-cast v2, Lay0/n;

    .line 119
    .line 120
    add-int/lit8 v6, v6, 0x2

    .line 121
    .line 122
    invoke-virtual {v1, v0}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    new-instance v1, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    const-string v9, "apply "

    .line 129
    .line 130
    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    goto/16 :goto_2

    .line 147
    .line 148
    :pswitch_2
    add-int/lit8 v0, v7, 0x2

    .line 149
    .line 150
    invoke-virtual {v2, p1}, Landroidx/collection/a0;->c(I)I

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    add-int/lit8 v2, v6, 0x1

    .line 155
    .line 156
    invoke-virtual {v1, v6}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    new-instance v6, Ljava/lang/StringBuilder;

    .line 161
    .line 162
    const-string v9, "insertTopDown "

    .line 163
    .line 164
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v6, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    :goto_1
    move v6, v0

    .line 181
    move-object v0, p1

    .line 182
    move p1, v6

    .line 183
    move v6, v2

    .line 184
    goto/16 :goto_2

    .line 185
    .line 186
    :pswitch_3
    add-int/lit8 v0, v7, 0x2

    .line 187
    .line 188
    invoke-virtual {v2, p1}, Landroidx/collection/a0;->c(I)I

    .line 189
    .line 190
    .line 191
    move-result p1

    .line 192
    add-int/lit8 v2, v6, 0x1

    .line 193
    .line 194
    invoke-virtual {v1, v6}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    new-instance v6, Ljava/lang/StringBuilder;

    .line 199
    .line 200
    const-string v9, "insertBottomUp "

    .line 201
    .line 202
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    invoke-virtual {v6, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    goto :goto_1

    .line 219
    :pswitch_4
    const-string v0, "clear"

    .line 220
    .line 221
    goto :goto_2

    .line 222
    :pswitch_5
    add-int/lit8 v0, v7, 0x2

    .line 223
    .line 224
    invoke-virtual {v2, p1}, Landroidx/collection/a0;->c(I)I

    .line 225
    .line 226
    .line 227
    move-result p1

    .line 228
    add-int/lit8 v1, v7, 0x3

    .line 229
    .line 230
    invoke-virtual {v2, v0}, Landroidx/collection/a0;->c(I)I

    .line 231
    .line 232
    .line 233
    move-result v0

    .line 234
    add-int/lit8 v9, v7, 0x4

    .line 235
    .line 236
    invoke-virtual {v2, v1}, Landroidx/collection/a0;->c(I)I

    .line 237
    .line 238
    .line 239
    move-result v1

    .line 240
    new-instance v2, Ljava/lang/StringBuilder;

    .line 241
    .line 242
    const-string v11, "move "

    .line 243
    .line 244
    invoke-direct {v2, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 248
    .line 249
    .line 250
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    move p1, v9

    .line 267
    goto :goto_2

    .line 268
    :pswitch_6
    add-int/lit8 v0, v7, 0x2

    .line 269
    .line 270
    invoke-virtual {v2, p1}, Landroidx/collection/a0;->c(I)I

    .line 271
    .line 272
    .line 273
    move-result p1

    .line 274
    add-int/lit8 v1, v7, 0x3

    .line 275
    .line 276
    invoke-virtual {v2, v0}, Landroidx/collection/a0;->c(I)I

    .line 277
    .line 278
    .line 279
    move-result v0

    .line 280
    new-instance v2, Ljava/lang/StringBuilder;

    .line 281
    .line 282
    const-string v9, "remove "

    .line 283
    .line 284
    invoke-direct {v2, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 288
    .line 289
    .line 290
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    move p1, v1

    .line 301
    goto :goto_2

    .line 302
    :pswitch_7
    add-int/lit8 v0, v6, 0x1

    .line 303
    .line 304
    invoke-virtual {v1, v6}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    const-string v2, "down "

    .line 309
    .line 310
    invoke-static {v1, v2}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    move v6, v0

    .line 315
    move-object v0, v1

    .line 316
    goto :goto_2

    .line 317
    :pswitch_8
    const-string v0, "up"

    .line 318
    .line 319
    :goto_2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 325
    .line 326
    .line 327
    const-string v2, ": "

    .line 328
    .line 329
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 330
    .line 331
    .line 332
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 333
    .line 334
    .line 335
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 336
    .line 337
    .line 338
    move-result-object v0

    .line 339
    iput-object v8, p0, Ll2/k;->i:Ljava/lang/Object;

    .line 340
    .line 341
    iput p1, p0, Ll2/k;->e:I

    .line 342
    .line 343
    iput v6, p0, Ll2/k;->f:I

    .line 344
    .line 345
    iput v4, p0, Ll2/k;->g:I

    .line 346
    .line 347
    iput v5, p0, Ll2/k;->h:I

    .line 348
    .line 349
    invoke-virtual {v8, v0, p0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 350
    .line 351
    .line 352
    return-object v3

    .line 353
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 354
    .line 355
    return-object p0

    .line 356
    nop

    .line 357
    :pswitch_data_0
    .packed-switch 0x0
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
