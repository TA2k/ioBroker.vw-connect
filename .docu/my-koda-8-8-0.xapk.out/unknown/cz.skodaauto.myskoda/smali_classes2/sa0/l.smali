.class public final Lsa0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsa0/s;


# direct methods
.method public synthetic constructor <init>(Lsa0/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsa0/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/l;->e:Lsa0/s;

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
    .locals 13

    .line 1
    iget v0, p0, Lsa0/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    iget-object p0, p0, Lsa0/l;->e:Lsa0/s;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lsa0/p;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    const/16 v7, 0x3d

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    invoke-static/range {v0 .. v7}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    check-cast p1, Lcn0/c;

    .line 39
    .line 40
    iget-object p0, p0, Lsa0/l;->e:Lsa0/s;

    .line 41
    .line 42
    iget-object v0, p0, Lsa0/s;->i:Lij0/a;

    .line 43
    .line 44
    iget-object v1, p1, Lcn0/c;->b:Lcn0/b;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    if-eqz v1, :cond_5

    .line 53
    .line 54
    const/4 v3, 0x1

    .line 55
    const/4 v4, 0x0

    .line 56
    if-eq v1, v3, :cond_3

    .line 57
    .line 58
    const/4 v3, 0x2

    .line 59
    if-eq v1, v3, :cond_1

    .line 60
    .line 61
    const/4 v3, 0x3

    .line 62
    if-ne v1, v3, :cond_0

    .line 63
    .line 64
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    move-object v5, v1

    .line 69
    check-cast v5, Lsa0/p;

    .line 70
    .line 71
    const/4 v11, 0x0

    .line 72
    const/16 v12, 0x1f

    .line 73
    .line 74
    const/4 v6, 0x0

    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v9, 0x0

    .line 78
    const/4 v10, 0x0

    .line 79
    invoke-static/range {v5 .. v12}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    invoke-virtual {p0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lsa0/s;->p:Ljn0/c;

    .line 87
    .line 88
    new-array v1, v4, [Ljava/lang/Object;

    .line 89
    .line 90
    move-object v3, v0

    .line 91
    check-cast v3, Ljj0/f;

    .line 92
    .line 93
    const v4, 0x7f12038c

    .line 94
    .line 95
    .line 96
    invoke-virtual {v3, v4, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    invoke-static {p1, v0}, Ljp/fg;->b(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-static {p1, v0}, Ljp/fg;->a(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    new-instance v4, Lne0/c;

    .line 109
    .line 110
    new-instance v5, Ljava/lang/Exception;

    .line 111
    .line 112
    iget-object p1, p1, Lcn0/c;->c:Ljava/lang/String;

    .line 113
    .line 114
    invoke-direct {v5, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const/4 v8, 0x0

    .line 118
    const/16 v9, 0x1e

    .line 119
    .line 120
    const/4 v6, 0x0

    .line 121
    const/4 v7, 0x0

    .line 122
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 123
    .line 124
    .line 125
    new-instance p1, Lkn0/c;

    .line 126
    .line 127
    invoke-direct {p1, v3, v0, v1, v4}, Lkn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lne0/c;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p0, p1, p2}, Ljn0/c;->b(Lkn0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    if-ne p0, p1, :cond_6

    .line 137
    .line 138
    :goto_0
    move-object v2, p0

    .line 139
    goto/16 :goto_3

    .line 140
    .line 141
    :cond_0
    new-instance p0, La8/r0;

    .line 142
    .line 143
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 144
    .line 145
    .line 146
    throw p0

    .line 147
    :cond_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    move-object v3, v1

    .line 152
    check-cast v3, Lsa0/p;

    .line 153
    .line 154
    const/4 v9, 0x0

    .line 155
    const/16 v10, 0x1f

    .line 156
    .line 157
    const/4 v4, 0x0

    .line 158
    const/4 v5, 0x0

    .line 159
    const/4 v6, 0x0

    .line 160
    const/4 v7, 0x0

    .line 161
    const/4 v8, 0x0

    .line 162
    invoke-static/range {v3 .. v10}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-virtual {p0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 167
    .line 168
    .line 169
    iget-object p0, p0, Lsa0/s;->r:Lyt0/b;

    .line 170
    .line 171
    new-instance v3, Lzt0/a;

    .line 172
    .line 173
    invoke-static {p1, v0}, Ljp/fg;->g(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v4

    .line 177
    invoke-static {p1, v0}, Ljp/fg;->i(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    const/16 v5, 0x3c

    .line 182
    .line 183
    const/4 v7, 0x0

    .line 184
    invoke-direct/range {v3 .. v8}, Lzt0/a;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p0, v3, p2}, Lyt0/b;->b(Lzt0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    if-ne p0, p1, :cond_2

    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_2
    move-object p0, v2

    .line 197
    :goto_1
    if-ne p0, p1, :cond_6

    .line 198
    .line 199
    goto :goto_0

    .line 200
    :cond_3
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    move-object v5, v1

    .line 205
    check-cast v5, Lsa0/p;

    .line 206
    .line 207
    const/4 v11, 0x0

    .line 208
    const/16 v12, 0x1f

    .line 209
    .line 210
    const/4 v6, 0x0

    .line 211
    const/4 v7, 0x0

    .line 212
    const/4 v8, 0x0

    .line 213
    const/4 v9, 0x0

    .line 214
    const/4 v10, 0x0

    .line 215
    invoke-static/range {v5 .. v12}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-virtual {p0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 220
    .line 221
    .line 222
    iget-object p0, p0, Lsa0/s;->o:Lrq0/f;

    .line 223
    .line 224
    new-instance v1, Lsq0/c;

    .line 225
    .line 226
    invoke-static {p1, v0}, Ljp/fg;->g(Lcn0/c;Lij0/a;)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    const/4 v0, 0x6

    .line 231
    const/4 v3, 0x0

    .line 232
    invoke-direct {v1, v0, p1, v3, v3}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p0, v1, v4, p2}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 240
    .line 241
    if-ne p0, p1, :cond_4

    .line 242
    .line 243
    goto :goto_2

    .line 244
    :cond_4
    move-object p0, v2

    .line 245
    :goto_2
    if-ne p0, p1, :cond_6

    .line 246
    .line 247
    goto :goto_0

    .line 248
    :cond_5
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 249
    .line 250
    .line 251
    move-result-object p1

    .line 252
    move-object v3, p1

    .line 253
    check-cast v3, Lsa0/p;

    .line 254
    .line 255
    const/4 v9, 0x1

    .line 256
    const/16 v10, 0x1f

    .line 257
    .line 258
    const/4 v4, 0x0

    .line 259
    const/4 v5, 0x0

    .line 260
    const/4 v6, 0x0

    .line 261
    const/4 v7, 0x0

    .line 262
    const/4 v8, 0x0

    .line 263
    invoke-static/range {v3 .. v10}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 264
    .line 265
    .line 266
    move-result-object p1

    .line 267
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 268
    .line 269
    .line 270
    :cond_6
    :goto_3
    return-object v2

    .line 271
    :pswitch_1
    check-cast p1, Lss0/k;

    .line 272
    .line 273
    iget-object p0, p0, Lsa0/l;->e:Lsa0/s;

    .line 274
    .line 275
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 276
    .line 277
    .line 278
    move-result-object p2

    .line 279
    move-object v0, p2

    .line 280
    check-cast v0, Lsa0/p;

    .line 281
    .line 282
    const/4 p2, 0x0

    .line 283
    if-eqz p1, :cond_7

    .line 284
    .line 285
    iget-object v1, p1, Lss0/k;->i:Lss0/a0;

    .line 286
    .line 287
    if-eqz v1, :cond_7

    .line 288
    .line 289
    iget-object v1, v1, Lss0/a0;->a:Lss0/b;

    .line 290
    .line 291
    goto :goto_4

    .line 292
    :cond_7
    move-object v1, p2

    .line 293
    :goto_4
    sget-object v2, Lss0/e;->x1:Lss0/e;

    .line 294
    .line 295
    invoke-static {v1, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 296
    .line 297
    .line 298
    move-result v3

    .line 299
    if-eqz p1, :cond_8

    .line 300
    .line 301
    iget-object v1, p1, Lss0/k;->i:Lss0/a0;

    .line 302
    .line 303
    if-eqz v1, :cond_8

    .line 304
    .line 305
    iget-object p2, v1, Lss0/a0;->a:Lss0/b;

    .line 306
    .line 307
    :cond_8
    sget-object v1, Lss0/f;->w:Lss0/f;

    .line 308
    .line 309
    invoke-static {p2, v2, v1}, Llp/pf;->d(Lss0/b;Lss0/e;Lss0/f;)Z

    .line 310
    .line 311
    .line 312
    move-result p2

    .line 313
    xor-int/lit8 v4, p2, 0x1

    .line 314
    .line 315
    if-eqz p1, :cond_a

    .line 316
    .line 317
    iget-object p1, p1, Lss0/k;->b:Ljava/lang/String;

    .line 318
    .line 319
    if-nez p1, :cond_9

    .line 320
    .line 321
    goto :goto_6

    .line 322
    :cond_9
    :goto_5
    move-object v5, p1

    .line 323
    goto :goto_7

    .line 324
    :cond_a
    :goto_6
    const-string p1, ""

    .line 325
    .line 326
    goto :goto_5

    .line 327
    :goto_7
    const/4 v6, 0x0

    .line 328
    const/16 v7, 0x23

    .line 329
    .line 330
    const/4 v1, 0x0

    .line 331
    const/4 v2, 0x0

    .line 332
    invoke-static/range {v0 .. v7}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 333
    .line 334
    .line 335
    move-result-object p1

    .line 336
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 337
    .line 338
    .line 339
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 340
    .line 341
    return-object p0

    .line 342
    nop

    .line 343
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
