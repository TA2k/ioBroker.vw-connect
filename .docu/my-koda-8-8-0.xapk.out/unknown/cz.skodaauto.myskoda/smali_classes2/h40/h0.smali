.class public final synthetic Lh40/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/j0;


# direct methods
.method public synthetic constructor <init>(Lh40/j0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/h0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/h0;->e:Lh40/j0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 9

    .line 1
    iget v0, p0, Lh40/h0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onCollectBadge(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Lh40/j0;

    .line 13
    .line 14
    iget-object v5, p0, Lh40/h0;->e:Lh40/j0;

    .line 15
    .line 16
    const-string v6, "onCollectBadge"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onBadgeDetail(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Lh40/j0;

    .line 29
    .line 30
    iget-object v6, p0, Lh40/h0;->e:Lh40/j0;

    .line 31
    .line 32
    const-string v7, "onBadgeDetail"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/h0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v0, v0, Lh40/h0;->e:Lh40/j0;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lne0/s;

    .line 15
    .line 16
    instance-of v3, v1, Lne0/d;

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v3, v1

    .line 25
    check-cast v3, Lh40/i0;

    .line 26
    .line 27
    const/16 v17, 0x0

    .line 28
    .line 29
    const/16 v18, 0x3ff7

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x1

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const/4 v11, 0x0

    .line 39
    const/4 v12, 0x0

    .line 40
    const/4 v13, 0x0

    .line 41
    const/4 v14, 0x0

    .line 42
    const/4 v15, 0x0

    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    invoke-static/range {v3 .. v18}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    instance-of v3, v1, Lne0/e;

    .line 54
    .line 55
    if-eqz v3, :cond_1

    .line 56
    .line 57
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    move-object v3, v1

    .line 62
    check-cast v3, Lh40/i0;

    .line 63
    .line 64
    const/16 v17, 0x0

    .line 65
    .line 66
    const/16 v18, 0x3ff7

    .line 67
    .line 68
    const/4 v4, 0x0

    .line 69
    const/4 v5, 0x0

    .line 70
    const/4 v6, 0x0

    .line 71
    const/4 v7, 0x0

    .line 72
    const/4 v8, 0x0

    .line 73
    const/4 v9, 0x0

    .line 74
    const/4 v10, 0x0

    .line 75
    const/4 v11, 0x0

    .line 76
    const/4 v12, 0x0

    .line 77
    const/4 v13, 0x0

    .line 78
    const/4 v14, 0x0

    .line 79
    const/4 v15, 0x0

    .line 80
    const/16 v16, 0x0

    .line 81
    .line 82
    invoke-static/range {v3 .. v18}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 87
    .line 88
    .line 89
    iget-object v0, v0, Lh40/j0;->q:Lf40/b2;

    .line 90
    .line 91
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_1
    instance-of v3, v1, Lne0/c;

    .line 96
    .line 97
    if-eqz v3, :cond_2

    .line 98
    .line 99
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    move-object v4, v3

    .line 104
    check-cast v4, Lh40/i0;

    .line 105
    .line 106
    check-cast v1, Lne0/c;

    .line 107
    .line 108
    iget-object v3, v0, Lh40/j0;->o:Lij0/a;

    .line 109
    .line 110
    invoke-static {v1, v3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    const/16 v18, 0x0

    .line 115
    .line 116
    const/16 v19, 0x3ff6

    .line 117
    .line 118
    const/4 v6, 0x0

    .line 119
    const/4 v7, 0x0

    .line 120
    const/4 v8, 0x0

    .line 121
    const/4 v9, 0x0

    .line 122
    const/4 v10, 0x0

    .line 123
    const/4 v11, 0x0

    .line 124
    const/4 v12, 0x0

    .line 125
    const/4 v13, 0x0

    .line 126
    const/4 v14, 0x0

    .line 127
    const/4 v15, 0x0

    .line 128
    const/16 v16, 0x0

    .line 129
    .line 130
    const/16 v17, 0x0

    .line 131
    .line 132
    invoke-static/range {v4 .. v19}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 137
    .line 138
    .line 139
    :goto_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 140
    .line 141
    return-object v2

    .line 142
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    new-instance v0, La8/r0;

    .line 146
    .line 147
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 148
    .line 149
    .line 150
    throw v0

    .line 151
    :pswitch_0
    move-object/from16 v1, p1

    .line 152
    .line 153
    check-cast v1, Lne0/s;

    .line 154
    .line 155
    const-string v3, "data"

    .line 156
    .line 157
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    instance-of v3, v1, Lne0/d;

    .line 161
    .line 162
    if-eqz v3, :cond_3

    .line 163
    .line 164
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    move-object v3, v1

    .line 169
    check-cast v3, Lh40/i0;

    .line 170
    .line 171
    const/16 v17, 0x0

    .line 172
    .line 173
    const/16 v18, 0x3ffd

    .line 174
    .line 175
    const/4 v4, 0x0

    .line 176
    const/4 v5, 0x1

    .line 177
    const/4 v6, 0x0

    .line 178
    const/4 v7, 0x0

    .line 179
    const/4 v8, 0x0

    .line 180
    const/4 v9, 0x0

    .line 181
    const/4 v10, 0x0

    .line 182
    const/4 v11, 0x0

    .line 183
    const/4 v12, 0x0

    .line 184
    const/4 v13, 0x0

    .line 185
    const/4 v14, 0x0

    .line 186
    const/4 v15, 0x0

    .line 187
    const/16 v16, 0x0

    .line 188
    .line 189
    invoke-static/range {v3 .. v18}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 194
    .line 195
    .line 196
    goto :goto_1

    .line 197
    :cond_3
    instance-of v3, v1, Lne0/e;

    .line 198
    .line 199
    if-eqz v3, :cond_5

    .line 200
    .line 201
    check-cast v1, Lne0/e;

    .line 202
    .line 203
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v1, Lg40/i;

    .line 206
    .line 207
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    move-object v4, v3

    .line 212
    check-cast v4, Lh40/i0;

    .line 213
    .line 214
    iget-object v7, v1, Lg40/i;->a:Ljava/lang/String;

    .line 215
    .line 216
    new-instance v9, Ljava/net/URL;

    .line 217
    .line 218
    iget-object v3, v1, Lg40/i;->g:Ljava/lang/String;

    .line 219
    .line 220
    invoke-direct {v9, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    iget-object v10, v1, Lg40/i;->b:Ljava/lang/String;

    .line 224
    .line 225
    iget-object v11, v1, Lg40/i;->c:Ljava/lang/String;

    .line 226
    .line 227
    iget-object v12, v1, Lg40/i;->d:Ljava/lang/String;

    .line 228
    .line 229
    iget-object v13, v1, Lg40/i;->h:Lg40/l;

    .line 230
    .line 231
    iget-object v1, v1, Lg40/i;->f:Lg40/j;

    .line 232
    .line 233
    iget-object v15, v1, Lg40/j;->a:Ljava/lang/String;

    .line 234
    .line 235
    iget-object v14, v1, Lg40/j;->b:Lg40/k;

    .line 236
    .line 237
    iget-object v1, v13, Lg40/l;->d:Ljava/time/OffsetDateTime;

    .line 238
    .line 239
    iget-object v3, v0, Lh40/j0;->n:Lf40/c0;

    .line 240
    .line 241
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    check-cast v3, Ljava/lang/String;

    .line 246
    .line 247
    if-nez v3, :cond_4

    .line 248
    .line 249
    const-string v3, ""

    .line 250
    .line 251
    :cond_4
    move-object/from16 v17, v3

    .line 252
    .line 253
    const/16 v18, 0x0

    .line 254
    .line 255
    const/16 v19, 0x2009

    .line 256
    .line 257
    const/4 v5, 0x0

    .line 258
    const/4 v6, 0x0

    .line 259
    const/4 v8, 0x0

    .line 260
    move-object/from16 v16, v1

    .line 261
    .line 262
    invoke-static/range {v4 .. v19}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 267
    .line 268
    .line 269
    goto :goto_1

    .line 270
    :cond_5
    instance-of v3, v1, Lne0/c;

    .line 271
    .line 272
    if-eqz v3, :cond_6

    .line 273
    .line 274
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    move-object v4, v3

    .line 279
    check-cast v4, Lh40/i0;

    .line 280
    .line 281
    check-cast v1, Lne0/c;

    .line 282
    .line 283
    iget-object v3, v0, Lh40/j0;->o:Lij0/a;

    .line 284
    .line 285
    invoke-static {v1, v3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 286
    .line 287
    .line 288
    move-result-object v5

    .line 289
    const/16 v18, 0x0

    .line 290
    .line 291
    const/16 v19, 0x3ffc

    .line 292
    .line 293
    const/4 v6, 0x0

    .line 294
    const/4 v7, 0x0

    .line 295
    const/4 v8, 0x0

    .line 296
    const/4 v9, 0x0

    .line 297
    const/4 v10, 0x0

    .line 298
    const/4 v11, 0x0

    .line 299
    const/4 v12, 0x0

    .line 300
    const/4 v13, 0x0

    .line 301
    const/4 v14, 0x0

    .line 302
    const/4 v15, 0x0

    .line 303
    const/16 v16, 0x0

    .line 304
    .line 305
    const/16 v17, 0x0

    .line 306
    .line 307
    invoke-static/range {v4 .. v19}, Lh40/i0;->a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;

    .line 308
    .line 309
    .line 310
    move-result-object v1

    .line 311
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 312
    .line 313
    .line 314
    :goto_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 315
    .line 316
    return-object v2

    .line 317
    :cond_6
    new-instance v0, La8/r0;

    .line 318
    .line 319
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 320
    .line 321
    .line 322
    throw v0

    .line 323
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lh40/h0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lh40/h0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
