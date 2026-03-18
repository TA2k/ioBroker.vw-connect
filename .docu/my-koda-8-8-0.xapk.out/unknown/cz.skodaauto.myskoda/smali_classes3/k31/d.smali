.class public final Lk31/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/a;


# direct methods
.method public constructor <init>(Lf31/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/d;->a:Lf31/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lk31/c;)V
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    iget-object v1, v0, Lk31/c;->c:Ljava/util/List;

    .line 4
    .line 5
    check-cast v1, Ljava/lang/Iterable;

    .line 6
    .line 7
    new-instance v2, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/16 v3, 0xa

    .line 10
    .line 11
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    const-string v5, "<this>"

    .line 27
    .line 28
    if-eqz v4, :cond_0

    .line 29
    .line 30
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    check-cast v4, Li31/a0;

    .line 35
    .line 36
    iget-object v6, v4, Li31/a0;->a:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v6, Li31/h0;

    .line 39
    .line 40
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v5, Li31/g0;

    .line 44
    .line 45
    iget v7, v6, Li31/h0;->b:I

    .line 46
    .line 47
    iget-object v6, v6, Li31/h0;->a:Ljava/lang/String;

    .line 48
    .line 49
    invoke-direct {v5, v7, v6}, Li31/g0;-><init>(ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-boolean v4, v4, Li31/a0;->b:Z

    .line 53
    .line 54
    new-instance v6, Li31/a0;

    .line 55
    .line 56
    invoke-direct {v6, v5, v4}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    iget-object v1, v0, Lk31/c;->d:Ljava/util/List;

    .line 64
    .line 65
    check-cast v1, Ljava/lang/Iterable;

    .line 66
    .line 67
    new-instance v4, Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    if-eqz v6, :cond_1

    .line 85
    .line 86
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    check-cast v6, Li31/a0;

    .line 91
    .line 92
    iget-object v7, v6, Li31/a0;->a:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v7, Li31/y;

    .line 95
    .line 96
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v8, Li31/z;

    .line 100
    .line 101
    iget v9, v7, Li31/y;->c:I

    .line 102
    .line 103
    iget v10, v7, Li31/y;->a:I

    .line 104
    .line 105
    iget-object v7, v7, Li31/y;->b:Ljava/lang/String;

    .line 106
    .line 107
    invoke-direct {v8, v9, v10, v7}, Li31/z;-><init>(IILjava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-boolean v6, v6, Li31/a0;->b:Z

    .line 111
    .line 112
    new-instance v7, Li31/a0;

    .line 113
    .line 114
    invoke-direct {v7, v8, v6}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    iget-object v1, v0, Lk31/c;->b:Ljava/util/List;

    .line 122
    .line 123
    check-cast v1, Ljava/lang/Iterable;

    .line 124
    .line 125
    new-instance v6, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 128
    .line 129
    .line 130
    move-result v7

    .line 131
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    if-eqz v7, :cond_3

    .line 143
    .line 144
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    check-cast v7, Li31/a0;

    .line 149
    .line 150
    iget-object v8, v7, Li31/a0;->a:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v8, Li31/e;

    .line 153
    .line 154
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    iget-object v10, v8, Li31/e;->a:Ljava/lang/String;

    .line 158
    .line 159
    iget-object v11, v8, Li31/e;->b:Ljava/lang/String;

    .line 160
    .line 161
    iget-object v12, v8, Li31/e;->g:Ljava/lang/String;

    .line 162
    .line 163
    iget-object v13, v8, Li31/e;->h:Ljava/lang/String;

    .line 164
    .line 165
    iget-object v14, v8, Li31/e;->e:Li31/f;

    .line 166
    .line 167
    iget-object v8, v8, Li31/e;->d:Ljava/util/List;

    .line 168
    .line 169
    check-cast v8, Ljava/lang/Iterable;

    .line 170
    .line 171
    new-instance v15, Ljava/util/ArrayList;

    .line 172
    .line 173
    invoke-static {v8, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 174
    .line 175
    .line 176
    move-result v9

    .line 177
    invoke-direct {v15, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 178
    .line 179
    .line 180
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 181
    .line 182
    .line 183
    move-result-object v8

    .line 184
    :goto_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 185
    .line 186
    .line 187
    move-result v9

    .line 188
    if-eqz v9, :cond_2

    .line 189
    .line 190
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v9

    .line 194
    check-cast v9, Li31/c;

    .line 195
    .line 196
    new-instance v3, Li31/f0;

    .line 197
    .line 198
    move-object/from16 v17, v1

    .line 199
    .line 200
    iget-object v1, v9, Li31/c;->b:Ljava/lang/String;

    .line 201
    .line 202
    iget-object v9, v9, Li31/c;->c:Ljava/lang/String;

    .line 203
    .line 204
    invoke-direct {v3, v1, v9}, Li31/f0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-object/from16 v1, v17

    .line 211
    .line 212
    const/16 v3, 0xa

    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_2
    move-object/from16 v17, v1

    .line 216
    .line 217
    new-instance v9, Li31/c0;

    .line 218
    .line 219
    invoke-direct/range {v9 .. v15}, Li31/c0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Li31/f;Ljava/util/ArrayList;)V

    .line 220
    .line 221
    .line 222
    iget-boolean v1, v7, Li31/a0;->b:Z

    .line 223
    .line 224
    new-instance v3, Li31/a0;

    .line 225
    .line 226
    invoke-direct {v3, v9, v1}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-object/from16 v1, v17

    .line 233
    .line 234
    const/16 v3, 0xa

    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_3
    iget-object v1, v0, Lk31/c;->a:Ljava/util/List;

    .line 238
    .line 239
    check-cast v1, Ljava/lang/Iterable;

    .line 240
    .line 241
    new-instance v3, Ljava/util/ArrayList;

    .line 242
    .line 243
    const/16 v7, 0xa

    .line 244
    .line 245
    invoke-static {v1, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 246
    .line 247
    .line 248
    move-result v7

    .line 249
    invoke-direct {v3, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 250
    .line 251
    .line 252
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 257
    .line 258
    .line 259
    move-result v7

    .line 260
    if-eqz v7, :cond_4

    .line 261
    .line 262
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v7

    .line 266
    check-cast v7, Li31/a0;

    .line 267
    .line 268
    iget-object v8, v7, Li31/a0;->a:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast v8, Li31/u;

    .line 271
    .line 272
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    new-instance v9, Li31/v;

    .line 276
    .line 277
    iget v10, v8, Li31/u;->a:I

    .line 278
    .line 279
    invoke-virtual {v8}, Li31/u;->a()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object v8

    .line 283
    invoke-direct {v9, v10, v8}, Li31/v;-><init>(ILjava/lang/String;)V

    .line 284
    .line 285
    .line 286
    iget-boolean v7, v7, Li31/a0;->b:Z

    .line 287
    .line 288
    new-instance v8, Li31/a0;

    .line 289
    .line 290
    invoke-direct {v8, v9, v7}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 294
    .line 295
    .line 296
    goto :goto_4

    .line 297
    :cond_4
    new-instance v12, Li31/b0;

    .line 298
    .line 299
    invoke-direct {v12, v2, v4, v6, v3}, Li31/b0;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 300
    .line 301
    .line 302
    iget-object v15, v0, Lk31/c;->e:Ljava/lang/String;

    .line 303
    .line 304
    new-instance v10, Li31/b;

    .line 305
    .line 306
    const/4 v11, 0x0

    .line 307
    const/4 v13, 0x0

    .line 308
    const/4 v14, 0x0

    .line 309
    const/16 v16, 0x0

    .line 310
    .line 311
    const/16 v17, 0x0

    .line 312
    .line 313
    invoke-direct/range {v10 .. v17}, Li31/b;-><init>(Ljava/lang/String;Li31/b0;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    move-object/from16 v0, p0

    .line 317
    .line 318
    iget-object v0, v0, Lk31/d;->a:Lf31/a;

    .line 319
    .line 320
    iget-object v0, v0, Lf31/a;->a:Lb31/a;

    .line 321
    .line 322
    invoke-virtual {v0, v10}, Lb31/a;->a(Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lk31/c;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lk31/d;->a(Lk31/c;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
