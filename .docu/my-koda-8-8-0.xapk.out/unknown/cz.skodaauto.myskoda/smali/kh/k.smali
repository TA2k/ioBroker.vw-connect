.class public final Lkh/k;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lai/e;

.field public final e:Ljh/b;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;

.field public h:Lzg/t;


# direct methods
.method public constructor <init>(Lai/e;Ljh/b;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkh/k;->d:Lai/e;

    .line 5
    .line 6
    iput-object p2, p0, Lkh/k;->e:Ljh/b;

    .line 7
    .line 8
    new-instance v0, Lkh/i;

    .line 9
    .line 10
    const/4 v6, 0x0

    .line 11
    const/16 v7, 0x1ff

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    invoke-direct/range {v0 .. v7}, Lkh/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lkh/k;->f:Lyy0/c2;

    .line 26
    .line 27
    new-instance p2, Lyy0/l1;

    .line 28
    .line 29
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 30
    .line 31
    .line 32
    iput-object p2, p0, Lkh/k;->g:Lyy0/l1;

    .line 33
    .line 34
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    new-instance p2, Lkh/j;

    .line 39
    .line 40
    const/4 v0, 0x1

    .line 41
    invoke-direct {p2, p0, v1, v0}, Lkh/j;-><init>(Lkh/k;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x3

    .line 45
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public static a(Lkh/k;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 14

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lkh/i;

    .line 12
    .line 13
    iget-object v0, v0, Lkh/i;->a:Ljava/lang/String;

    .line 14
    .line 15
    move-object v2, v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move-object v2, p1

    .line 18
    :goto_0
    and-int/lit8 v0, p6, 0x2

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 23
    .line 24
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lkh/i;

    .line 29
    .line 30
    iget-object v0, v0, Lkh/i;->b:Ljava/lang/String;

    .line 31
    .line 32
    move-object v3, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-object/from16 v3, p2

    .line 35
    .line 36
    :goto_1
    and-int/lit8 v0, p6, 0x4

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 41
    .line 42
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lkh/i;

    .line 47
    .line 48
    iget-object v0, v0, Lkh/i;->c:Ljava/lang/String;

    .line 49
    .line 50
    move-object v4, v0

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move-object/from16 v4, p3

    .line 53
    .line 54
    :goto_2
    and-int/lit8 v0, p6, 0x8

    .line 55
    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 59
    .line 60
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Lkh/i;

    .line 65
    .line 66
    iget-object v0, v0, Lkh/i;->d:Ljava/lang/String;

    .line 67
    .line 68
    move-object v5, v0

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    move-object/from16 v5, p4

    .line 71
    .line 72
    :goto_3
    and-int/lit8 v0, p6, 0x10

    .line 73
    .line 74
    if-eqz v0, :cond_4

    .line 75
    .line 76
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 77
    .line 78
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    check-cast v0, Lkh/i;

    .line 83
    .line 84
    iget-object v0, v0, Lkh/i;->e:Ljava/lang/String;

    .line 85
    .line 86
    move-object v6, v0

    .line 87
    goto :goto_4

    .line 88
    :cond_4
    move-object/from16 v6, p5

    .line 89
    .line 90
    :goto_4
    iget-object v0, p0, Lkh/k;->f:Lyy0/c2;

    .line 91
    .line 92
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Lkh/i;

    .line 97
    .line 98
    iget-boolean v7, v0, Lkh/i;->f:Z

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    const/4 v1, 0x1

    .line 108
    const/4 v8, 0x0

    .line 109
    if-lez v0, :cond_5

    .line 110
    .line 111
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-lez v0, :cond_5

    .line 116
    .line 117
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    if-lez v0, :cond_5

    .line 122
    .line 123
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    if-lez v0, :cond_5

    .line 128
    .line 129
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-lez v0, :cond_5

    .line 134
    .line 135
    move v0, v1

    .line 136
    goto :goto_5

    .line 137
    :cond_5
    move v0, v8

    .line 138
    :goto_5
    iget-object v9, p0, Lkh/k;->h:Lzg/t;

    .line 139
    .line 140
    const/4 v10, 0x0

    .line 141
    if-eqz v9, :cond_6

    .line 142
    .line 143
    iget-object v9, v9, Lzg/t;->d:Ljava/lang/String;

    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_6
    move-object v9, v10

    .line 147
    :goto_6
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v9

    .line 151
    if-eqz v9, :cond_11

    .line 152
    .line 153
    iget-object v9, p0, Lkh/k;->h:Lzg/t;

    .line 154
    .line 155
    if-eqz v9, :cond_7

    .line 156
    .line 157
    iget-object v9, v9, Lzg/t;->e:Ljava/lang/String;

    .line 158
    .line 159
    goto :goto_7

    .line 160
    :cond_7
    move-object v9, v10

    .line 161
    :goto_7
    invoke-static {v9, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v9

    .line 165
    if-eqz v9, :cond_11

    .line 166
    .line 167
    iget-object v9, p0, Lkh/k;->h:Lzg/t;

    .line 168
    .line 169
    if-eqz v9, :cond_8

    .line 170
    .line 171
    iget-object v9, v9, Lzg/t;->f:Ljava/lang/String;

    .line 172
    .line 173
    goto :goto_8

    .line 174
    :cond_8
    move-object v9, v10

    .line 175
    :goto_8
    invoke-static {v9, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v9

    .line 179
    if-eqz v9, :cond_11

    .line 180
    .line 181
    iget-object v9, p0, Lkh/k;->h:Lzg/t;

    .line 182
    .line 183
    if-eqz v9, :cond_9

    .line 184
    .line 185
    iget-object v11, v9, Lzg/t;->g:Ljava/lang/String;

    .line 186
    .line 187
    goto :goto_9

    .line 188
    :cond_9
    move-object v11, v10

    .line 189
    :goto_9
    if-eqz v9, :cond_a

    .line 190
    .line 191
    iget-object v9, v9, Lzg/t;->a:Ljava/util/List;

    .line 192
    .line 193
    goto :goto_a

    .line 194
    :cond_a
    move-object v9, v10

    .line 195
    :goto_a
    if-nez v9, :cond_b

    .line 196
    .line 197
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    .line 198
    .line 199
    :cond_b
    check-cast v9, Ljava/lang/Iterable;

    .line 200
    .line 201
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 202
    .line 203
    .line 204
    move-result-object v9

    .line 205
    :cond_c
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 206
    .line 207
    .line 208
    move-result v12

    .line 209
    if-eqz v12, :cond_d

    .line 210
    .line 211
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v12

    .line 215
    move-object v13, v12

    .line 216
    check-cast v13, Lzg/n;

    .line 217
    .line 218
    iget-object v13, v13, Lzg/n;->b:Ljava/lang/String;

    .line 219
    .line 220
    invoke-static {v13, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v13

    .line 224
    if-eqz v13, :cond_c

    .line 225
    .line 226
    goto :goto_b

    .line 227
    :cond_d
    move-object v12, v10

    .line 228
    :goto_b
    check-cast v12, Lzg/n;

    .line 229
    .line 230
    if-eqz v12, :cond_e

    .line 231
    .line 232
    iget-object v9, v12, Lzg/n;->a:Ljava/lang/String;

    .line 233
    .line 234
    goto :goto_c

    .line 235
    :cond_e
    move-object v9, v10

    .line 236
    :goto_c
    invoke-static {v11, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v9

    .line 240
    if-eqz v9, :cond_11

    .line 241
    .line 242
    iget-object v9, p0, Lkh/k;->h:Lzg/t;

    .line 243
    .line 244
    if-eqz v9, :cond_f

    .line 245
    .line 246
    iget-object v10, v9, Lzg/t;->c:Ljava/lang/String;

    .line 247
    .line 248
    :cond_f
    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v9

    .line 252
    if-nez v9, :cond_10

    .line 253
    .line 254
    goto :goto_d

    .line 255
    :cond_10
    move v9, v8

    .line 256
    goto :goto_e

    .line 257
    :cond_11
    :goto_d
    move v9, v1

    .line 258
    :goto_e
    if-eqz v0, :cond_12

    .line 259
    .line 260
    if-eqz v9, :cond_12

    .line 261
    .line 262
    move v9, v1

    .line 263
    goto :goto_f

    .line 264
    :cond_12
    move v9, v8

    .line 265
    :goto_f
    iget-object p0, p0, Lkh/k;->f:Lyy0/c2;

    .line 266
    .line 267
    :cond_13
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    move-object v1, v0

    .line 272
    check-cast v1, Lkh/i;

    .line 273
    .line 274
    const/4 v8, 0x0

    .line 275
    const/16 v10, 0x100

    .line 276
    .line 277
    invoke-static/range {v1 .. v10}, Lkh/i;->a(Lkh/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLkh/a;ZI)Lkh/i;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v0

    .line 285
    if-eqz v0, :cond_13

    .line 286
    .line 287
    return-void
.end method
