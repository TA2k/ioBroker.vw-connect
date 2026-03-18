.class public final Llz0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llz0/m;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:I

.field public final c:Z


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz0/g;->a:Ljava/util/List;

    .line 5
    .line 6
    check-cast p1, Ljava/lang/Iterable;

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const/4 v0, 0x0

    .line 13
    move v1, v0

    .line 14
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Llz0/d;

    .line 26
    .line 27
    iget-object v2, v2, Llz0/d;->a:Ljava/lang/Integer;

    .line 28
    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    :cond_0
    add-int/2addr v1, v3

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    iput v1, p0, Llz0/g;->b:I

    .line 38
    .line 39
    iget-object p1, p0, Llz0/g;->a:Ljava/util/List;

    .line 40
    .line 41
    check-cast p1, Ljava/lang/Iterable;

    .line 42
    .line 43
    instance-of v1, p1, Ljava/util/Collection;

    .line 44
    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    move-object v1, p1

    .line 48
    check-cast v1, Ljava/util/Collection;

    .line 49
    .line 50
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_3

    .line 55
    .line 56
    :cond_2
    move p1, v0

    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_2

    .line 67
    .line 68
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Llz0/d;

    .line 73
    .line 74
    iget-object v1, v1, Llz0/d;->a:Ljava/lang/Integer;

    .line 75
    .line 76
    if-nez v1, :cond_4

    .line 77
    .line 78
    move p1, v3

    .line 79
    :goto_1
    iput-boolean p1, p0, Llz0/g;->c:Z

    .line 80
    .line 81
    iget-object p1, p0, Llz0/g;->a:Ljava/util/List;

    .line 82
    .line 83
    check-cast p1, Ljava/lang/Iterable;

    .line 84
    .line 85
    instance-of v1, p1, Ljava/util/Collection;

    .line 86
    .line 87
    if-eqz v1, :cond_6

    .line 88
    .line 89
    move-object v1, p1

    .line 90
    check-cast v1, Ljava/util/Collection;

    .line 91
    .line 92
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-eqz v1, :cond_6

    .line 97
    .line 98
    :cond_5
    move p1, v3

    .line 99
    goto :goto_4

    .line 100
    :cond_6
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    :cond_7
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-eqz v1, :cond_5

    .line 109
    .line 110
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    check-cast v1, Llz0/d;

    .line 115
    .line 116
    iget-object v1, v1, Llz0/d;->a:Ljava/lang/Integer;

    .line 117
    .line 118
    if-eqz v1, :cond_8

    .line 119
    .line 120
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    goto :goto_2

    .line 125
    :cond_8
    const v1, 0x7fffffff

    .line 126
    .line 127
    .line 128
    :goto_2
    if-lez v1, :cond_9

    .line 129
    .line 130
    move v1, v3

    .line 131
    goto :goto_3

    .line 132
    :cond_9
    move v1, v0

    .line 133
    :goto_3
    if-nez v1, :cond_7

    .line 134
    .line 135
    move p1, v0

    .line 136
    :goto_4
    if-eqz p1, :cond_15

    .line 137
    .line 138
    iget-object p1, p0, Llz0/g;->a:Ljava/util/List;

    .line 139
    .line 140
    check-cast p1, Ljava/lang/Iterable;

    .line 141
    .line 142
    instance-of v1, p1, Ljava/util/Collection;

    .line 143
    .line 144
    if-eqz v1, :cond_a

    .line 145
    .line 146
    move-object v1, p1

    .line 147
    check-cast v1, Ljava/util/Collection;

    .line 148
    .line 149
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-eqz v1, :cond_a

    .line 154
    .line 155
    move v1, v0

    .line 156
    goto :goto_7

    .line 157
    :cond_a
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    move v1, v0

    .line 162
    :cond_b
    :goto_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 163
    .line 164
    .line 165
    move-result v2

    .line 166
    if-eqz v2, :cond_e

    .line 167
    .line 168
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    check-cast v2, Llz0/d;

    .line 173
    .line 174
    iget-object v2, v2, Llz0/d;->a:Ljava/lang/Integer;

    .line 175
    .line 176
    if-nez v2, :cond_c

    .line 177
    .line 178
    move v2, v3

    .line 179
    goto :goto_6

    .line 180
    :cond_c
    move v2, v0

    .line 181
    :goto_6
    if-eqz v2, :cond_b

    .line 182
    .line 183
    add-int/lit8 v1, v1, 0x1

    .line 184
    .line 185
    if-ltz v1, :cond_d

    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_d
    invoke-static {}, Ljp/k1;->q()V

    .line 189
    .line 190
    .line 191
    const/4 p0, 0x0

    .line 192
    throw p0

    .line 193
    :cond_e
    :goto_7
    if-gt v1, v3, :cond_f

    .line 194
    .line 195
    move p1, v3

    .line 196
    goto :goto_8

    .line 197
    :cond_f
    move p1, v0

    .line 198
    :goto_8
    if-nez p1, :cond_14

    .line 199
    .line 200
    iget-object p0, p0, Llz0/g;->a:Ljava/util/List;

    .line 201
    .line 202
    check-cast p0, Ljava/lang/Iterable;

    .line 203
    .line 204
    new-instance p1, Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 207
    .line 208
    .line 209
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    :cond_10
    :goto_9
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    if-eqz v1, :cond_12

    .line 218
    .line 219
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    move-object v2, v1

    .line 224
    check-cast v2, Llz0/d;

    .line 225
    .line 226
    iget-object v2, v2, Llz0/d;->a:Ljava/lang/Integer;

    .line 227
    .line 228
    if-nez v2, :cond_11

    .line 229
    .line 230
    move v2, v3

    .line 231
    goto :goto_a

    .line 232
    :cond_11
    move v2, v0

    .line 233
    :goto_a
    if-eqz v2, :cond_10

    .line 234
    .line 235
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    goto :goto_9

    .line 239
    :cond_12
    new-instance p0, Ljava/util/ArrayList;

    .line 240
    .line 241
    const/16 v0, 0xa

    .line 242
    .line 243
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 244
    .line 245
    .line 246
    move-result v0

    .line 247
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    :goto_b
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 255
    .line 256
    .line 257
    move-result v0

    .line 258
    if-eqz v0, :cond_13

    .line 259
    .line 260
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    check-cast v0, Llz0/d;

    .line 265
    .line 266
    iget-object v0, v0, Llz0/d;->b:Ljava/lang/String;

    .line 267
    .line 268
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 269
    .line 270
    .line 271
    goto :goto_b

    .line 272
    :cond_13
    new-instance p1, Ljava/lang/StringBuilder;

    .line 273
    .line 274
    const-string v0, "At most one variable-length numeric field in a row is allowed, but got several: "

    .line 275
    .line 276
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 280
    .line 281
    .line 282
    const-string p0, ". Parsing is undefined: for example, with variable-length month number and variable-length day of month, \'111\' can be parsed as Jan 11th or Nov 1st."

    .line 283
    .line 284
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 285
    .line 286
    .line 287
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 292
    .line 293
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    throw p1

    .line 301
    :cond_14
    return-void

    .line 302
    :cond_15
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 303
    .line 304
    const-string p1, "Failed requirement."

    .line 305
    .line 306
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw p0
.end method


# virtual methods
.method public final a(Llz0/c;Ljava/lang/CharSequence;I)Ljava/lang/Object;
    .locals 10

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Llz0/g;->b:I

    .line 7
    .line 8
    add-int v1, p3, v0

    .line 9
    .line 10
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-le v1, v2, :cond_0

    .line 15
    .line 16
    new-instance p1, Lh50/q0;

    .line 17
    .line 18
    const/16 p2, 0x1b

    .line 19
    .line 20
    invoke-direct {p1, p0, p2}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Llz0/h;

    .line 24
    .line 25
    invoke-direct {p0, p3, p1}, Llz0/h;-><init>(ILay0/a;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    new-instance v1, Lkotlin/jvm/internal/d0;

    .line 30
    .line 31
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 35
    .line 36
    add-int/2addr v2, p3

    .line 37
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-ge v2, v3, :cond_1

    .line 42
    .line 43
    iget v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 44
    .line 45
    add-int/2addr v2, p3

    .line 46
    invoke-interface {p2, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    invoke-static {v2}, Liz0/b;->a(C)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    iget v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 57
    .line 58
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    iput v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    iget v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 64
    .line 65
    if-ge v2, v0, :cond_2

    .line 66
    .line 67
    new-instance p1, Llk/j;

    .line 68
    .line 69
    const/4 p2, 0x2

    .line 70
    invoke-direct {p1, p2, v1, p0}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    new-instance p0, Llz0/h;

    .line 74
    .line 75
    invoke-direct {p0, p3, p1}, Llz0/h;-><init>(ILay0/a;)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :cond_2
    iget-object v2, p0, Llz0/g;->a:Ljava/util/List;

    .line 80
    .line 81
    move-object v3, v2

    .line 82
    check-cast v3, Ljava/util/Collection;

    .line 83
    .line 84
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    const/4 v4, 0x0

    .line 89
    move v5, v4

    .line 90
    :goto_1
    if-ge v5, v3, :cond_5

    .line 91
    .line 92
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Llz0/d;

    .line 97
    .line 98
    iget-object v4, v4, Llz0/d;->a:Ljava/lang/Integer;

    .line 99
    .line 100
    if-eqz v4, :cond_3

    .line 101
    .line 102
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    goto :goto_2

    .line 107
    :cond_3
    iget v4, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 108
    .line 109
    sub-int/2addr v4, v0

    .line 110
    add-int/lit8 v4, v4, 0x1

    .line 111
    .line 112
    :goto_2
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    check-cast v6, Llz0/d;

    .line 117
    .line 118
    add-int/2addr v4, p3

    .line 119
    invoke-virtual {v6, p1, p2, p3, v4}, Llz0/d;->a(Ljava/lang/Object;Ljava/lang/CharSequence;II)Llz0/f;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    if-eqz v9, :cond_4

    .line 124
    .line 125
    invoke-interface {p2, p3, v4}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    new-instance v4, Lh2/w4;

    .line 134
    .line 135
    const/4 v6, 0x1

    .line 136
    move-object v8, p0

    .line 137
    invoke-direct/range {v4 .. v9}, Lh2/w4;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    new-instance p0, Llz0/h;

    .line 141
    .line 142
    invoke-direct {p0, p3, v4}, Llz0/h;-><init>(ILay0/a;)V

    .line 143
    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_4
    move-object v8, p0

    .line 147
    add-int/lit8 v5, v5, 0x1

    .line 148
    .line 149
    move p3, v4

    .line 150
    goto :goto_1

    .line 151
    :cond_5
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Llz0/g;->a:Ljava/util/List;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    const/16 v2, 0xa

    .line 8
    .line 9
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Llz0/d;

    .line 31
    .line 32
    new-instance v3, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 35
    .line 36
    .line 37
    iget-object v4, v2, Llz0/d;->a:Ljava/lang/Integer;

    .line 38
    .line 39
    if-nez v4, :cond_0

    .line 40
    .line 41
    const-string v4, "at least one digit"

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    new-instance v5, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v4, " digits"

    .line 53
    .line 54
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    :goto_1
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v4, " for "

    .line 65
    .line 66
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v2, v2, Llz0/d;->b:Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    invoke-interface {v1, v2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    iget-boolean v0, p0, Llz0/g;->c:Z

    .line 83
    .line 84
    const-string v2, " digits: "

    .line 85
    .line 86
    iget p0, p0, Llz0/g;->b:I

    .line 87
    .line 88
    if-eqz v0, :cond_2

    .line 89
    .line 90
    new-instance v0, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    const-string v3, "a number with at least "

    .line 93
    .line 94
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0

    .line 111
    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 112
    .line 113
    const-string v3, "a number with exactly "

    .line 114
    .line 115
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Llz0/g;->b()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
