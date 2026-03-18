.class public final Ldn/c;
.super Ldn/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Lxm/f;

.field public final B:Ljava/util/ArrayList;

.field public final C:Landroid/graphics/RectF;

.field public final D:Landroid/graphics/RectF;

.field public final E:Landroid/graphics/RectF;

.field public final F:Lgn/g;

.field public final G:Lb11/a;

.field public H:F

.field public I:Z

.field public final J:Lxm/g;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;Ljava/util/List;Lum/a;)V
    .locals 10

    .line 1
    invoke-direct {p0, p1, p2}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ldn/c;->B:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/RectF;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ldn/c;->C:Landroid/graphics/RectF;

    .line 17
    .line 18
    new-instance v0, Landroid/graphics/RectF;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Ldn/c;->D:Landroid/graphics/RectF;

    .line 24
    .line 25
    new-instance v0, Landroid/graphics/RectF;

    .line 26
    .line 27
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Ldn/c;->E:Landroid/graphics/RectF;

    .line 31
    .line 32
    new-instance v0, Lgn/g;

    .line 33
    .line 34
    invoke-direct {v0}, Lgn/g;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Ldn/c;->F:Lgn/g;

    .line 38
    .line 39
    new-instance v0, Lb11/a;

    .line 40
    .line 41
    const/4 v1, 0x4

    .line 42
    const/4 v2, 0x0

    .line 43
    invoke-direct {v0, v2, v1}, Lb11/a;-><init>(BI)V

    .line 44
    .line 45
    .line 46
    iput-object v0, p0, Ldn/c;->G:Lb11/a;

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    iput-boolean v0, p0, Ldn/c;->I:Z

    .line 50
    .line 51
    iget-object p2, p2, Ldn/e;->s:Lbn/b;

    .line 52
    .line 53
    const/4 v1, 0x0

    .line 54
    if-eqz p2, :cond_0

    .line 55
    .line 56
    invoke-virtual {p2}, Lbn/b;->b0()Lxm/f;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    iput-object p2, p0, Ldn/c;->A:Lxm/f;

    .line 61
    .line 62
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    iput-object v1, p0, Ldn/c;->A:Lxm/f;

    .line 70
    .line 71
    :goto_0
    new-instance p2, Landroidx/collection/u;

    .line 72
    .line 73
    iget-object v2, p4, Lum/a;->j:Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    invoke-direct {p2, v2}, Landroidx/collection/u;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    sub-int/2addr v2, v0

    .line 87
    move-object v3, v1

    .line 88
    :goto_1
    const/4 v4, 0x0

    .line 89
    if-ltz v2, :cond_a

    .line 90
    .line 91
    invoke-interface {p3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Ldn/e;

    .line 96
    .line 97
    iget v6, v5, Ldn/e;->e:I

    .line 98
    .line 99
    invoke-static {v6}, Lu/w;->o(I)I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    const/4 v7, 0x2

    .line 104
    if-eqz v6, :cond_6

    .line 105
    .line 106
    if-eq v6, v0, :cond_5

    .line 107
    .line 108
    if-eq v6, v7, :cond_4

    .line 109
    .line 110
    const/4 v8, 0x3

    .line 111
    if-eq v6, v8, :cond_3

    .line 112
    .line 113
    const/4 v8, 0x4

    .line 114
    if-eq v6, v8, :cond_2

    .line 115
    .line 116
    const/4 v8, 0x5

    .line 117
    if-eq v6, v8, :cond_1

    .line 118
    .line 119
    iget v6, v5, Ldn/e;->e:I

    .line 120
    .line 121
    packed-switch v6, :pswitch_data_0

    .line 122
    .line 123
    .line 124
    const-string v6, "null"

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :pswitch_0
    const-string v6, "UNKNOWN"

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :pswitch_1
    const-string v6, "TEXT"

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :pswitch_2
    const-string v6, "SHAPE"

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :pswitch_3
    const-string v6, "NULL"

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :pswitch_4
    const-string v6, "IMAGE"

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :pswitch_5
    const-string v6, "SOLID"

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :pswitch_6
    const-string v6, "PRE_COMP"

    .line 146
    .line 147
    :goto_2
    const-string v8, "Unknown layer type "

    .line 148
    .line 149
    invoke-virtual {v8, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    invoke-static {v6}, Lgn/c;->a(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    move-object v6, v1

    .line 157
    goto :goto_3

    .line 158
    :cond_1
    new-instance v6, Ldn/k;

    .line 159
    .line 160
    invoke-direct {v6, p1, v5}, Ldn/k;-><init>(Lum/j;Ldn/e;)V

    .line 161
    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_2
    new-instance v6, Ldn/g;

    .line 165
    .line 166
    invoke-direct {v6, p1, v5, p0, p4}, Ldn/g;-><init>(Lum/j;Ldn/e;Ldn/c;Lum/a;)V

    .line 167
    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_3
    new-instance v6, Ldn/f;

    .line 171
    .line 172
    invoke-direct {v6, p1, v5}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 173
    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_4
    new-instance v6, Ldn/d;

    .line 177
    .line 178
    invoke-direct {v6, p1, v5}, Ldn/d;-><init>(Lum/j;Ldn/e;)V

    .line 179
    .line 180
    .line 181
    goto :goto_3

    .line 182
    :cond_5
    new-instance v6, Ldn/h;

    .line 183
    .line 184
    invoke-direct {v6, p1, v5}, Ldn/h;-><init>(Lum/j;Ldn/e;)V

    .line 185
    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_6
    new-instance v6, Ldn/c;

    .line 189
    .line 190
    iget-object v8, v5, Ldn/e;->g:Ljava/lang/String;

    .line 191
    .line 192
    iget-object v9, p4, Lum/a;->c:Ljava/util/HashMap;

    .line 193
    .line 194
    invoke-virtual {v9, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v8

    .line 198
    check-cast v8, Ljava/util/List;

    .line 199
    .line 200
    invoke-direct {v6, p1, v5, v8, p4}, Ldn/c;-><init>(Lum/j;Ldn/e;Ljava/util/List;Lum/a;)V

    .line 201
    .line 202
    .line 203
    :goto_3
    if-nez v6, :cond_7

    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_7
    iget-object v8, v6, Ldn/b;->p:Ldn/e;

    .line 207
    .line 208
    iget-wide v8, v8, Ldn/e;->d:J

    .line 209
    .line 210
    invoke-virtual {p2, v8, v9, v6}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    if-eqz v3, :cond_8

    .line 214
    .line 215
    iput-object v6, v3, Ldn/b;->s:Ldn/b;

    .line 216
    .line 217
    move-object v3, v1

    .line 218
    goto :goto_4

    .line 219
    :cond_8
    iget-object v8, p0, Ldn/c;->B:Ljava/util/ArrayList;

    .line 220
    .line 221
    invoke-virtual {v8, v4, v6}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    iget v4, v5, Ldn/e;->u:I

    .line 225
    .line 226
    invoke-static {v4}, Lu/w;->o(I)I

    .line 227
    .line 228
    .line 229
    move-result v4

    .line 230
    if-eq v4, v0, :cond_9

    .line 231
    .line 232
    if-eq v4, v7, :cond_9

    .line 233
    .line 234
    goto :goto_4

    .line 235
    :cond_9
    move-object v3, v6

    .line 236
    :goto_4
    add-int/lit8 v2, v2, -0x1

    .line 237
    .line 238
    goto/16 :goto_1

    .line 239
    .line 240
    :cond_a
    :goto_5
    invoke-virtual {p2}, Landroidx/collection/u;->h()I

    .line 241
    .line 242
    .line 243
    move-result p1

    .line 244
    if-ge v4, p1, :cond_d

    .line 245
    .line 246
    invoke-virtual {p2, v4}, Landroidx/collection/u;->d(I)J

    .line 247
    .line 248
    .line 249
    move-result-wide p3

    .line 250
    invoke-virtual {p2, p3, p4}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    check-cast p1, Ldn/b;

    .line 255
    .line 256
    if-nez p1, :cond_b

    .line 257
    .line 258
    goto :goto_6

    .line 259
    :cond_b
    iget-object p3, p1, Ldn/b;->p:Ldn/e;

    .line 260
    .line 261
    iget-wide p3, p3, Ldn/e;->f:J

    .line 262
    .line 263
    invoke-virtual {p2, p3, p4}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object p3

    .line 267
    check-cast p3, Ldn/b;

    .line 268
    .line 269
    if-eqz p3, :cond_c

    .line 270
    .line 271
    iput-object p3, p1, Ldn/b;->t:Ldn/b;

    .line 272
    .line 273
    :cond_c
    :goto_6
    add-int/lit8 v4, v4, 0x1

    .line 274
    .line 275
    goto :goto_5

    .line 276
    :cond_d
    iget-object p1, p0, Ldn/b;->p:Ldn/e;

    .line 277
    .line 278
    iget-object p1, p1, Ldn/e;->x:Landroidx/lifecycle/c1;

    .line 279
    .line 280
    if-eqz p1, :cond_e

    .line 281
    .line 282
    new-instance p2, Lxm/g;

    .line 283
    .line 284
    invoke-direct {p2, p0, p0, p1}, Lxm/g;-><init>(Ldn/b;Ldn/b;Landroidx/lifecycle/c1;)V

    .line 285
    .line 286
    .line 287
    iput-object p2, p0, Ldn/c;->J:Lxm/g;

    .line 288
    .line 289
    :cond_e
    return-void

    .line 290
    nop

    .line 291
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 4

    .line 1
    invoke-super {p0, p1, p2, p3}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Ldn/c;->B:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result p3

    .line 10
    const/4 v0, 0x1

    .line 11
    sub-int/2addr p3, v0

    .line 12
    :goto_0
    if-ltz p3, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Ldn/c;->C:Landroid/graphics/RectF;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-virtual {v1, v2, v2, v2, v2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ldn/b;

    .line 25
    .line 26
    iget-object v3, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-virtual {v2, v1, v3, v0}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v1}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 32
    .line 33
    .line 34
    add-int/lit8 p3, p3, -0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-void
.end method

.method public final h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ldn/c;->J:Lxm/g;

    .line 3
    .line 4
    const/4 v2, 0x1

    .line 5
    if-nez p4, :cond_1

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move v3, v0

    .line 11
    goto :goto_1

    .line 12
    :cond_1
    :goto_0
    move v3, v2

    .line 13
    :goto_1
    iget-object v4, p0, Ldn/b;->o:Lum/j;

    .line 14
    .line 15
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    if-eqz v3, :cond_2

    .line 19
    .line 20
    iget-boolean v3, v4, Lum/j;->n:Z

    .line 21
    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    move v0, v2

    .line 25
    :cond_2
    if-eqz v0, :cond_3

    .line 26
    .line 27
    const/16 v3, 0xff

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_3
    move v3, p3

    .line 31
    :goto_2
    if-eqz v1, :cond_4

    .line 32
    .line 33
    invoke-virtual {v1, p2, v3}, Lxm/g;->b(Landroid/graphics/Matrix;I)Lgn/a;

    .line 34
    .line 35
    .line 36
    move-result-object p4

    .line 37
    :cond_4
    iget-boolean v1, p0, Ldn/c;->I:Z

    .line 38
    .line 39
    iget-object v4, p0, Ldn/b;->p:Ldn/e;

    .line 40
    .line 41
    iget-object v5, p0, Ldn/c;->B:Ljava/util/ArrayList;

    .line 42
    .line 43
    iget-object v6, p0, Ldn/c;->D:Landroid/graphics/RectF;

    .line 44
    .line 45
    if-nez v1, :cond_5

    .line 46
    .line 47
    const-string v1, "__container"

    .line 48
    .line 49
    iget-object v7, v4, Ldn/e;->c:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v1, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_5

    .line 56
    .line 57
    invoke-virtual {v6}, Landroid/graphics/RectF;->setEmpty()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-eqz v4, :cond_6

    .line 69
    .line 70
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    check-cast v4, Ldn/b;

    .line 75
    .line 76
    iget-object v7, p0, Ldn/c;->E:Landroid/graphics/RectF;

    .line 77
    .line 78
    invoke-virtual {v4, v7, p2, v2}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6, v7}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 82
    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_5
    iget v1, v4, Ldn/e;->o:F

    .line 86
    .line 87
    iget v4, v4, Ldn/e;->p:F

    .line 88
    .line 89
    const/4 v7, 0x0

    .line 90
    invoke-virtual {v6, v7, v7, v1, v4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2, v6}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 94
    .line 95
    .line 96
    :cond_6
    iget-object v1, p0, Ldn/c;->F:Lgn/g;

    .line 97
    .line 98
    if-eqz v0, :cond_9

    .line 99
    .line 100
    iget-object p0, p0, Ldn/c;->G:Lb11/a;

    .line 101
    .line 102
    const/4 v4, 0x0

    .line 103
    iput-object v4, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 104
    .line 105
    iput p3, p0, Lb11/a;->e:I

    .line 106
    .line 107
    if-eqz p4, :cond_8

    .line 108
    .line 109
    iget p3, p4, Lgn/a;->d:I

    .line 110
    .line 111
    invoke-static {p3}, Landroid/graphics/Color;->alpha(I)I

    .line 112
    .line 113
    .line 114
    move-result p3

    .line 115
    if-lez p3, :cond_7

    .line 116
    .line 117
    iput-object p4, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_7
    iput-object v4, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 121
    .line 122
    :goto_4
    move-object p4, v4

    .line 123
    :cond_8
    invoke-virtual {v1, p1, v6, p0}, Lgn/g;->e(Landroid/graphics/Canvas;Landroid/graphics/RectF;Lb11/a;)Landroid/graphics/Canvas;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    goto :goto_5

    .line 128
    :cond_9
    move-object p0, p1

    .line 129
    :goto_5
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 130
    .line 131
    .line 132
    invoke-virtual {p1, v6}, Landroid/graphics/Canvas;->clipRect(Landroid/graphics/RectF;)Z

    .line 133
    .line 134
    .line 135
    move-result p3

    .line 136
    if-eqz p3, :cond_a

    .line 137
    .line 138
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 139
    .line 140
    .line 141
    move-result p3

    .line 142
    sub-int/2addr p3, v2

    .line 143
    :goto_6
    if-ltz p3, :cond_a

    .line 144
    .line 145
    invoke-virtual {v5, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Ldn/b;

    .line 150
    .line 151
    invoke-virtual {v2, p0, p2, v3, p4}, Ldn/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 152
    .line 153
    .line 154
    add-int/lit8 p3, p3, -0x1

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_a
    if-eqz v0, :cond_b

    .line 158
    .line 159
    invoke-virtual {v1}, Lgn/g;->c()V

    .line 160
    .line 161
    .line 162
    :cond_b
    invoke-virtual {p1}, Landroid/graphics/Canvas;->restore()V

    .line 163
    .line 164
    .line 165
    return-void
.end method

.method public final l(F)V
    .locals 5

    .line 1
    iput p1, p0, Ldn/c;->H:F

    .line 2
    .line 3
    invoke-super {p0, p1}, Ldn/b;->l(F)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldn/b;->p:Ldn/e;

    .line 7
    .line 8
    iget-object v1, p0, Ldn/c;->A:Lxm/f;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object p1, p0, Ldn/b;->o:Lum/j;

    .line 13
    .line 14
    iget-object p1, p1, Lum/j;->d:Lum/a;

    .line 15
    .line 16
    iget v2, p1, Lum/a;->m:F

    .line 17
    .line 18
    iget p1, p1, Lum/a;->l:F

    .line 19
    .line 20
    sub-float/2addr v2, p1

    .line 21
    const p1, 0x3c23d70a    # 0.01f

    .line 22
    .line 23
    .line 24
    add-float/2addr v2, p1

    .line 25
    iget-object p1, v0, Ldn/e;->b:Lum/a;

    .line 26
    .line 27
    iget p1, p1, Lum/a;->l:F

    .line 28
    .line 29
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ljava/lang/Float;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    iget-object v4, v0, Ldn/e;->b:Lum/a;

    .line 40
    .line 41
    iget v4, v4, Lum/a;->n:F

    .line 42
    .line 43
    mul-float/2addr v3, v4

    .line 44
    sub-float/2addr v3, p1

    .line 45
    div-float p1, v3, v2

    .line 46
    .line 47
    :cond_0
    if-nez v1, :cond_1

    .line 48
    .line 49
    iget v1, v0, Ldn/e;->n:F

    .line 50
    .line 51
    iget-object v2, v0, Ldn/e;->b:Lum/a;

    .line 52
    .line 53
    iget v3, v2, Lum/a;->m:F

    .line 54
    .line 55
    iget v2, v2, Lum/a;->l:F

    .line 56
    .line 57
    sub-float/2addr v3, v2

    .line 58
    div-float/2addr v1, v3

    .line 59
    sub-float/2addr p1, v1

    .line 60
    :cond_1
    iget v1, v0, Ldn/e;->m:F

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    cmpl-float v1, v1, v2

    .line 64
    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    const-string v1, "__container"

    .line 68
    .line 69
    iget-object v2, v0, Ldn/e;->c:Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_2

    .line 76
    .line 77
    iget v0, v0, Ldn/e;->m:F

    .line 78
    .line 79
    div-float/2addr p1, v0

    .line 80
    :cond_2
    iget-object p0, p0, Ldn/c;->B:Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    add-int/lit8 v0, v0, -0x1

    .line 87
    .line 88
    :goto_0
    if-ltz v0, :cond_3

    .line 89
    .line 90
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Ldn/b;

    .line 95
    .line 96
    invoke-virtual {v1, p1}, Ldn/b;->l(F)V

    .line 97
    .line 98
    .line 99
    add-int/lit8 v0, v0, -0x1

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_3
    return-void
.end method
