.class public final Lwm/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwm/l;
.implements Lxm/a;
.implements Lwm/c;


# instance fields
.field public final a:Landroid/graphics/Path;

.field public final b:Landroid/graphics/Path;

.field public final c:Landroid/graphics/PathMeasure;

.field public final d:[F

.field public final e:Lum/j;

.field public final f:I

.field public final g:Z

.field public final h:Z

.field public final i:Lxm/f;

.field public final j:Lxm/e;

.field public final k:Lxm/f;

.field public final l:Lxm/f;

.field public final m:Lxm/f;

.field public final n:Lxm/f;

.field public final o:Lxm/f;

.field public final p:Ld01/x;

.field public q:Z


# direct methods
.method public constructor <init>(Lum/j;Ldn/b;Lcn/h;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Path;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lwm/m;->a:Landroid/graphics/Path;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/Path;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lwm/m;->b:Landroid/graphics/Path;

    .line 17
    .line 18
    new-instance v0, Landroid/graphics/PathMeasure;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/graphics/PathMeasure;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lwm/m;->c:Landroid/graphics/PathMeasure;

    .line 24
    .line 25
    const/4 v0, 0x2

    .line 26
    new-array v0, v0, [F

    .line 27
    .line 28
    iput-object v0, p0, Lwm/m;->d:[F

    .line 29
    .line 30
    new-instance v0, Ld01/x;

    .line 31
    .line 32
    const/4 v1, 0x4

    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {v0, v2, v1}, Ld01/x;-><init>(BI)V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lwm/m;->p:Ld01/x;

    .line 38
    .line 39
    iput-object p1, p0, Lwm/m;->e:Lum/j;

    .line 40
    .line 41
    iget p1, p3, Lcn/h;->a:I

    .line 42
    .line 43
    iput p1, p0, Lwm/m;->f:I

    .line 44
    .line 45
    iget-boolean v0, p3, Lcn/h;->i:Z

    .line 46
    .line 47
    iput-boolean v0, p0, Lwm/m;->g:Z

    .line 48
    .line 49
    iget-boolean v0, p3, Lcn/h;->j:Z

    .line 50
    .line 51
    iput-boolean v0, p0, Lwm/m;->h:Z

    .line 52
    .line 53
    iget-object v0, p3, Lcn/h;->b:Lbn/b;

    .line 54
    .line 55
    invoke-virtual {v0}, Lbn/b;->b0()Lxm/f;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    iput-object v0, p0, Lwm/m;->i:Lxm/f;

    .line 60
    .line 61
    iget-object v1, p3, Lcn/h;->c:Lbn/f;

    .line 62
    .line 63
    invoke-interface {v1}, Lbn/f;->p()Lxm/e;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    iput-object v1, p0, Lwm/m;->j:Lxm/e;

    .line 68
    .line 69
    iget-object v2, p3, Lcn/h;->d:Lbn/b;

    .line 70
    .line 71
    invoke-virtual {v2}, Lbn/b;->b0()Lxm/f;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    iput-object v2, p0, Lwm/m;->k:Lxm/f;

    .line 76
    .line 77
    iget-object v3, p3, Lcn/h;->f:Lbn/b;

    .line 78
    .line 79
    invoke-virtual {v3}, Lbn/b;->b0()Lxm/f;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    iput-object v3, p0, Lwm/m;->m:Lxm/f;

    .line 84
    .line 85
    iget-object v4, p3, Lcn/h;->h:Lbn/b;

    .line 86
    .line 87
    invoke-virtual {v4}, Lbn/b;->b0()Lxm/f;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    iput-object v4, p0, Lwm/m;->o:Lxm/f;

    .line 92
    .line 93
    const/4 v5, 0x1

    .line 94
    if-ne p1, v5, :cond_0

    .line 95
    .line 96
    iget-object v6, p3, Lcn/h;->e:Lbn/b;

    .line 97
    .line 98
    invoke-virtual {v6}, Lbn/b;->b0()Lxm/f;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    iput-object v6, p0, Lwm/m;->l:Lxm/f;

    .line 103
    .line 104
    iget-object p3, p3, Lcn/h;->g:Lbn/b;

    .line 105
    .line 106
    invoke-virtual {p3}, Lbn/b;->b0()Lxm/f;

    .line 107
    .line 108
    .line 109
    move-result-object p3

    .line 110
    iput-object p3, p0, Lwm/m;->n:Lxm/f;

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_0
    const/4 p3, 0x0

    .line 114
    iput-object p3, p0, Lwm/m;->l:Lxm/f;

    .line 115
    .line 116
    iput-object p3, p0, Lwm/m;->n:Lxm/f;

    .line 117
    .line 118
    :goto_0
    invoke-virtual {p2, v0}, Ldn/b;->f(Lxm/e;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p2, v1}, Ldn/b;->f(Lxm/e;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p2, v2}, Ldn/b;->f(Lxm/e;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, v3}, Ldn/b;->f(Lxm/e;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p2, v4}, Ldn/b;->f(Lxm/e;)V

    .line 131
    .line 132
    .line 133
    if-ne p1, v5, :cond_1

    .line 134
    .line 135
    iget-object p3, p0, Lwm/m;->l:Lxm/f;

    .line 136
    .line 137
    invoke-virtual {p2, p3}, Ldn/b;->f(Lxm/e;)V

    .line 138
    .line 139
    .line 140
    iget-object p3, p0, Lwm/m;->n:Lxm/f;

    .line 141
    .line 142
    invoke-virtual {p2, p3}, Ldn/b;->f(Lxm/e;)V

    .line 143
    .line 144
    .line 145
    :cond_1
    invoke-virtual {v0, p0}, Lxm/e;->a(Lxm/a;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v3, p0}, Lxm/e;->a(Lxm/a;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v4, p0}, Lxm/e;->a(Lxm/a;)V

    .line 158
    .line 159
    .line 160
    if-ne p1, v5, :cond_2

    .line 161
    .line 162
    iget-object p1, p0, Lwm/m;->l:Lxm/f;

    .line 163
    .line 164
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 165
    .line 166
    .line 167
    iget-object p1, p0, Lwm/m;->n:Lxm/f;

    .line 168
    .line 169
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 170
    .line 171
    .line 172
    :cond_2
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lwm/m;->q:Z

    .line 3
    .line 4
    iget-object p0, p0, Lwm/m;->e:Lum/j;

    .line 5
    .line 6
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final b(Ljava/util/List;Ljava/util/List;)V
    .locals 3

    .line 1
    const/4 p2, 0x0

    .line 2
    :goto_0
    move-object v0, p1

    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-ge p2, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lwm/c;

    .line 16
    .line 17
    instance-of v1, v0, Lwm/s;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    check-cast v0, Lwm/s;

    .line 22
    .line 23
    iget v1, v0, Lwm/s;->c:I

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    if-ne v1, v2, :cond_0

    .line 27
    .line 28
    iget-object v1, p0, Lwm/m;->p:Ld01/x;

    .line 29
    .line 30
    iget-object v1, v1, Ld01/x;->b:Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, p0}, Lwm/s;->f(Lxm/a;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    add-int/lit8 p2, p2, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    return-void
.end method

.method public final d()Landroid/graphics/Path;
    .locals 42

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lwm/m;->q:Z

    .line 4
    .line 5
    iget-object v2, v0, Lwm/m;->a:Landroid/graphics/Path;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    return-object v2

    .line 10
    :cond_0
    invoke-virtual {v2}, Landroid/graphics/Path;->reset()V

    .line 11
    .line 12
    .line 13
    iget-boolean v1, v0, Lwm/m;->g:Z

    .line 14
    .line 15
    const/4 v9, 0x1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    iput-boolean v9, v0, Lwm/m;->q:Z

    .line 19
    .line 20
    return-object v2

    .line 21
    :cond_1
    iget v1, v0, Lwm/m;->f:I

    .line 22
    .line 23
    invoke-static {v1}, Lu/w;->o(I)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-object v10, v0, Lwm/m;->j:Lxm/e;

    .line 28
    .line 29
    iget-object v3, v0, Lwm/m;->m:Lxm/f;

    .line 30
    .line 31
    iget-object v5, v0, Lwm/m;->o:Lxm/f;

    .line 32
    .line 33
    const-wide v12, 0x4056800000000000L    # 90.0

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    const-wide/16 v14, 0x0

    .line 39
    .line 40
    iget-object v8, v0, Lwm/m;->k:Lxm/f;

    .line 41
    .line 42
    const/high16 v16, 0x42c80000    # 100.0f

    .line 43
    .line 44
    iget-object v4, v0, Lwm/m;->i:Lxm/f;

    .line 45
    .line 46
    const/16 v17, 0x0

    .line 47
    .line 48
    const-wide v18, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    const-wide/high16 v20, 0x3ff0000000000000L    # 1.0

    .line 54
    .line 55
    if-eqz v1, :cond_8

    .line 56
    .line 57
    if-eq v1, v9, :cond_2

    .line 58
    .line 59
    move/from16 v24, v9

    .line 60
    .line 61
    goto/16 :goto_12

    .line 62
    .line 63
    :cond_2
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, Ljava/lang/Float;

    .line 68
    .line 69
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    const-wide v22, 0x401921fb54442d18L    # 6.283185307179586

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    float-to-double v6, v1

    .line 79
    invoke-static {v6, v7}, Ljava/lang/Math;->floor(D)D

    .line 80
    .line 81
    .line 82
    move-result-wide v6

    .line 83
    double-to-int v1, v6

    .line 84
    if-nez v8, :cond_3

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_3
    invoke-virtual {v8}, Lxm/e;->d()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    check-cast v4, Ljava/lang/Float;

    .line 92
    .line 93
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    float-to-double v14, v4

    .line 98
    :goto_0
    sub-double/2addr v14, v12

    .line 99
    invoke-static {v14, v15}, Ljava/lang/Math;->toRadians(D)D

    .line 100
    .line 101
    .line 102
    move-result-wide v6

    .line 103
    int-to-double v12, v1

    .line 104
    div-double v14, v22, v12

    .line 105
    .line 106
    double-to-float v1, v14

    .line 107
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    check-cast v4, Ljava/lang/Float;

    .line 112
    .line 113
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    div-float v14, v4, v16

    .line 118
    .line 119
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    check-cast v3, Ljava/lang/Float;

    .line 124
    .line 125
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 126
    .line 127
    .line 128
    move-result v15

    .line 129
    float-to-double v3, v15

    .line 130
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 131
    .line 132
    .line 133
    move-result-wide v22

    .line 134
    move/from16 v24, v9

    .line 135
    .line 136
    move-object/from16 v25, v10

    .line 137
    .line 138
    mul-double v9, v22, v3

    .line 139
    .line 140
    double-to-float v5, v9

    .line 141
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 142
    .line 143
    .line 144
    move-result-wide v8

    .line 145
    mul-double/2addr v8, v3

    .line 146
    double-to-float v8, v8

    .line 147
    invoke-virtual {v2, v5, v8}, Landroid/graphics/Path;->moveTo(FF)V

    .line 148
    .line 149
    .line 150
    float-to-double v9, v1

    .line 151
    add-double/2addr v6, v9

    .line 152
    invoke-static {v12, v13}, Ljava/lang/Math;->ceil(D)D

    .line 153
    .line 154
    .line 155
    move-result-wide v12

    .line 156
    move-wide/from16 v22, v6

    .line 157
    .line 158
    const/4 v1, 0x0

    .line 159
    :goto_1
    int-to-double v6, v1

    .line 160
    cmpg-double v16, v6, v12

    .line 161
    .line 162
    if-gez v16, :cond_7

    .line 163
    .line 164
    invoke-static/range {v22 .. v23}, Ljava/lang/Math;->cos(D)D

    .line 165
    .line 166
    .line 167
    move-result-wide v26

    .line 168
    move-wide/from16 v29, v12

    .line 169
    .line 170
    mul-double v11, v26, v3

    .line 171
    .line 172
    double-to-float v11, v11

    .line 173
    invoke-static/range {v22 .. v23}, Ljava/lang/Math;->sin(D)D

    .line 174
    .line 175
    .line 176
    move-result-wide v12

    .line 177
    mul-double/2addr v12, v3

    .line 178
    double-to-float v12, v12

    .line 179
    cmpl-float v13, v14, v17

    .line 180
    .line 181
    if-eqz v13, :cond_5

    .line 182
    .line 183
    move v13, v1

    .line 184
    move-object/from16 v26, v2

    .line 185
    .line 186
    float-to-double v1, v8

    .line 187
    move-wide/from16 v38, v3

    .line 188
    .line 189
    float-to-double v3, v5

    .line 190
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->atan2(DD)D

    .line 191
    .line 192
    .line 193
    move-result-wide v1

    .line 194
    sub-double v1, v1, v18

    .line 195
    .line 196
    double-to-float v1, v1

    .line 197
    float-to-double v1, v1

    .line 198
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 199
    .line 200
    .line 201
    move-result-wide v3

    .line 202
    double-to-float v3, v3

    .line 203
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 204
    .line 205
    .line 206
    move-result-wide v1

    .line 207
    double-to-float v1, v1

    .line 208
    move v4, v1

    .line 209
    float-to-double v1, v12

    .line 210
    move/from16 v16, v3

    .line 211
    .line 212
    move/from16 v27, v4

    .line 213
    .line 214
    float-to-double v3, v11

    .line 215
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->atan2(DD)D

    .line 216
    .line 217
    .line 218
    move-result-wide v1

    .line 219
    sub-double v1, v1, v18

    .line 220
    .line 221
    double-to-float v1, v1

    .line 222
    float-to-double v1, v1

    .line 223
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 224
    .line 225
    .line 226
    move-result-wide v3

    .line 227
    double-to-float v3, v3

    .line 228
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 229
    .line 230
    .line 231
    move-result-wide v1

    .line 232
    double-to-float v1, v1

    .line 233
    mul-float v2, v15, v14

    .line 234
    .line 235
    const/high16 v4, 0x3e800000    # 0.25f

    .line 236
    .line 237
    mul-float/2addr v2, v4

    .line 238
    mul-float v4, v2, v16

    .line 239
    .line 240
    mul-float v16, v2, v27

    .line 241
    .line 242
    mul-float/2addr v3, v2

    .line 243
    mul-float/2addr v2, v1

    .line 244
    sub-double v31, v29, v20

    .line 245
    .line 246
    cmpl-double v1, v6, v31

    .line 247
    .line 248
    if-nez v1, :cond_4

    .line 249
    .line 250
    iget-object v1, v0, Lwm/m;->b:Landroid/graphics/Path;

    .line 251
    .line 252
    invoke-virtual {v1}, Landroid/graphics/Path;->reset()V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v1, v5, v8}, Landroid/graphics/Path;->moveTo(FF)V

    .line 256
    .line 257
    .line 258
    sub-float v32, v5, v4

    .line 259
    .line 260
    sub-float v33, v8, v16

    .line 261
    .line 262
    add-float v34, v11, v3

    .line 263
    .line 264
    add-float v35, v12, v2

    .line 265
    .line 266
    move-object/from16 v31, v1

    .line 267
    .line 268
    move/from16 v36, v11

    .line 269
    .line 270
    move/from16 v37, v12

    .line 271
    .line 272
    invoke-virtual/range {v31 .. v37}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 273
    .line 274
    .line 275
    iget-object v2, v0, Lwm/m;->c:Landroid/graphics/PathMeasure;

    .line 276
    .line 277
    const/4 v11, 0x0

    .line 278
    invoke-virtual {v2, v1, v11}, Landroid/graphics/PathMeasure;->setPath(Landroid/graphics/Path;Z)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v2}, Landroid/graphics/PathMeasure;->getLength()F

    .line 282
    .line 283
    .line 284
    move-result v1

    .line 285
    const v3, 0x3f7ff972    # 0.9999f

    .line 286
    .line 287
    .line 288
    mul-float/2addr v1, v3

    .line 289
    const/4 v3, 0x0

    .line 290
    iget-object v4, v0, Lwm/m;->d:[F

    .line 291
    .line 292
    invoke-virtual {v2, v1, v4, v3}, Landroid/graphics/PathMeasure;->getPosTan(F[F[F)Z

    .line 293
    .line 294
    .line 295
    aget v7, v4, v11

    .line 296
    .line 297
    aget v8, v4, v24

    .line 298
    .line 299
    move-object/from16 v2, v26

    .line 300
    .line 301
    move/from16 v3, v32

    .line 302
    .line 303
    move/from16 v4, v33

    .line 304
    .line 305
    move/from16 v5, v34

    .line 306
    .line 307
    move/from16 v6, v35

    .line 308
    .line 309
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 310
    .line 311
    .line 312
    move/from16 v5, v36

    .line 313
    .line 314
    move/from16 v8, v37

    .line 315
    .line 316
    goto :goto_2

    .line 317
    :cond_4
    move/from16 v36, v11

    .line 318
    .line 319
    move/from16 v37, v12

    .line 320
    .line 321
    const/4 v11, 0x0

    .line 322
    sub-float/2addr v5, v4

    .line 323
    sub-float v4, v8, v16

    .line 324
    .line 325
    add-float v1, v36, v3

    .line 326
    .line 327
    add-float v6, v37, v2

    .line 328
    .line 329
    move v3, v5

    .line 330
    move-object/from16 v2, v26

    .line 331
    .line 332
    move/from16 v7, v36

    .line 333
    .line 334
    move/from16 v8, v37

    .line 335
    .line 336
    move v5, v1

    .line 337
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 338
    .line 339
    .line 340
    move v5, v7

    .line 341
    goto :goto_2

    .line 342
    :cond_5
    move v13, v1

    .line 343
    move-wide/from16 v38, v3

    .line 344
    .line 345
    move v5, v11

    .line 346
    move v8, v12

    .line 347
    const/4 v11, 0x0

    .line 348
    sub-double v3, v29, v20

    .line 349
    .line 350
    cmpl-double v1, v6, v3

    .line 351
    .line 352
    if-nez v1, :cond_6

    .line 353
    .line 354
    goto :goto_3

    .line 355
    :cond_6
    invoke-virtual {v2, v5, v8}, Landroid/graphics/Path;->lineTo(FF)V

    .line 356
    .line 357
    .line 358
    :goto_2
    add-double v22, v22, v9

    .line 359
    .line 360
    :goto_3
    add-int/lit8 v1, v13, 0x1

    .line 361
    .line 362
    move-wide/from16 v12, v29

    .line 363
    .line 364
    move-wide/from16 v3, v38

    .line 365
    .line 366
    goto/16 :goto_1

    .line 367
    .line 368
    :cond_7
    invoke-virtual/range {v25 .. v25}, Lxm/e;->d()Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    check-cast v1, Landroid/graphics/PointF;

    .line 373
    .line 374
    iget v3, v1, Landroid/graphics/PointF;->x:F

    .line 375
    .line 376
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 377
    .line 378
    invoke-virtual {v2, v3, v1}, Landroid/graphics/Path;->offset(FF)V

    .line 379
    .line 380
    .line 381
    invoke-virtual {v2}, Landroid/graphics/Path;->close()V

    .line 382
    .line 383
    .line 384
    goto/16 :goto_12

    .line 385
    .line 386
    :cond_8
    move/from16 v24, v9

    .line 387
    .line 388
    move-object/from16 v25, v10

    .line 389
    .line 390
    const/4 v11, 0x0

    .line 391
    const-wide v22, 0x401921fb54442d18L    # 6.283185307179586

    .line 392
    .line 393
    .line 394
    .line 395
    .line 396
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object v1

    .line 400
    check-cast v1, Ljava/lang/Float;

    .line 401
    .line 402
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    if-nez v8, :cond_9

    .line 407
    .line 408
    goto :goto_4

    .line 409
    :cond_9
    invoke-virtual {v8}, Lxm/e;->d()Ljava/lang/Object;

    .line 410
    .line 411
    .line 412
    move-result-object v4

    .line 413
    check-cast v4, Ljava/lang/Float;

    .line 414
    .line 415
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 416
    .line 417
    .line 418
    move-result v4

    .line 419
    float-to-double v14, v4

    .line 420
    :goto_4
    sub-double/2addr v14, v12

    .line 421
    invoke-static {v14, v15}, Ljava/lang/Math;->toRadians(D)D

    .line 422
    .line 423
    .line 424
    move-result-wide v6

    .line 425
    float-to-double v8, v1

    .line 426
    div-double v12, v22, v8

    .line 427
    .line 428
    double-to-float v4, v12

    .line 429
    iget-boolean v10, v0, Lwm/m;->h:Z

    .line 430
    .line 431
    if-eqz v10, :cond_a

    .line 432
    .line 433
    const/high16 v10, -0x40800000    # -1.0f

    .line 434
    .line 435
    mul-float/2addr v4, v10

    .line 436
    :cond_a
    move v10, v4

    .line 437
    const/high16 v12, 0x40000000    # 2.0f

    .line 438
    .line 439
    div-float v13, v10, v12

    .line 440
    .line 441
    float-to-int v4, v1

    .line 442
    int-to-float v4, v4

    .line 443
    sub-float/2addr v1, v4

    .line 444
    cmpl-float v14, v1, v17

    .line 445
    .line 446
    if-eqz v14, :cond_b

    .line 447
    .line 448
    const/high16 v4, 0x3f800000    # 1.0f

    .line 449
    .line 450
    sub-float/2addr v4, v1

    .line 451
    mul-float/2addr v4, v13

    .line 452
    move v15, v12

    .line 453
    float-to-double v11, v4

    .line 454
    add-double/2addr v6, v11

    .line 455
    goto :goto_5

    .line 456
    :cond_b
    move v15, v12

    .line 457
    :goto_5
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v3

    .line 461
    check-cast v3, Ljava/lang/Float;

    .line 462
    .line 463
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 464
    .line 465
    .line 466
    move-result v11

    .line 467
    iget-object v3, v0, Lwm/m;->l:Lxm/f;

    .line 468
    .line 469
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v3

    .line 473
    check-cast v3, Ljava/lang/Float;

    .line 474
    .line 475
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 476
    .line 477
    .line 478
    move-result v12

    .line 479
    iget-object v3, v0, Lwm/m;->n:Lxm/f;

    .line 480
    .line 481
    if-eqz v3, :cond_c

    .line 482
    .line 483
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v3

    .line 487
    check-cast v3, Ljava/lang/Float;

    .line 488
    .line 489
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 490
    .line 491
    .line 492
    move-result v3

    .line 493
    div-float v3, v3, v16

    .line 494
    .line 495
    move/from16 v22, v3

    .line 496
    .line 497
    goto :goto_6

    .line 498
    :cond_c
    move/from16 v22, v17

    .line 499
    .line 500
    :goto_6
    if-eqz v5, :cond_d

    .line 501
    .line 502
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v3

    .line 506
    check-cast v3, Ljava/lang/Float;

    .line 507
    .line 508
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 509
    .line 510
    .line 511
    move-result v3

    .line 512
    div-float v3, v3, v16

    .line 513
    .line 514
    move/from16 v16, v3

    .line 515
    .line 516
    goto :goto_7

    .line 517
    :cond_d
    move/from16 v16, v17

    .line 518
    .line 519
    :goto_7
    if-eqz v14, :cond_e

    .line 520
    .line 521
    invoke-static {v11, v12, v1, v12}, La7/g0;->b(FFFF)F

    .line 522
    .line 523
    .line 524
    move-result v3

    .line 525
    float-to-double v4, v3

    .line 526
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 527
    .line 528
    .line 529
    move-result-wide v26

    .line 530
    move/from16 v23, v3

    .line 531
    .line 532
    move-wide/from16 v29, v4

    .line 533
    .line 534
    mul-double v3, v26, v29

    .line 535
    .line 536
    double-to-float v3, v3

    .line 537
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 538
    .line 539
    .line 540
    move-result-wide v4

    .line 541
    mul-double v4, v4, v29

    .line 542
    .line 543
    double-to-float v4, v4

    .line 544
    invoke-virtual {v2, v3, v4}, Landroid/graphics/Path;->moveTo(FF)V

    .line 545
    .line 546
    .line 547
    mul-float v5, v10, v1

    .line 548
    .line 549
    div-float/2addr v5, v15

    .line 550
    move/from16 v26, v3

    .line 551
    .line 552
    move/from16 v27, v4

    .line 553
    .line 554
    float-to-double v3, v5

    .line 555
    add-double/2addr v6, v3

    .line 556
    move/from16 v3, v26

    .line 557
    .line 558
    move/from16 v4, v27

    .line 559
    .line 560
    goto :goto_8

    .line 561
    :cond_e
    float-to-double v3, v11

    .line 562
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 563
    .line 564
    .line 565
    move-result-wide v26

    .line 566
    move-wide/from16 v29, v3

    .line 567
    .line 568
    mul-double v3, v26, v29

    .line 569
    .line 570
    double-to-float v3, v3

    .line 571
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 572
    .line 573
    .line 574
    move-result-wide v4

    .line 575
    mul-double v4, v4, v29

    .line 576
    .line 577
    double-to-float v4, v4

    .line 578
    invoke-virtual {v2, v3, v4}, Landroid/graphics/Path;->moveTo(FF)V

    .line 579
    .line 580
    .line 581
    move v5, v3

    .line 582
    move/from16 v23, v4

    .line 583
    .line 584
    float-to-double v3, v13

    .line 585
    add-double/2addr v6, v3

    .line 586
    move v3, v5

    .line 587
    move/from16 v4, v23

    .line 588
    .line 589
    move/from16 v23, v17

    .line 590
    .line 591
    :goto_8
    invoke-static {v8, v9}, Ljava/lang/Math;->ceil(D)D

    .line 592
    .line 593
    .line 594
    move-result-wide v8

    .line 595
    const-wide/high16 v26, 0x4000000000000000L    # 2.0

    .line 596
    .line 597
    mul-double v29, v8, v26

    .line 598
    .line 599
    move-wide/from16 v31, v6

    .line 600
    .line 601
    const/4 v9, 0x0

    .line 602
    const/16 v28, 0x0

    .line 603
    .line 604
    :goto_9
    int-to-double v5, v9

    .line 605
    cmpg-double v7, v5, v29

    .line 606
    .line 607
    if-gez v7, :cond_19

    .line 608
    .line 609
    if-eqz v28, :cond_f

    .line 610
    .line 611
    move v7, v11

    .line 612
    goto :goto_a

    .line 613
    :cond_f
    move v7, v12

    .line 614
    :goto_a
    cmpl-float v8, v23, v17

    .line 615
    .line 616
    if-eqz v8, :cond_10

    .line 617
    .line 618
    sub-double v33, v29, v26

    .line 619
    .line 620
    cmpl-double v33, v5, v33

    .line 621
    .line 622
    if-nez v33, :cond_10

    .line 623
    .line 624
    mul-float v33, v10, v1

    .line 625
    .line 626
    div-float v33, v33, v15

    .line 627
    .line 628
    move/from16 v15, v33

    .line 629
    .line 630
    goto :goto_b

    .line 631
    :cond_10
    move v15, v13

    .line 632
    :goto_b
    if-eqz v8, :cond_11

    .line 633
    .line 634
    sub-double v34, v29, v20

    .line 635
    .line 636
    cmpl-double v8, v5, v34

    .line 637
    .line 638
    if-nez v8, :cond_11

    .line 639
    .line 640
    move/from16 v7, v23

    .line 641
    .line 642
    :cond_11
    float-to-double v7, v7

    .line 643
    invoke-static/range {v31 .. v32}, Ljava/lang/Math;->cos(D)D

    .line 644
    .line 645
    .line 646
    move-result-wide v34

    .line 647
    move-wide/from16 v36, v5

    .line 648
    .line 649
    mul-double v5, v34, v7

    .line 650
    .line 651
    double-to-float v5, v5

    .line 652
    invoke-static/range {v31 .. v32}, Ljava/lang/Math;->sin(D)D

    .line 653
    .line 654
    .line 655
    move-result-wide v34

    .line 656
    mul-double v6, v34, v7

    .line 657
    .line 658
    double-to-float v8, v6

    .line 659
    cmpl-float v6, v22, v17

    .line 660
    .line 661
    if-nez v6, :cond_12

    .line 662
    .line 663
    cmpl-float v6, v16, v17

    .line 664
    .line 665
    if-nez v6, :cond_12

    .line 666
    .line 667
    invoke-virtual {v2, v5, v8}, Landroid/graphics/Path;->lineTo(FF)V

    .line 668
    .line 669
    .line 670
    move/from16 v35, v1

    .line 671
    .line 672
    move v7, v5

    .line 673
    goto/16 :goto_11

    .line 674
    .line 675
    :cond_12
    float-to-double v6, v4

    .line 676
    move/from16 v35, v1

    .line 677
    .line 678
    move-object/from16 v34, v2

    .line 679
    .line 680
    float-to-double v1, v3

    .line 681
    invoke-static {v6, v7, v1, v2}, Ljava/lang/Math;->atan2(DD)D

    .line 682
    .line 683
    .line 684
    move-result-wide v1

    .line 685
    sub-double v1, v1, v18

    .line 686
    .line 687
    double-to-float v1, v1

    .line 688
    float-to-double v1, v1

    .line 689
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 690
    .line 691
    .line 692
    move-result-wide v6

    .line 693
    double-to-float v6, v6

    .line 694
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 695
    .line 696
    .line 697
    move-result-wide v1

    .line 698
    double-to-float v1, v1

    .line 699
    move v7, v1

    .line 700
    float-to-double v1, v8

    .line 701
    move/from16 v38, v3

    .line 702
    .line 703
    move/from16 v39, v4

    .line 704
    .line 705
    float-to-double v3, v5

    .line 706
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->atan2(DD)D

    .line 707
    .line 708
    .line 709
    move-result-wide v1

    .line 710
    sub-double v1, v1, v18

    .line 711
    .line 712
    double-to-float v1, v1

    .line 713
    float-to-double v1, v1

    .line 714
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 715
    .line 716
    .line 717
    move-result-wide v3

    .line 718
    double-to-float v3, v3

    .line 719
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 720
    .line 721
    .line 722
    move-result-wide v1

    .line 723
    double-to-float v1, v1

    .line 724
    if-eqz v28, :cond_13

    .line 725
    .line 726
    move/from16 v2, v22

    .line 727
    .line 728
    goto :goto_c

    .line 729
    :cond_13
    move/from16 v2, v16

    .line 730
    .line 731
    :goto_c
    if-eqz v28, :cond_14

    .line 732
    .line 733
    move/from16 v4, v16

    .line 734
    .line 735
    goto :goto_d

    .line 736
    :cond_14
    move/from16 v4, v22

    .line 737
    .line 738
    :goto_d
    if-eqz v28, :cond_15

    .line 739
    .line 740
    move/from16 v40, v12

    .line 741
    .line 742
    goto :goto_e

    .line 743
    :cond_15
    move/from16 v40, v11

    .line 744
    .line 745
    :goto_e
    if-eqz v28, :cond_16

    .line 746
    .line 747
    move/from16 v41, v11

    .line 748
    .line 749
    goto :goto_f

    .line 750
    :cond_16
    move/from16 v41, v12

    .line 751
    .line 752
    :goto_f
    mul-float v40, v40, v2

    .line 753
    .line 754
    const v2, 0x3ef4e26d    # 0.47829f

    .line 755
    .line 756
    .line 757
    mul-float v40, v40, v2

    .line 758
    .line 759
    mul-float v6, v6, v40

    .line 760
    .line 761
    mul-float v40, v40, v7

    .line 762
    .line 763
    mul-float v41, v41, v4

    .line 764
    .line 765
    mul-float v41, v41, v2

    .line 766
    .line 767
    mul-float v3, v3, v41

    .line 768
    .line 769
    mul-float v41, v41, v1

    .line 770
    .line 771
    if-eqz v14, :cond_18

    .line 772
    .line 773
    if-nez v9, :cond_17

    .line 774
    .line 775
    mul-float v6, v6, v35

    .line 776
    .line 777
    mul-float v40, v40, v35

    .line 778
    .line 779
    goto :goto_10

    .line 780
    :cond_17
    sub-double v1, v29, v20

    .line 781
    .line 782
    cmpl-double v1, v36, v1

    .line 783
    .line 784
    if-nez v1, :cond_18

    .line 785
    .line 786
    mul-float v3, v3, v35

    .line 787
    .line 788
    mul-float v41, v41, v35

    .line 789
    .line 790
    :cond_18
    :goto_10
    sub-float v1, v38, v6

    .line 791
    .line 792
    sub-float v4, v39, v40

    .line 793
    .line 794
    add-float/2addr v3, v5

    .line 795
    add-float v6, v8, v41

    .line 796
    .line 797
    move v7, v5

    .line 798
    move-object/from16 v2, v34

    .line 799
    .line 800
    move v5, v3

    .line 801
    move v3, v1

    .line 802
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 803
    .line 804
    .line 805
    :goto_11
    float-to-double v3, v15

    .line 806
    add-double v31, v31, v3

    .line 807
    .line 808
    xor-int/lit8 v28, v28, 0x1

    .line 809
    .line 810
    add-int/lit8 v9, v9, 0x1

    .line 811
    .line 812
    move v3, v7

    .line 813
    move v4, v8

    .line 814
    move/from16 v1, v35

    .line 815
    .line 816
    const/high16 v15, 0x40000000    # 2.0f

    .line 817
    .line 818
    goto/16 :goto_9

    .line 819
    .line 820
    :cond_19
    invoke-virtual/range {v25 .. v25}, Lxm/e;->d()Ljava/lang/Object;

    .line 821
    .line 822
    .line 823
    move-result-object v1

    .line 824
    check-cast v1, Landroid/graphics/PointF;

    .line 825
    .line 826
    iget v3, v1, Landroid/graphics/PointF;->x:F

    .line 827
    .line 828
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 829
    .line 830
    invoke-virtual {v2, v3, v1}, Landroid/graphics/Path;->offset(FF)V

    .line 831
    .line 832
    .line 833
    invoke-virtual {v2}, Landroid/graphics/Path;->close()V

    .line 834
    .line 835
    .line 836
    :goto_12
    invoke-virtual {v2}, Landroid/graphics/Path;->close()V

    .line 837
    .line 838
    .line 839
    iget-object v1, v0, Lwm/m;->p:Ld01/x;

    .line 840
    .line 841
    invoke-virtual {v1, v2}, Ld01/x;->i(Landroid/graphics/Path;)V

    .line 842
    .line 843
    .line 844
    move/from16 v1, v24

    .line 845
    .line 846
    iput-boolean v1, v0, Lwm/m;->q:Z

    .line 847
    .line 848
    return-object v2
.end method
