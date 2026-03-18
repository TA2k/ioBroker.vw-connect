.class public abstract Lb0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/b1;


# instance fields
.field public d:Lb0/d0;

.field public volatile e:I

.field public volatile f:I

.field public volatile g:I

.field public volatile h:Z

.field public volatile i:Z

.field public j:Ljava/util/concurrent/Executor;

.field public k:Lb0/n1;

.field public l:Landroid/media/ImageWriter;

.field public m:Landroid/graphics/Rect;

.field public n:Landroid/graphics/Rect;

.field public o:Landroid/graphics/Matrix;

.field public p:Landroid/graphics/Matrix;

.field public q:Ljava/nio/ByteBuffer;

.field public r:Ljava/nio/ByteBuffer;

.field public s:Ljava/nio/ByteBuffer;

.field public t:Ljava/nio/ByteBuffer;

.field public u:Ljava/nio/ByteBuffer;

.field public v:Ljava/nio/ByteBuffer;

.field public final w:Ljava/lang/Object;

.field public x:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput v0, p0, Lb0/l0;->g:I

    .line 6
    .line 7
    new-instance v1, Landroid/graphics/Rect;

    .line 8
    .line 9
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lb0/l0;->m:Landroid/graphics/Rect;

    .line 13
    .line 14
    new-instance v1, Landroid/graphics/Rect;

    .line 15
    .line 16
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lb0/l0;->n:Landroid/graphics/Rect;

    .line 20
    .line 21
    new-instance v1, Landroid/graphics/Matrix;

    .line 22
    .line 23
    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v1, p0, Lb0/l0;->o:Landroid/graphics/Matrix;

    .line 27
    .line 28
    new-instance v1, Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lb0/l0;->p:Landroid/graphics/Matrix;

    .line 34
    .line 35
    new-instance v1, Ljava/lang/Object;

    .line 36
    .line 37
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v1, p0, Lb0/l0;->w:Ljava/lang/Object;

    .line 41
    .line 42
    iput-boolean v0, p0, Lb0/l0;->x:Z

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public abstract a(Lh0/c1;)Lb0/a1;
.end method

.method public final b(Lb0/a1;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    iget-boolean v0, v1, Lb0/l0;->h:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget v0, v1, Lb0/l0;->e:I

    .line 10
    .line 11
    move v8, v0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v8, 0x0

    .line 14
    :goto_0
    iget-object v3, v1, Lb0/l0;->w:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v3

    .line 17
    :try_start_0
    iget-object v0, v1, Lb0/l0;->j:Ljava/util/concurrent/Executor;

    .line 18
    .line 19
    iget-object v10, v1, Lb0/l0;->d:Lb0/d0;

    .line 20
    .line 21
    iget-boolean v4, v1, Lb0/l0;->h:Z

    .line 22
    .line 23
    const/4 v11, 0x1

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    iget v4, v1, Lb0/l0;->f:I

    .line 27
    .line 28
    if-eq v8, v4, :cond_1

    .line 29
    .line 30
    move v12, v11

    .line 31
    goto :goto_1

    .line 32
    :catchall_0
    move-exception v0

    .line 33
    move-object v14, v3

    .line 34
    goto/16 :goto_b

    .line 35
    .line 36
    :cond_1
    const/4 v12, 0x0

    .line 37
    :goto_1
    if-eqz v12, :cond_2

    .line 38
    .line 39
    invoke-virtual {v1, v2, v8}, Lb0/l0;->h(Lb0/a1;I)V

    .line 40
    .line 41
    .line 42
    :cond_2
    iget-boolean v4, v1, Lb0/l0;->h:Z

    .line 43
    .line 44
    const/4 v5, 0x3

    .line 45
    if-nez v4, :cond_4

    .line 46
    .line 47
    iget v4, v1, Lb0/l0;->g:I

    .line 48
    .line 49
    if-ne v4, v5, :cond_3

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_3
    :goto_2
    move-object v4, v3

    .line 53
    goto :goto_4

    .line 54
    :cond_4
    :goto_3
    invoke-virtual/range {p0 .. p1}, Lb0/l0;->e(Lb0/a1;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :goto_4
    :try_start_1
    iget-object v3, v1, Lb0/l0;->k:Lb0/n1;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 59
    .line 60
    move-object v6, v4

    .line 61
    :try_start_2
    iget-object v4, v1, Lb0/l0;->l:Landroid/media/ImageWriter;

    .line 62
    .line 63
    iget-object v7, v1, Lb0/l0;->q:Ljava/nio/ByteBuffer;

    .line 64
    .line 65
    move v13, v5

    .line 66
    iget-object v5, v1, Lb0/l0;->r:Ljava/nio/ByteBuffer;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 67
    .line 68
    move-object v14, v6

    .line 69
    :try_start_3
    iget-object v6, v1, Lb0/l0;->s:Ljava/nio/ByteBuffer;

    .line 70
    .line 71
    iget-object v15, v1, Lb0/l0;->t:Ljava/nio/ByteBuffer;

    .line 72
    .line 73
    move-object/from16 v16, v6

    .line 74
    .line 75
    iget-object v6, v1, Lb0/l0;->u:Ljava/nio/ByteBuffer;

    .line 76
    .line 77
    iget-object v9, v1, Lb0/l0;->v:Ljava/nio/ByteBuffer;

    .line 78
    .line 79
    monitor-exit v14
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 80
    if-eqz v10, :cond_d

    .line 81
    .line 82
    if-eqz v0, :cond_d

    .line 83
    .line 84
    iget-boolean v14, v1, Lb0/l0;->x:Z

    .line 85
    .line 86
    if-eqz v14, :cond_d

    .line 87
    .line 88
    if-eqz v3, :cond_7

    .line 89
    .line 90
    iget v6, v1, Lb0/l0;->g:I

    .line 91
    .line 92
    const/4 v9, 0x2

    .line 93
    if-ne v6, v9, :cond_5

    .line 94
    .line 95
    iget-boolean v4, v1, Lb0/l0;->i:Z

    .line 96
    .line 97
    invoke-static {v2, v3, v7, v8, v4}, Landroidx/camera/core/ImageProcessingUtil;->b(Lb0/a1;Lh0/c1;Ljava/nio/ByteBuffer;IZ)Lb0/o0;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    :goto_5
    move-object v2, v3

    .line 102
    goto :goto_6

    .line 103
    :cond_5
    iget v6, v1, Lb0/l0;->g:I

    .line 104
    .line 105
    if-ne v6, v11, :cond_9

    .line 106
    .line 107
    iget-boolean v6, v1, Lb0/l0;->i:Z

    .line 108
    .line 109
    if-eqz v6, :cond_6

    .line 110
    .line 111
    invoke-static {v2}, Landroidx/camera/core/ImageProcessingUtil;->a(Lb0/a1;)V

    .line 112
    .line 113
    .line 114
    :cond_6
    if-eqz v4, :cond_9

    .line 115
    .line 116
    if-eqz v5, :cond_9

    .line 117
    .line 118
    if-eqz v16, :cond_9

    .line 119
    .line 120
    if-eqz v15, :cond_9

    .line 121
    .line 122
    move-object v7, v15

    .line 123
    move-object/from16 v6, v16

    .line 124
    .line 125
    invoke-static/range {v2 .. v8}, Landroidx/camera/core/ImageProcessingUtil;->f(Lb0/a1;Lh0/c1;Landroid/media/ImageWriter;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;I)Lb0/o0;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    goto :goto_5

    .line 130
    :cond_7
    move-object v3, v5

    .line 131
    move-object v5, v15

    .line 132
    iget v2, v1, Lb0/l0;->g:I

    .line 133
    .line 134
    if-ne v2, v13, :cond_9

    .line 135
    .line 136
    iget-boolean v2, v1, Lb0/l0;->i:Z

    .line 137
    .line 138
    if-eqz v2, :cond_8

    .line 139
    .line 140
    invoke-static/range {p1 .. p1}, Landroidx/camera/core/ImageProcessingUtil;->a(Lb0/a1;)V

    .line 141
    .line 142
    .line 143
    :cond_8
    if-eqz v3, :cond_9

    .line 144
    .line 145
    if-eqz v16, :cond_9

    .line 146
    .line 147
    if-eqz v5, :cond_9

    .line 148
    .line 149
    if-eqz v6, :cond_9

    .line 150
    .line 151
    if-eqz v9, :cond_9

    .line 152
    .line 153
    move-object/from16 v2, p1

    .line 154
    .line 155
    move-object v7, v9

    .line 156
    move-object/from16 v4, v16

    .line 157
    .line 158
    invoke-static/range {v2 .. v8}, Landroidx/camera/core/ImageProcessingUtil;->g(Lb0/a1;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;I)Lb0/o0;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    goto :goto_5

    .line 163
    :cond_9
    const/4 v2, 0x0

    .line 164
    :goto_6
    if-nez v2, :cond_a

    .line 165
    .line 166
    move v9, v11

    .line 167
    goto :goto_7

    .line 168
    :cond_a
    const/4 v9, 0x0

    .line 169
    :goto_7
    if-eqz v9, :cond_b

    .line 170
    .line 171
    move-object/from16 v5, p1

    .line 172
    .line 173
    goto :goto_8

    .line 174
    :cond_b
    move-object v5, v2

    .line 175
    :goto_8
    new-instance v6, Landroid/graphics/Rect;

    .line 176
    .line 177
    invoke-direct {v6}, Landroid/graphics/Rect;-><init>()V

    .line 178
    .line 179
    .line 180
    new-instance v4, Landroid/graphics/Matrix;

    .line 181
    .line 182
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 183
    .line 184
    .line 185
    iget-object v2, v1, Lb0/l0;->w:Ljava/lang/Object;

    .line 186
    .line 187
    monitor-enter v2

    .line 188
    if-eqz v12, :cond_c

    .line 189
    .line 190
    if-nez v9, :cond_c

    .line 191
    .line 192
    :try_start_4
    invoke-interface/range {p1 .. p1}, Lb0/a1;->o()I

    .line 193
    .line 194
    .line 195
    move-result v3

    .line 196
    invoke-interface/range {p1 .. p1}, Lb0/a1;->m()I

    .line 197
    .line 198
    .line 199
    move-result v7

    .line 200
    invoke-interface {v5}, Lb0/a1;->o()I

    .line 201
    .line 202
    .line 203
    move-result v9

    .line 204
    invoke-interface {v5}, Lb0/a1;->m()I

    .line 205
    .line 206
    .line 207
    move-result v11

    .line 208
    invoke-virtual {v1, v3, v7, v9, v11}, Lb0/l0;->g(IIII)V

    .line 209
    .line 210
    .line 211
    goto :goto_9

    .line 212
    :catchall_1
    move-exception v0

    .line 213
    goto :goto_a

    .line 214
    :cond_c
    :goto_9
    iput v8, v1, Lb0/l0;->f:I

    .line 215
    .line 216
    iget-object v3, v1, Lb0/l0;->n:Landroid/graphics/Rect;

    .line 217
    .line 218
    invoke-virtual {v6, v3}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 219
    .line 220
    .line 221
    iget-object v3, v1, Lb0/l0;->p:Landroid/graphics/Matrix;

    .line 222
    .line 223
    invoke-virtual {v4, v3}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 224
    .line 225
    .line 226
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 227
    move-object v2, v0

    .line 228
    new-instance v0, Lb0/j0;

    .line 229
    .line 230
    move-object/from16 v3, p1

    .line 231
    .line 232
    move-object v7, v10

    .line 233
    invoke-direct/range {v0 .. v7}, Lb0/j0;-><init>(Lb0/l0;Ljava/util/concurrent/Executor;Lb0/a1;Landroid/graphics/Matrix;Lb0/a1;Landroid/graphics/Rect;Lb0/d0;)V

    .line 234
    .line 235
    .line 236
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    return-object v0

    .line 241
    :goto_a
    :try_start_5
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 242
    throw v0

    .line 243
    :cond_d
    new-instance v0, La8/r0;

    .line 244
    .line 245
    const-string v1, "No analyzer or executor currently set."

    .line 246
    .line 247
    invoke-direct {v0, v1}, La8/r0;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    new-instance v1, Lk0/j;

    .line 251
    .line 252
    const/4 v2, 0x1

    .line 253
    invoke-direct {v1, v0, v2}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 254
    .line 255
    .line 256
    return-object v1

    .line 257
    :catchall_2
    move-exception v0

    .line 258
    goto :goto_b

    .line 259
    :catchall_3
    move-exception v0

    .line 260
    move-object v14, v6

    .line 261
    goto :goto_b

    .line 262
    :catchall_4
    move-exception v0

    .line 263
    move-object v14, v4

    .line 264
    :goto_b
    :try_start_6
    monitor-exit v14
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 265
    throw v0
.end method

.method public final c(Lh0/c1;)V
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Lb0/l0;->a(Lh0/c1;)Lb0/a1;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lb0/l0;->f(Lb0/a1;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void

    .line 11
    :catch_0
    move-exception p0

    .line 12
    const-string p1, "ImageAnalysisAnalyzer"

    .line 13
    .line 14
    const-string v0, "Failed to acquire image."

    .line 15
    .line 16
    invoke-static {p1, v0, p0}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public abstract d()V
.end method

.method public final e(Lb0/a1;)V
    .locals 5

    .line 1
    iget v0, p0, Lb0/l0;->g:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x2

    .line 5
    const/4 v3, 0x3

    .line 6
    if-eq v0, v1, :cond_1

    .line 7
    .line 8
    iget v0, p0, Lb0/l0;->g:I

    .line 9
    .line 10
    if-ne v0, v3, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget v0, p0, Lb0/l0;->g:I

    .line 14
    .line 15
    if-ne v0, v2, :cond_7

    .line 16
    .line 17
    iget-object v0, p0, Lb0/l0;->q:Ljava/nio/ByteBuffer;

    .line 18
    .line 19
    if-nez v0, :cond_7

    .line 20
    .line 21
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    mul-int/2addr p1, v0

    .line 30
    mul-int/lit8 p1, p1, 0x4

    .line 31
    .line 32
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lb0/l0;->q:Ljava/nio/ByteBuffer;

    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    :goto_0
    iget-object v0, p0, Lb0/l0;->r:Ljava/nio/ByteBuffer;

    .line 40
    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    mul-int/2addr v1, v0

    .line 52
    invoke-static {v1}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    iput-object v0, p0, Lb0/l0;->r:Ljava/nio/ByteBuffer;

    .line 57
    .line 58
    :cond_2
    iget-object v0, p0, Lb0/l0;->r:Ljava/nio/ByteBuffer;

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 62
    .line 63
    .line 64
    iget-object v0, p0, Lb0/l0;->s:Ljava/nio/ByteBuffer;

    .line 65
    .line 66
    if-nez v0, :cond_3

    .line 67
    .line 68
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    mul-int/2addr v4, v0

    .line 77
    div-int/lit8 v4, v4, 0x4

    .line 78
    .line 79
    invoke-static {v4}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    iput-object v0, p0, Lb0/l0;->s:Ljava/nio/ByteBuffer;

    .line 84
    .line 85
    :cond_3
    iget-object v0, p0, Lb0/l0;->s:Ljava/nio/ByteBuffer;

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 88
    .line 89
    .line 90
    iget-object v0, p0, Lb0/l0;->t:Ljava/nio/ByteBuffer;

    .line 91
    .line 92
    if-nez v0, :cond_4

    .line 93
    .line 94
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    mul-int/2addr v4, v0

    .line 103
    div-int/lit8 v4, v4, 0x4

    .line 104
    .line 105
    invoke-static {v4}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    iput-object v0, p0, Lb0/l0;->t:Ljava/nio/ByteBuffer;

    .line 110
    .line 111
    :cond_4
    iget-object v0, p0, Lb0/l0;->t:Ljava/nio/ByteBuffer;

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 114
    .line 115
    .line 116
    iget v0, p0, Lb0/l0;->g:I

    .line 117
    .line 118
    if-ne v0, v3, :cond_7

    .line 119
    .line 120
    iget-object v0, p0, Lb0/l0;->u:Ljava/nio/ByteBuffer;

    .line 121
    .line 122
    if-nez v0, :cond_5

    .line 123
    .line 124
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    mul-int/2addr v3, v0

    .line 133
    invoke-static {v3}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    iput-object v0, p0, Lb0/l0;->u:Ljava/nio/ByteBuffer;

    .line 138
    .line 139
    :cond_5
    iget-object v0, p0, Lb0/l0;->u:Ljava/nio/ByteBuffer;

    .line 140
    .line 141
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 142
    .line 143
    .line 144
    iget-object v0, p0, Lb0/l0;->v:Ljava/nio/ByteBuffer;

    .line 145
    .line 146
    if-nez v0, :cond_6

    .line 147
    .line 148
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    mul-int/2addr p1, v0

    .line 157
    div-int/2addr p1, v2

    .line 158
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    iput-object p1, p0, Lb0/l0;->v:Ljava/nio/ByteBuffer;

    .line 163
    .line 164
    :cond_6
    iget-object p0, p0, Lb0/l0;->v:Ljava/nio/ByteBuffer;

    .line 165
    .line 166
    invoke-virtual {p0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 167
    .line 168
    .line 169
    :cond_7
    return-void
.end method

.method public abstract f(Lb0/a1;)V
.end method

.method public final g(IIII)V
    .locals 4

    .line 1
    iget v0, p0, Lb0/l0;->e:I

    .line 2
    .line 3
    new-instance v1, Landroid/graphics/Matrix;

    .line 4
    .line 5
    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    .line 6
    .line 7
    .line 8
    if-lez v0, :cond_0

    .line 9
    .line 10
    new-instance v2, Landroid/graphics/RectF;

    .line 11
    .line 12
    int-to-float p1, p1

    .line 13
    int-to-float p2, p2

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v2, v3, v3, p1, p2}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Li0/f;->a:Landroid/graphics/RectF;

    .line 19
    .line 20
    sget-object p2, Landroid/graphics/Matrix$ScaleToFit;->FILL:Landroid/graphics/Matrix$ScaleToFit;

    .line 21
    .line 22
    invoke-virtual {v1, v2, p1, p2}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 23
    .line 24
    .line 25
    int-to-float v0, v0

    .line 26
    invoke-virtual {v1, v0}, Landroid/graphics/Matrix;->postRotate(F)Z

    .line 27
    .line 28
    .line 29
    new-instance v0, Landroid/graphics/RectF;

    .line 30
    .line 31
    int-to-float p3, p3

    .line 32
    int-to-float p4, p4

    .line 33
    invoke-direct {v0, v3, v3, p3, p4}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 34
    .line 35
    .line 36
    new-instance p3, Landroid/graphics/Matrix;

    .line 37
    .line 38
    invoke-direct {p3}, Landroid/graphics/Matrix;-><init>()V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p3, p1, v0, p2}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, p3}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 45
    .line 46
    .line 47
    :cond_0
    iget-object p1, p0, Lb0/l0;->m:Landroid/graphics/Rect;

    .line 48
    .line 49
    new-instance p2, Landroid/graphics/RectF;

    .line 50
    .line 51
    invoke-direct {p2, p1}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, p2}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 55
    .line 56
    .line 57
    new-instance p1, Landroid/graphics/Rect;

    .line 58
    .line 59
    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2, p1}, Landroid/graphics/RectF;->round(Landroid/graphics/Rect;)V

    .line 63
    .line 64
    .line 65
    iput-object p1, p0, Lb0/l0;->n:Landroid/graphics/Rect;

    .line 66
    .line 67
    iget-object p1, p0, Lb0/l0;->p:Landroid/graphics/Matrix;

    .line 68
    .line 69
    iget-object p0, p0, Lb0/l0;->o:Landroid/graphics/Matrix;

    .line 70
    .line 71
    invoke-virtual {p1, p0, v1}, Landroid/graphics/Matrix;->setConcat(Landroid/graphics/Matrix;Landroid/graphics/Matrix;)Z

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public final h(Lb0/a1;I)V
    .locals 5

    .line 1
    iget-object v0, p0, Lb0/l0;->k:Lb0/n1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_4

    .line 6
    :cond_0
    invoke-virtual {v0}, Lb0/n1;->r()V

    .line 7
    .line 8
    .line 9
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object v1, p0, Lb0/l0;->k:Lb0/n1;

    .line 18
    .line 19
    invoke-virtual {v1}, Lb0/n1;->d()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    iget-object v2, p0, Lb0/l0;->k:Lb0/n1;

    .line 24
    .line 25
    invoke-virtual {v2}, Lb0/n1;->f()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/16 v3, 0x5a

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    if-eq p2, v3, :cond_2

    .line 33
    .line 34
    const/16 v3, 0x10e

    .line 35
    .line 36
    if-ne p2, v3, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const/4 p2, 0x0

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    move p2, v4

    .line 42
    :goto_1
    if-eqz p2, :cond_3

    .line 43
    .line 44
    move v3, p1

    .line 45
    goto :goto_2

    .line 46
    :cond_3
    move v3, v0

    .line 47
    :goto_2
    if-eqz p2, :cond_4

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_4
    move v0, p1

    .line 51
    :goto_3
    new-instance p1, Lb0/n1;

    .line 52
    .line 53
    invoke-static {v3, v0, v1, v2}, Ljp/u1;->e(IIII)Lcom/google/android/gms/internal/measurement/i4;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-direct {p1, p2}, Lb0/n1;-><init>(Lh0/c1;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Lb0/l0;->k:Lb0/n1;

    .line 61
    .line 62
    iget p1, p0, Lb0/l0;->g:I

    .line 63
    .line 64
    if-ne p1, v4, :cond_6

    .line 65
    .line 66
    iget-object p1, p0, Lb0/l0;->l:Landroid/media/ImageWriter;

    .line 67
    .line 68
    if-eqz p1, :cond_5

    .line 69
    .line 70
    invoke-virtual {p1}, Landroid/media/ImageWriter;->close()V

    .line 71
    .line 72
    .line 73
    :cond_5
    iget-object p1, p0, Lb0/l0;->k:Lb0/n1;

    .line 74
    .line 75
    invoke-virtual {p1}, Lb0/n1;->getSurface()Landroid/view/Surface;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    iget-object p2, p0, Lb0/l0;->k:Lb0/n1;

    .line 80
    .line 81
    invoke-virtual {p2}, Lb0/n1;->f()I

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    invoke-static {p1, p2}, Landroid/media/ImageWriter;->newInstance(Landroid/view/Surface;I)Landroid/media/ImageWriter;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Lb0/l0;->l:Landroid/media/ImageWriter;

    .line 90
    .line 91
    :cond_6
    :goto_4
    return-void
.end method

.method public final i(Landroid/graphics/Matrix;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/l0;->w:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lb0/l0;->o:Landroid/graphics/Matrix;

    .line 5
    .line 6
    new-instance p1, Landroid/graphics/Matrix;

    .line 7
    .line 8
    iget-object v1, p0, Lb0/l0;->o:Landroid/graphics/Matrix;

    .line 9
    .line 10
    invoke-direct {p1, v1}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lb0/l0;->p:Landroid/graphics/Matrix;

    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public final j(Landroid/graphics/Rect;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/l0;->w:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lb0/l0;->m:Landroid/graphics/Rect;

    .line 5
    .line 6
    new-instance p1, Landroid/graphics/Rect;

    .line 7
    .line 8
    iget-object v1, p0, Lb0/l0;->m:Landroid/graphics/Rect;

    .line 9
    .line 10
    invoke-direct {p1, v1}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lb0/l0;->n:Landroid/graphics/Rect;

    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method
