.class public final Lq0/c;
.super Lc1/k2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public q:I

.field public r:I

.field public final s:Lb0/x;

.field public final t:Lb0/x;


# direct methods
.method public constructor <init>(Lb0/x;Lb0/x;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lc1/k2;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lq0/c;->q:I

    .line 6
    .line 7
    iput v0, p0, Lq0/c;->r:I

    .line 8
    .line 9
    iput-object p1, p0, Lq0/c;->s:Lb0/x;

    .line 10
    .line 11
    iput-object p2, p0, Lq0/c;->t:Lb0/x;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final i(Lb0/y;)Lr0/a;
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 2
    .line 3
    invoke-super {p0, p1}, Lc1/k2;->i(Lb0/y;)Lr0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {}, Lr0/i;->h()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput v0, p0, Lq0/c;->q:I

    .line 12
    .line 13
    invoke-static {}, Lr0/i;->h()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iput v0, p0, Lq0/c;->r:I

    .line 18
    .line 19
    return-object p1
.end method

.method public final q(JLandroid/view/Surface;Lp0/l;Landroid/graphics/SurfaceTexture;Landroid/graphics/SurfaceTexture;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-static {v0, v1}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lc1/k2;->h:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Ljava/lang/Thread;

    .line 12
    .line 13
    invoke-static {v0}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-virtual {v0, p3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    const-string v2, "The surface is not registered."

    .line 25
    .line 26
    invoke-static {v2, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lr0/c;

    .line 34
    .line 35
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    sget-object v2, Lr0/i;->j:Lr0/c;

    .line 39
    .line 40
    if-ne v1, v2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p0, p3}, Lc1/k2;->c(Landroid/view/Surface;)Lr0/c;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    if-nez v1, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v0, p3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    :cond_1
    move-object v3, v1

    .line 53
    iget-object v0, v3, Lr0/c;->a:Landroid/opengl/EGLSurface;

    .line 54
    .line 55
    iget-object v1, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Landroid/view/Surface;

    .line 58
    .line 59
    if-eq p3, v1, :cond_2

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Lc1/k2;->k(Landroid/opengl/EGLSurface;)V

    .line 62
    .line 63
    .line 64
    iput-object p3, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 65
    .line 66
    :cond_2
    const/high16 v1, 0x3f800000    # 1.0f

    .line 67
    .line 68
    const/4 v2, 0x0

    .line 69
    invoke-static {v2, v2, v2, v1}, Landroid/opengl/GLES20;->glClearColor(FFFF)V

    .line 70
    .line 71
    .line 72
    const/16 v1, 0x4000

    .line 73
    .line 74
    invoke-static {v1}, Landroid/opengl/GLES20;->glClear(I)V

    .line 75
    .line 76
    .line 77
    iget v7, p0, Lq0/c;->q:I

    .line 78
    .line 79
    const/4 v8, 0x1

    .line 80
    iget-object v6, p0, Lq0/c;->s:Lb0/x;

    .line 81
    .line 82
    move-object v2, p0

    .line 83
    move-object v4, p4

    .line 84
    move-object v5, p5

    .line 85
    invoke-virtual/range {v2 .. v8}, Lq0/c;->r(Lr0/c;Lp0/l;Landroid/graphics/SurfaceTexture;Lb0/x;IZ)V

    .line 86
    .line 87
    .line 88
    iget v7, v2, Lq0/c;->r:I

    .line 89
    .line 90
    const/4 v8, 0x0

    .line 91
    iget-object v6, v2, Lq0/c;->t:Lb0/x;

    .line 92
    .line 93
    move-object v5, p6

    .line 94
    invoke-virtual/range {v2 .. v8}, Lq0/c;->r(Lr0/c;Lp0/l;Landroid/graphics/SurfaceTexture;Lb0/x;IZ)V

    .line 95
    .line 96
    .line 97
    iget-object p0, v2, Lc1/k2;->i:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Landroid/opengl/EGLDisplay;

    .line 100
    .line 101
    invoke-static {p0, v0, p1, p2}, Landroid/opengl/EGLExt;->eglPresentationTimeANDROID(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;J)Z

    .line 102
    .line 103
    .line 104
    iget-object p0, v2, Lc1/k2;->i:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p0, Landroid/opengl/EGLDisplay;

    .line 107
    .line 108
    invoke-static {p0, v0}, Landroid/opengl/EGL14;->eglSwapBuffers(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    if-nez p0, :cond_3

    .line 113
    .line 114
    new-instance p0, Ljava/lang/StringBuilder;

    .line 115
    .line 116
    const-string p1, "Failed to swap buffers with EGL error: 0x"

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-static {}, Landroid/opengl/EGL14;->eglGetError()I

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    invoke-static {p1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    const-string p1, "DualOpenGlRenderer"

    .line 137
    .line 138
    invoke-static {p1, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const/4 p0, 0x0

    .line 142
    invoke-virtual {v2, p3, p0}, Lc1/k2;->n(Landroid/view/Surface;Z)V

    .line 143
    .line 144
    .line 145
    :cond_3
    :goto_0
    return-void
.end method

.method public final r(Lr0/c;Lp0/l;Landroid/graphics/SurfaceTexture;Lb0/x;IZ)V
    .locals 14

    .line 1
    move-object/from16 v2, p2

    .line 2
    .line 3
    move-object/from16 v3, p4

    .line 4
    .line 5
    move/from16 v4, p5

    .line 6
    .line 7
    invoke-virtual {p0, v4}, Lc1/k2;->p(I)V

    .line 8
    .line 9
    .line 10
    iget v4, p1, Lr0/c;->b:I

    .line 11
    .line 12
    iget v1, p1, Lr0/c;->c:I

    .line 13
    .line 14
    const/4 v5, 0x0

    .line 15
    invoke-static {v5, v5, v4, v1}, Landroid/opengl/GLES20;->glViewport(IIII)V

    .line 16
    .line 17
    .line 18
    invoke-static {v5, v5, v4, v1}, Landroid/opengl/GLES20;->glScissor(IIII)V

    .line 19
    .line 20
    .line 21
    const/16 v6, 0x10

    .line 22
    .line 23
    new-array v9, v6, [F

    .line 24
    .line 25
    move-object/from16 v7, p3

    .line 26
    .line 27
    invoke-virtual {v7, v9}, Landroid/graphics/SurfaceTexture;->getTransformMatrix([F)V

    .line 28
    .line 29
    .line 30
    new-array v7, v6, [F

    .line 31
    .line 32
    if-eqz p6, :cond_0

    .line 33
    .line 34
    iget-object v2, v2, Lp0/l;->h:[F

    .line 35
    .line 36
    :goto_0
    move-object v11, v2

    .line 37
    goto :goto_1

    .line 38
    :cond_0
    iget-object v2, v2, Lp0/l;->i:[F

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :goto_1
    const/4 v12, 0x0

    .line 42
    const/4 v8, 0x0

    .line 43
    const/4 v10, 0x0

    .line 44
    invoke-static/range {v7 .. v12}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lr0/g;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    instance-of v2, v0, Lr0/h;

    .line 55
    .line 56
    const-string v8, "glUniformMatrix4fv"

    .line 57
    .line 58
    const/4 v9, 0x1

    .line 59
    if-eqz v2, :cond_1

    .line 60
    .line 61
    move-object v2, v0

    .line 62
    check-cast v2, Lr0/h;

    .line 63
    .line 64
    iget v2, v2, Lr0/h;->f:I

    .line 65
    .line 66
    invoke-static {v2, v9, v5, v7, v5}, Landroid/opengl/GLES20;->glUniformMatrix4fv(IIZ[FI)V

    .line 67
    .line 68
    .line 69
    invoke-static {v8}, Lr0/i;->b(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    :cond_1
    new-instance v2, Landroid/util/Size;

    .line 73
    .line 74
    int-to-float v7, v4

    .line 75
    iget-object v10, v3, Lb0/x;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v10, Lc6/b;

    .line 78
    .line 79
    iget-object v11, v10, Lc6/b;->a:Ljava/lang/Object;

    .line 80
    .line 81
    iget-object v12, v10, Lc6/b;->b:Ljava/lang/Object;

    .line 82
    .line 83
    iget-object v10, v10, Lc6/b;->a:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v10, Ljava/lang/Float;

    .line 86
    .line 87
    invoke-virtual {v10}, Ljava/lang/Float;->floatValue()F

    .line 88
    .line 89
    .line 90
    move-result v10

    .line 91
    mul-float/2addr v10, v7

    .line 92
    float-to-int v7, v10

    .line 93
    int-to-float v10, v1

    .line 94
    move-object v13, v12

    .line 95
    check-cast v13, Ljava/lang/Float;

    .line 96
    .line 97
    invoke-virtual {v13}, Ljava/lang/Float;->floatValue()F

    .line 98
    .line 99
    .line 100
    move-result v13

    .line 101
    mul-float/2addr v13, v10

    .line 102
    float-to-int v10, v13

    .line 103
    invoke-direct {v2, v7, v10}, Landroid/util/Size;-><init>(II)V

    .line 104
    .line 105
    .line 106
    new-instance v7, Landroid/util/Size;

    .line 107
    .line 108
    invoke-direct {v7, v4, v1}, Landroid/util/Size;-><init>(II)V

    .line 109
    .line 110
    .line 111
    new-array v1, v6, [F

    .line 112
    .line 113
    invoke-static {v1, v5}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 114
    .line 115
    .line 116
    new-array v4, v6, [F

    .line 117
    .line 118
    invoke-static {v4, v5}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 119
    .line 120
    .line 121
    new-array v6, v6, [F

    .line 122
    .line 123
    invoke-static {v6, v5}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 127
    .line 128
    .line 129
    move-result v10

    .line 130
    int-to-float v10, v10

    .line 131
    invoke-virtual {v7}, Landroid/util/Size;->getWidth()I

    .line 132
    .line 133
    .line 134
    move-result v13

    .line 135
    int-to-float v13, v13

    .line 136
    div-float/2addr v10, v13

    .line 137
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    int-to-float v2, v2

    .line 142
    invoke-virtual {v7}, Landroid/util/Size;->getHeight()I

    .line 143
    .line 144
    .line 145
    move-result v7

    .line 146
    int-to-float v7, v7

    .line 147
    div-float/2addr v2, v7

    .line 148
    const/high16 v7, 0x3f800000    # 1.0f

    .line 149
    .line 150
    invoke-static {v1, v5, v10, v2, v7}, Landroid/opengl/Matrix;->scaleM([FIFFF)V

    .line 151
    .line 152
    .line 153
    iget-object v2, v3, Lb0/x;->e:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v2, Lc6/b;

    .line 156
    .line 157
    move-object v3, v11

    .line 158
    check-cast v3, Ljava/lang/Float;

    .line 159
    .line 160
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    const/4 v10, 0x0

    .line 165
    cmpl-float v3, v3, v10

    .line 166
    .line 167
    if-nez v3, :cond_2

    .line 168
    .line 169
    move-object v3, v12

    .line 170
    check-cast v3, Ljava/lang/Float;

    .line 171
    .line 172
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    cmpl-float v3, v3, v10

    .line 177
    .line 178
    if-eqz v3, :cond_3

    .line 179
    .line 180
    :cond_2
    iget-object v3, v2, Lc6/b;->a:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v3, Ljava/lang/Float;

    .line 183
    .line 184
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 185
    .line 186
    .line 187
    move-result v3

    .line 188
    check-cast v11, Ljava/lang/Float;

    .line 189
    .line 190
    invoke-virtual {v11}, Ljava/lang/Float;->floatValue()F

    .line 191
    .line 192
    .line 193
    move-result v11

    .line 194
    div-float/2addr v3, v11

    .line 195
    iget-object v2, v2, Lc6/b;->b:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v2, Ljava/lang/Float;

    .line 198
    .line 199
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    check-cast v12, Ljava/lang/Float;

    .line 204
    .line 205
    invoke-virtual {v12}, Ljava/lang/Float;->floatValue()F

    .line 206
    .line 207
    .line 208
    move-result v11

    .line 209
    div-float/2addr v2, v11

    .line 210
    invoke-static {v4, v5, v3, v2, v10}, Landroid/opengl/Matrix;->translateM([FIFFF)V

    .line 211
    .line 212
    .line 213
    :cond_3
    const/4 v2, 0x0

    .line 214
    const/4 v3, 0x0

    .line 215
    const/4 v10, 0x0

    .line 216
    move-object/from16 p2, v1

    .line 217
    .line 218
    move/from16 p3, v2

    .line 219
    .line 220
    move/from16 p5, v3

    .line 221
    .line 222
    move-object/from16 p4, v4

    .line 223
    .line 224
    move-object p0, v6

    .line 225
    move p1, v10

    .line 226
    invoke-static/range {p0 .. p5}, Landroid/opengl/Matrix;->multiplyMM([FI[FI[FI)V

    .line 227
    .line 228
    .line 229
    move-object v1, p0

    .line 230
    iget v2, v0, Lr0/g;->b:I

    .line 231
    .line 232
    invoke-static {v2, v9, v5, v1, v5}, Landroid/opengl/GLES20;->glUniformMatrix4fv(IIZ[FI)V

    .line 233
    .line 234
    .line 235
    invoke-static {v8}, Lr0/i;->b(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    iget v0, v0, Lr0/g;->c:I

    .line 239
    .line 240
    invoke-static {v0, v7}, Landroid/opengl/GLES20;->glUniform1f(IF)V

    .line 241
    .line 242
    .line 243
    const-string v0, "glUniform1f"

    .line 244
    .line 245
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    const/16 v0, 0xbe2

    .line 249
    .line 250
    invoke-static {v0}, Landroid/opengl/GLES20;->glEnable(I)V

    .line 251
    .line 252
    .line 253
    const/16 v1, 0x302

    .line 254
    .line 255
    const/16 v2, 0x303

    .line 256
    .line 257
    invoke-static {v1, v2, v9, v2}, Landroid/opengl/GLES20;->glBlendFuncSeparate(IIII)V

    .line 258
    .line 259
    .line 260
    const/4 v1, 0x5

    .line 261
    const/4 v2, 0x4

    .line 262
    invoke-static {v1, v5, v2}, Landroid/opengl/GLES20;->glDrawArrays(III)V

    .line 263
    .line 264
    .line 265
    const-string v1, "glDrawArrays"

    .line 266
    .line 267
    invoke-static {v1}, Lr0/i;->b(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    invoke-static {v0}, Landroid/opengl/GLES20;->glDisable(I)V

    .line 271
    .line 272
    .line 273
    return-void
.end method
