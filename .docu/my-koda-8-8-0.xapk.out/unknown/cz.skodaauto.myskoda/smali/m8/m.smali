.class public final Lm8/m;
.super Landroid/os/HandlerThread;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# instance fields
.field public d:Lw7/g;

.field public e:Landroid/os/Handler;

.field public f:Ljava/lang/Error;

.field public g:Ljava/lang/RuntimeException;

.field public h:Lm8/n;


# virtual methods
.method public final a(I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lm8/m;->d:Lw7/g;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Lm8/m;->d:Lw7/g;

    .line 11
    .line 12
    iget-object v3, v2, Lw7/g;->e:[I

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-static {v4}, Landroid/opengl/EGL14;->eglGetDisplay(I)Landroid/opengl/EGLDisplay;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    const/4 v13, 0x1

    .line 20
    if-eqz v5, :cond_0

    .line 21
    .line 22
    move v6, v13

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v6, v4

    .line 25
    :goto_0
    const-string v7, "eglGetDisplay failed"

    .line 26
    .line 27
    invoke-static {v7, v6}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 28
    .line 29
    .line 30
    const/4 v14, 0x2

    .line 31
    new-array v6, v14, [I

    .line 32
    .line 33
    invoke-static {v5, v6, v4, v6, v13}, Landroid/opengl/EGL14;->eglInitialize(Landroid/opengl/EGLDisplay;[II[II)Z

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    const-string v7, "eglInitialize failed"

    .line 38
    .line 39
    invoke-static {v7, v6}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    iput-object v5, v2, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 43
    .line 44
    new-array v8, v13, [Landroid/opengl/EGLConfig;

    .line 45
    .line 46
    new-array v11, v13, [I

    .line 47
    .line 48
    const/4 v10, 0x1

    .line 49
    const/4 v12, 0x0

    .line 50
    sget-object v6, Lw7/g;->j:[I

    .line 51
    .line 52
    const/4 v7, 0x0

    .line 53
    const/4 v9, 0x0

    .line 54
    invoke-static/range {v5 .. v12}, Landroid/opengl/EGL14;->eglChooseConfig(Landroid/opengl/EGLDisplay;[II[Landroid/opengl/EGLConfig;II[II)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_1

    .line 59
    .line 60
    aget v6, v11, v4

    .line 61
    .line 62
    if-lez v6, :cond_1

    .line 63
    .line 64
    aget-object v6, v8, v4

    .line 65
    .line 66
    if-eqz v6, :cond_1

    .line 67
    .line 68
    move v6, v13

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    move v6, v4

    .line 71
    :goto_1
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    aget v7, v11, v4

    .line 76
    .line 77
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    aget-object v9, v8, v4

    .line 82
    .line 83
    filled-new-array {v5, v7, v9}, [Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 88
    .line 89
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 90
    .line 91
    const-string v9, "eglChooseConfig failed: success=%b, numConfigs[0]=%d, configs[0]=%s"

    .line 92
    .line 93
    invoke-static {v7, v9, v5}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    invoke-static {v5, v6}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 98
    .line 99
    .line 100
    aget-object v5, v8, v4

    .line 101
    .line 102
    iget-object v6, v2, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 103
    .line 104
    const/4 v7, 0x4

    .line 105
    const/16 v8, 0x32c0

    .line 106
    .line 107
    const/4 v9, 0x5

    .line 108
    const/4 v10, 0x3

    .line 109
    const/16 v11, 0x3038

    .line 110
    .line 111
    const/16 v12, 0x3098

    .line 112
    .line 113
    if-nez v1, :cond_2

    .line 114
    .line 115
    new-array v15, v10, [I

    .line 116
    .line 117
    aput v12, v15, v4

    .line 118
    .line 119
    aput v14, v15, v13

    .line 120
    .line 121
    aput v11, v15, v14

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_2
    new-array v15, v9, [I

    .line 125
    .line 126
    aput v12, v15, v4

    .line 127
    .line 128
    aput v14, v15, v13

    .line 129
    .line 130
    aput v8, v15, v14

    .line 131
    .line 132
    aput v13, v15, v10

    .line 133
    .line 134
    aput v11, v15, v7

    .line 135
    .line 136
    :goto_2
    sget-object v12, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 137
    .line 138
    invoke-static {v6, v5, v12, v15, v4}, Landroid/opengl/EGL14;->eglCreateContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Landroid/opengl/EGLContext;[II)Landroid/opengl/EGLContext;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    if-eqz v6, :cond_3

    .line 143
    .line 144
    move v12, v13

    .line 145
    goto :goto_3

    .line 146
    :cond_3
    move v12, v4

    .line 147
    :goto_3
    const-string v15, "eglCreateContext failed"

    .line 148
    .line 149
    invoke-static {v15, v12}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 150
    .line 151
    .line 152
    iput-object v6, v2, Lw7/g;->g:Landroid/opengl/EGLContext;

    .line 153
    .line 154
    iget-object v12, v2, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 155
    .line 156
    if-ne v1, v13, :cond_4

    .line 157
    .line 158
    sget-object v5, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 159
    .line 160
    goto :goto_6

    .line 161
    :cond_4
    const/16 v15, 0x3056

    .line 162
    .line 163
    const/16 v16, 0x3057

    .line 164
    .line 165
    if-ne v1, v14, :cond_5

    .line 166
    .line 167
    move/from16 v17, v7

    .line 168
    .line 169
    const/4 v7, 0x7

    .line 170
    new-array v7, v7, [I

    .line 171
    .line 172
    aput v16, v7, v4

    .line 173
    .line 174
    aput v13, v7, v13

    .line 175
    .line 176
    aput v15, v7, v14

    .line 177
    .line 178
    aput v13, v7, v10

    .line 179
    .line 180
    aput v8, v7, v17

    .line 181
    .line 182
    aput v13, v7, v9

    .line 183
    .line 184
    const/4 v8, 0x6

    .line 185
    aput v11, v7, v8

    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_5
    move/from16 v17, v7

    .line 189
    .line 190
    new-array v7, v9, [I

    .line 191
    .line 192
    aput v16, v7, v4

    .line 193
    .line 194
    aput v13, v7, v13

    .line 195
    .line 196
    aput v15, v7, v14

    .line 197
    .line 198
    aput v13, v7, v10

    .line 199
    .line 200
    aput v11, v7, v17

    .line 201
    .line 202
    :goto_4
    invoke-static {v12, v5, v7, v4}, Landroid/opengl/EGL14;->eglCreatePbufferSurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;[II)Landroid/opengl/EGLSurface;

    .line 203
    .line 204
    .line 205
    move-result-object v5

    .line 206
    if-eqz v5, :cond_6

    .line 207
    .line 208
    move v7, v13

    .line 209
    goto :goto_5

    .line 210
    :cond_6
    move v7, v4

    .line 211
    :goto_5
    const-string v8, "eglCreatePbufferSurface failed"

    .line 212
    .line 213
    invoke-static {v8, v7}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 214
    .line 215
    .line 216
    :goto_6
    invoke-static {v12, v5, v5, v6}, Landroid/opengl/EGL14;->eglMakeCurrent(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z

    .line 217
    .line 218
    .line 219
    move-result v6

    .line 220
    const-string v7, "eglMakeCurrent failed"

    .line 221
    .line 222
    invoke-static {v7, v6}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 223
    .line 224
    .line 225
    iput-object v5, v2, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 226
    .line 227
    invoke-static {v13, v3, v4}, Landroid/opengl/GLES20;->glGenTextures(I[II)V

    .line 228
    .line 229
    .line 230
    invoke-static {}, Lw7/a;->e()V

    .line 231
    .line 232
    .line 233
    new-instance v5, Landroid/graphics/SurfaceTexture;

    .line 234
    .line 235
    aget v3, v3, v4

    .line 236
    .line 237
    invoke-direct {v5, v3}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 238
    .line 239
    .line 240
    iput-object v5, v2, Lw7/g;->i:Landroid/graphics/SurfaceTexture;

    .line 241
    .line 242
    invoke-virtual {v5, v2}, Landroid/graphics/SurfaceTexture;->setOnFrameAvailableListener(Landroid/graphics/SurfaceTexture$OnFrameAvailableListener;)V

    .line 243
    .line 244
    .line 245
    new-instance v2, Lm8/n;

    .line 246
    .line 247
    iget-object v3, v0, Lm8/m;->d:Lw7/g;

    .line 248
    .line 249
    iget-object v3, v3, Lw7/g;->i:Landroid/graphics/SurfaceTexture;

    .line 250
    .line 251
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 252
    .line 253
    .line 254
    if-eqz v1, :cond_7

    .line 255
    .line 256
    move v4, v13

    .line 257
    :cond_7
    invoke-direct {v2, v0, v3, v4}, Lm8/n;-><init>(Lm8/m;Landroid/graphics/SurfaceTexture;Z)V

    .line 258
    .line 259
    .line 260
    iput-object v2, v0, Lm8/m;->h:Lm8/n;

    .line 261
    .line 262
    return-void
.end method

.method public final b()V
    .locals 5

    .line 1
    iget-object v0, p0, Lm8/m;->d:Lw7/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm8/m;->d:Lw7/g;

    .line 7
    .line 8
    iget-object v0, p0, Lw7/g;->d:Landroid/os/Handler;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    :try_start_0
    iget-object v1, p0, Lw7/g;->i:Landroid/graphics/SurfaceTexture;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {v1}, Landroid/graphics/SurfaceTexture;->release()V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Lw7/g;->e:[I

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-static {v3, v1, v2}, Landroid/opengl/GLES20;->glDeleteTextures(I[II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception v1

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    :goto_0
    iget-object v1, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 32
    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Landroid/opengl/EGLDisplay;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_1

    .line 42
    .line 43
    iget-object v1, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 44
    .line 45
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 46
    .line 47
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 48
    .line 49
    invoke-static {v1, v2, v2, v3}, Landroid/opengl/EGL14;->eglMakeCurrent(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z

    .line 50
    .line 51
    .line 52
    :cond_1
    iget-object v1, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 53
    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 57
    .line 58
    invoke-virtual {v1, v2}, Landroid/opengl/EGLSurface;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-nez v1, :cond_2

    .line 63
    .line 64
    iget-object v1, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 65
    .line 66
    iget-object v2, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 67
    .line 68
    invoke-static {v1, v2}, Landroid/opengl/EGL14;->eglDestroySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 69
    .line 70
    .line 71
    :cond_2
    iget-object v1, p0, Lw7/g;->g:Landroid/opengl/EGLContext;

    .line 72
    .line 73
    if-eqz v1, :cond_3

    .line 74
    .line 75
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 76
    .line 77
    invoke-static {v2, v1}, Landroid/opengl/EGL14;->eglDestroyContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;)Z

    .line 78
    .line 79
    .line 80
    :cond_3
    invoke-static {}, Landroid/opengl/EGL14;->eglReleaseThread()Z

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 84
    .line 85
    if-eqz v1, :cond_4

    .line 86
    .line 87
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 88
    .line 89
    invoke-virtual {v1, v2}, Landroid/opengl/EGLDisplay;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_4

    .line 94
    .line 95
    iget-object v1, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 96
    .line 97
    invoke-static {v1}, Landroid/opengl/EGL14;->eglTerminate(Landroid/opengl/EGLDisplay;)Z

    .line 98
    .line 99
    .line 100
    :cond_4
    iput-object v0, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 101
    .line 102
    iput-object v0, p0, Lw7/g;->g:Landroid/opengl/EGLContext;

    .line 103
    .line 104
    iput-object v0, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 105
    .line 106
    iput-object v0, p0, Lw7/g;->i:Landroid/graphics/SurfaceTexture;

    .line 107
    .line 108
    return-void

    .line 109
    :goto_1
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 110
    .line 111
    if-eqz v2, :cond_5

    .line 112
    .line 113
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 114
    .line 115
    invoke-virtual {v2, v3}, Landroid/opengl/EGLDisplay;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-nez v2, :cond_5

    .line 120
    .line 121
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 122
    .line 123
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 124
    .line 125
    sget-object v4, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 126
    .line 127
    invoke-static {v2, v3, v3, v4}, Landroid/opengl/EGL14;->eglMakeCurrent(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z

    .line 128
    .line 129
    .line 130
    :cond_5
    iget-object v2, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 131
    .line 132
    if-eqz v2, :cond_6

    .line 133
    .line 134
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 135
    .line 136
    invoke-virtual {v2, v3}, Landroid/opengl/EGLSurface;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    if-nez v2, :cond_6

    .line 141
    .line 142
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 143
    .line 144
    iget-object v3, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 145
    .line 146
    invoke-static {v2, v3}, Landroid/opengl/EGL14;->eglDestroySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 147
    .line 148
    .line 149
    :cond_6
    iget-object v2, p0, Lw7/g;->g:Landroid/opengl/EGLContext;

    .line 150
    .line 151
    if-eqz v2, :cond_7

    .line 152
    .line 153
    iget-object v3, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 154
    .line 155
    invoke-static {v3, v2}, Landroid/opengl/EGL14;->eglDestroyContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;)Z

    .line 156
    .line 157
    .line 158
    :cond_7
    invoke-static {}, Landroid/opengl/EGL14;->eglReleaseThread()Z

    .line 159
    .line 160
    .line 161
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 162
    .line 163
    if-eqz v2, :cond_8

    .line 164
    .line 165
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 166
    .line 167
    invoke-virtual {v2, v3}, Landroid/opengl/EGLDisplay;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    if-nez v2, :cond_8

    .line 172
    .line 173
    iget-object v2, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 174
    .line 175
    invoke-static {v2}, Landroid/opengl/EGL14;->eglTerminate(Landroid/opengl/EGLDisplay;)Z

    .line 176
    .line 177
    .line 178
    :cond_8
    iput-object v0, p0, Lw7/g;->f:Landroid/opengl/EGLDisplay;

    .line 179
    .line 180
    iput-object v0, p0, Lw7/g;->g:Landroid/opengl/EGLContext;

    .line 181
    .line 182
    iput-object v0, p0, Lw7/g;->h:Landroid/opengl/EGLSurface;

    .line 183
    .line 184
    iput-object v0, p0, Lw7/g;->i:Landroid/graphics/SurfaceTexture;

    .line 185
    .line 186
    throw v1
.end method

.method public final handleMessage(Landroid/os/Message;)Z
    .locals 3

    .line 1
    iget v0, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq v0, v1, :cond_1

    .line 5
    .line 6
    const/4 p1, 0x2

    .line 7
    if-eq v0, p1, :cond_0

    .line 8
    .line 9
    goto :goto_3

    .line 10
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Lm8/m;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/os/HandlerThread;->quit()Z

    .line 14
    .line 15
    .line 16
    return v1

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    :try_start_1
    const-string v0, "PlaceholderSurface"

    .line 19
    .line 20
    const-string v2, "Failed to release placeholder surface"

    .line 21
    .line 22
    invoke-static {v0, v2, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/os/HandlerThread;->quit()Z

    .line 26
    .line 27
    .line 28
    return v1

    .line 29
    :catchall_1
    move-exception p1

    .line 30
    invoke-virtual {p0}, Landroid/os/HandlerThread;->quit()Z

    .line 31
    .line 32
    .line 33
    throw p1

    .line 34
    :cond_1
    :try_start_2
    iget p1, p1, Landroid/os/Message;->arg1:I

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lm8/m;->a(I)V
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Lw7/h; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/Error; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 37
    .line 38
    .line 39
    monitor-enter p0

    .line 40
    :try_start_3
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 41
    .line 42
    .line 43
    monitor-exit p0

    .line 44
    return v1

    .line 45
    :catchall_2
    move-exception p1

    .line 46
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 47
    throw p1

    .line 48
    :catchall_3
    move-exception p1

    .line 49
    goto :goto_4

    .line 50
    :catch_0
    move-exception p1

    .line 51
    goto :goto_0

    .line 52
    :catch_1
    move-exception p1

    .line 53
    goto :goto_1

    .line 54
    :catch_2
    move-exception p1

    .line 55
    goto :goto_2

    .line 56
    :goto_0
    :try_start_4
    const-string v0, "PlaceholderSurface"

    .line 57
    .line 58
    const-string v2, "Failed to initialize placeholder surface"

    .line 59
    .line 60
    invoke-static {v0, v2, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 61
    .line 62
    .line 63
    iput-object p1, p0, Lm8/m;->f:Ljava/lang/Error;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 64
    .line 65
    monitor-enter p0

    .line 66
    :try_start_5
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 67
    .line 68
    .line 69
    monitor-exit p0

    .line 70
    goto :goto_3

    .line 71
    :catchall_4
    move-exception p1

    .line 72
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 73
    throw p1

    .line 74
    :goto_1
    :try_start_6
    const-string v0, "PlaceholderSurface"

    .line 75
    .line 76
    const-string v2, "Failed to initialize placeholder surface"

    .line 77
    .line 78
    invoke-static {v0, v2, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 79
    .line 80
    .line 81
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 84
    .line 85
    .line 86
    iput-object v0, p0, Lm8/m;->g:Ljava/lang/RuntimeException;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 87
    .line 88
    monitor-enter p0

    .line 89
    :try_start_7
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 90
    .line 91
    .line 92
    monitor-exit p0

    .line 93
    goto :goto_3

    .line 94
    :catchall_5
    move-exception p1

    .line 95
    monitor-exit p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 96
    throw p1

    .line 97
    :goto_2
    :try_start_8
    const-string v0, "PlaceholderSurface"

    .line 98
    .line 99
    const-string v2, "Failed to initialize placeholder surface"

    .line 100
    .line 101
    invoke-static {v0, v2, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 102
    .line 103
    .line 104
    iput-object p1, p0, Lm8/m;->g:Ljava/lang/RuntimeException;
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 105
    .line 106
    monitor-enter p0

    .line 107
    :try_start_9
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 108
    .line 109
    .line 110
    monitor-exit p0

    .line 111
    :goto_3
    return v1

    .line 112
    :catchall_6
    move-exception p1

    .line 113
    monitor-exit p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    .line 114
    throw p1

    .line 115
    :goto_4
    monitor-enter p0

    .line 116
    :try_start_a
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 117
    .line 118
    .line 119
    monitor-exit p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_7

    .line 120
    throw p1

    .line 121
    :catchall_7
    move-exception p1

    .line 122
    :try_start_b
    monitor-exit p0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    .line 123
    throw p1
.end method
