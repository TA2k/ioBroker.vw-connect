.class public Lc1/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/f2;


# instance fields
.field public d:[I

.field public e:I

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;

.field public m:Ljava/lang/Object;

.field public n:Ljava/lang/Object;

.field public o:Ljava/lang/Object;

.field public p:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 3
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 4
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    iput-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 5
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    iput-object v0, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 6
    sget-object v0, Lr0/i;->a:[I

    iput-object v0, p0, Lc1/k2;->d:[I

    .line 7
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    iput-object v0, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 8
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    iput-object v0, p0, Lc1/k2;->n:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 10
    sget-object v0, Lr0/f;->d:Lr0/f;

    iput-object v0, p0, Lc1/k2;->p:Ljava/lang/Object;

    const/4 v0, -0x1

    .line 11
    iput v0, p0, Lc1/k2;->e:I

    return-void
.end method

.method public constructor <init>(Landroidx/collection/a0;Landroidx/collection/b0;ILc1/w;)V
    .locals 0

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 14
    iput-object p2, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 15
    iput p3, p0, Lc1/k2;->e:I

    .line 16
    iput-object p4, p0, Lc1/k2;->h:Ljava/lang/Object;

    .line 17
    sget-object p1, Lc1/e2;->a:[I

    iput-object p1, p0, Lc1/k2;->d:[I

    .line 18
    sget-object p1, Lc1/e2;->b:[F

    iput-object p1, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 19
    iput-object p1, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 20
    iput-object p1, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 21
    sget-object p1, Lc1/e2;->c:Laq/a;

    .line 22
    iput-object p1, p0, Lc1/k2;->p:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 13

    .line 1
    move-object/from16 v5, p5

    .line 2
    .line 3
    const-wide/32 v6, 0xf4240

    .line 4
    .line 5
    .line 6
    div-long v0, p1, v6

    .line 7
    .line 8
    sget-object v2, Lc1/e2;->a:[I

    .line 9
    .line 10
    const/4 v8, 0x0

    .line 11
    int-to-long v2, v8

    .line 12
    sub-long/2addr v0, v2

    .line 13
    iget v2, p0, Lc1/k2;->e:I

    .line 14
    .line 15
    int-to-long v2, v2

    .line 16
    const-wide/16 v9, 0x0

    .line 17
    .line 18
    cmp-long v4, v0, v9

    .line 19
    .line 20
    if-gez v4, :cond_0

    .line 21
    .line 22
    move-wide v0, v9

    .line 23
    :cond_0
    cmp-long v4, v0, v2

    .line 24
    .line 25
    if-lez v4, :cond_1

    .line 26
    .line 27
    move-wide v11, v2

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    move-wide v11, v0

    .line 30
    :goto_0
    cmp-long v0, v11, v9

    .line 31
    .line 32
    if-gez v0, :cond_2

    .line 33
    .line 34
    return-object v5

    .line 35
    :cond_2
    move-object/from16 v3, p3

    .line 36
    .line 37
    move-object/from16 v4, p4

    .line 38
    .line 39
    invoke-virtual {p0, v3, v4, v5}, Lc1/k2;->j(Lc1/p;Lc1/p;Lc1/p;)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v9, v0

    .line 45
    check-cast v9, Lc1/p;

    .line 46
    .line 47
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Laq/a;

    .line 53
    .line 54
    sget-object v1, Lc1/e2;->c:Laq/a;

    .line 55
    .line 56
    if-eq v0, v1, :cond_a

    .line 57
    .line 58
    long-to-int v0, v11

    .line 59
    invoke-virtual {p0, v0}, Lc1/k2;->e(I)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    invoke-virtual {p0, v1, v0, v8}, Lc1/k2;->f(IIZ)F

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    iget-object v1, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, [F

    .line 70
    .line 71
    iget-object p0, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Laq/a;

    .line 74
    .line 75
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, [[Lc1/r;

    .line 78
    .line 79
    aget-object v2, p0, v8

    .line 80
    .line 81
    aget-object v2, v2, v8

    .line 82
    .line 83
    iget v2, v2, Lc1/r;->a:F

    .line 84
    .line 85
    array-length v3, p0

    .line 86
    const/4 v4, 0x1

    .line 87
    sub-int/2addr v3, v4

    .line 88
    aget-object v3, p0, v3

    .line 89
    .line 90
    aget-object v3, v3, v8

    .line 91
    .line 92
    iget v3, v3, Lc1/r;->b:F

    .line 93
    .line 94
    cmpg-float v5, v0, v2

    .line 95
    .line 96
    if-gez v5, :cond_3

    .line 97
    .line 98
    move v0, v2

    .line 99
    :cond_3
    cmpl-float v2, v0, v3

    .line 100
    .line 101
    if-lez v2, :cond_4

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_4
    move v3, v0

    .line 105
    :goto_1
    array-length v0, v1

    .line 106
    array-length v2, p0

    .line 107
    move v5, v8

    .line 108
    move v6, v5

    .line 109
    :goto_2
    if-ge v5, v2, :cond_9

    .line 110
    .line 111
    move v7, v8

    .line 112
    move v10, v7

    .line 113
    :goto_3
    add-int/lit8 v11, v0, -0x1

    .line 114
    .line 115
    if-ge v7, v11, :cond_7

    .line 116
    .line 117
    aget-object v11, p0, v5

    .line 118
    .line 119
    aget-object v11, v11, v10

    .line 120
    .line 121
    iget v12, v11, Lc1/r;->b:F

    .line 122
    .line 123
    cmpg-float v12, v3, v12

    .line 124
    .line 125
    if-gtz v12, :cond_6

    .line 126
    .line 127
    iget-boolean v6, v11, Lc1/r;->p:Z

    .line 128
    .line 129
    if-eqz v6, :cond_5

    .line 130
    .line 131
    iget v6, v11, Lc1/r;->q:F

    .line 132
    .line 133
    aput v6, v1, v7

    .line 134
    .line 135
    add-int/lit8 v6, v7, 0x1

    .line 136
    .line 137
    iget v11, v11, Lc1/r;->r:F

    .line 138
    .line 139
    aput v11, v1, v6

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_5
    invoke-virtual {v11, v3}, Lc1/r;->c(F)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v11}, Lc1/r;->a()F

    .line 146
    .line 147
    .line 148
    move-result v6

    .line 149
    aput v6, v1, v7

    .line 150
    .line 151
    add-int/lit8 v6, v7, 0x1

    .line 152
    .line 153
    invoke-virtual {v11}, Lc1/r;->b()F

    .line 154
    .line 155
    .line 156
    move-result v11

    .line 157
    aput v11, v1, v6

    .line 158
    .line 159
    :goto_4
    move v6, v4

    .line 160
    :cond_6
    add-int/lit8 v7, v7, 0x2

    .line 161
    .line 162
    add-int/lit8 v10, v10, 0x1

    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_7
    if-eqz v6, :cond_8

    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_9
    :goto_5
    array-length p0, v1

    .line 172
    :goto_6
    if-ge v8, p0, :cond_b

    .line 173
    .line 174
    aget v0, v1, v8

    .line 175
    .line 176
    invoke-virtual {v9, v8, v0}, Lc1/p;->e(IF)V

    .line 177
    .line 178
    .line 179
    add-int/lit8 v8, v8, 0x1

    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_a
    const-wide/16 v0, 0x1

    .line 183
    .line 184
    sub-long v0, v11, v0

    .line 185
    .line 186
    mul-long v1, v0, v6

    .line 187
    .line 188
    move-object v0, p0

    .line 189
    invoke-virtual/range {v0 .. v5}, Lc1/k2;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 190
    .line 191
    .line 192
    move-result-object v10

    .line 193
    mul-long v1, v11, v6

    .line 194
    .line 195
    move-object/from16 v3, p3

    .line 196
    .line 197
    move-object/from16 v4, p4

    .line 198
    .line 199
    move-object/from16 v5, p5

    .line 200
    .line 201
    invoke-virtual/range {v0 .. v5}, Lc1/k2;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    invoke-virtual {v10}, Lc1/p;->b()I

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    :goto_7
    if-ge v8, v0, :cond_b

    .line 210
    .line 211
    invoke-virtual {v10, v8}, Lc1/p;->a(I)F

    .line 212
    .line 213
    .line 214
    move-result v1

    .line 215
    invoke-virtual {p0, v8}, Lc1/p;->a(I)F

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    sub-float/2addr v1, v2

    .line 220
    const/high16 v2, 0x447a0000    # 1000.0f

    .line 221
    .line 222
    mul-float/2addr v1, v2

    .line 223
    invoke-virtual {v9, v8, v1}, Lc1/p;->e(IF)V

    .line 224
    .line 225
    .line 226
    add-int/lit8 v8, v8, 0x1

    .line 227
    .line 228
    goto :goto_7

    .line 229
    :cond_b
    return-object v9
.end method

.method public b(Lb0/y;Lcom/google/firebase/messaging/w;)V
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v2}, Landroid/opengl/EGL14;->eglGetDisplay(I)Landroid/opengl/EGLDisplay;

    .line 7
    .line 8
    .line 9
    move-result-object v3

    .line 10
    iput-object v3, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 11
    .line 12
    sget-object v4, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 13
    .line 14
    invoke-static {v3, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-nez v3, :cond_9

    .line 19
    .line 20
    const/4 v3, 0x2

    .line 21
    new-array v4, v3, [I

    .line 22
    .line 23
    iget-object v5, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, Landroid/opengl/EGLDisplay;

    .line 26
    .line 27
    const/4 v6, 0x1

    .line 28
    invoke-static {v5, v4, v2, v4, v6}, Landroid/opengl/EGL14;->eglInitialize(Landroid/opengl/EGLDisplay;[II[II)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_8

    .line 33
    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    new-instance v5, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 39
    .line 40
    .line 41
    aget v7, v4, v2

    .line 42
    .line 43
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v7, "."

    .line 47
    .line 48
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    aget v4, v4, v6

    .line 52
    .line 53
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    if-eqz v4, :cond_0

    .line 61
    .line 62
    iput-object v4, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    .line 66
    .line 67
    const-string v1, "Null eglVersion"

    .line 68
    .line 69
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_1
    :goto_0
    invoke-virtual/range {p1 .. p1}, Lb0/y;->a()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    const/16 v4, 0x8

    .line 78
    .line 79
    if-eqz v1, :cond_2

    .line 80
    .line 81
    const/16 v1, 0xa

    .line 82
    .line 83
    move v8, v1

    .line 84
    goto :goto_1

    .line 85
    :cond_2
    move v8, v4

    .line 86
    :goto_1
    invoke-virtual/range {p1 .. p1}, Lb0/y;->a()Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_3

    .line 91
    .line 92
    move v14, v3

    .line 93
    goto :goto_2

    .line 94
    :cond_3
    move v14, v4

    .line 95
    :goto_2
    invoke-virtual/range {p1 .. p1}, Lb0/y;->a()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    const/16 v1, 0x40

    .line 102
    .line 103
    :goto_3
    move/from16 v20, v1

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_4
    const/4 v1, 0x4

    .line 107
    goto :goto_3

    .line 108
    :goto_4
    invoke-virtual/range {p1 .. p1}, Lb0/y;->a()Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    const/4 v1, -0x1

    .line 115
    move/from16 v22, v1

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_5
    move/from16 v22, v6

    .line 119
    .line 120
    :goto_5
    const/16 v24, 0x5

    .line 121
    .line 122
    const/16 v25, 0x3038

    .line 123
    .line 124
    const/16 v7, 0x3024

    .line 125
    .line 126
    const/16 v9, 0x3023

    .line 127
    .line 128
    const/16 v11, 0x3022

    .line 129
    .line 130
    const/16 v13, 0x3021

    .line 131
    .line 132
    const/16 v15, 0x3025

    .line 133
    .line 134
    const/16 v16, 0x0

    .line 135
    .line 136
    const/16 v17, 0x3026

    .line 137
    .line 138
    const/16 v18, 0x0

    .line 139
    .line 140
    const/16 v19, 0x3040

    .line 141
    .line 142
    const/16 v21, 0x3142

    .line 143
    .line 144
    const/16 v23, 0x3033

    .line 145
    .line 146
    move v10, v8

    .line 147
    move v12, v8

    .line 148
    filled-new-array/range {v7 .. v25}, [I

    .line 149
    .line 150
    .line 151
    move-result-object v27

    .line 152
    const/4 v1, 0x1

    .line 153
    new-array v4, v1, [Landroid/opengl/EGLConfig;

    .line 154
    .line 155
    new-array v5, v6, [I

    .line 156
    .line 157
    iget-object v7, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 158
    .line 159
    move-object/from16 v26, v7

    .line 160
    .line 161
    check-cast v26, Landroid/opengl/EGLDisplay;

    .line 162
    .line 163
    const/16 v30, 0x0

    .line 164
    .line 165
    const/16 v33, 0x0

    .line 166
    .line 167
    const/16 v28, 0x0

    .line 168
    .line 169
    move/from16 v31, v1

    .line 170
    .line 171
    move-object/from16 v29, v4

    .line 172
    .line 173
    move-object/from16 v32, v5

    .line 174
    .line 175
    invoke-static/range {v26 .. v33}, Landroid/opengl/EGL14;->eglChooseConfig(Landroid/opengl/EGLDisplay;[II[Landroid/opengl/EGLConfig;II[II)Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    if-eqz v1, :cond_7

    .line 180
    .line 181
    aget-object v1, v29, v2

    .line 182
    .line 183
    invoke-virtual/range {p1 .. p1}, Lb0/y;->a()Z

    .line 184
    .line 185
    .line 186
    move-result v4

    .line 187
    if-eqz v4, :cond_6

    .line 188
    .line 189
    const/4 v3, 0x3

    .line 190
    :cond_6
    const/16 v4, 0x3038

    .line 191
    .line 192
    const/16 v5, 0x3098

    .line 193
    .line 194
    filled-new-array {v5, v3, v4}, [I

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    iget-object v4, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v4, Landroid/opengl/EGLDisplay;

    .line 201
    .line 202
    sget-object v7, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 203
    .line 204
    invoke-static {v4, v1, v7, v3, v2}, Landroid/opengl/EGL14;->eglCreateContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Landroid/opengl/EGLContext;[II)Landroid/opengl/EGLContext;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    const-string v4, "eglCreateContext"

    .line 209
    .line 210
    invoke-static {v4}, Lr0/i;->a(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    iput-object v1, v0, Lc1/k2;->k:Ljava/lang/Object;

    .line 214
    .line 215
    iput-object v3, v0, Lc1/k2;->j:Ljava/lang/Object;

    .line 216
    .line 217
    new-array v1, v6, [I

    .line 218
    .line 219
    iget-object v0, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 222
    .line 223
    invoke-static {v0, v3, v5, v1, v2}, Landroid/opengl/EGL14;->eglQueryContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;I[II)Z

    .line 224
    .line 225
    .line 226
    new-instance v0, Ljava/lang/StringBuilder;

    .line 227
    .line 228
    const-string v3, "EGLContext created, client version "

    .line 229
    .line 230
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    aget v1, v1, v2

    .line 234
    .line 235
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    const-string v1, "OpenGlRenderer"

    .line 243
    .line 244
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 245
    .line 246
    .line 247
    return-void

    .line 248
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 249
    .line 250
    const-string v1, "Unable to find a suitable EGLConfig"

    .line 251
    .line 252
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw v0

    .line 256
    :cond_8
    sget-object v1, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 257
    .line 258
    iput-object v1, v0, Lc1/k2;->i:Ljava/lang/Object;

    .line 259
    .line 260
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 261
    .line 262
    const-string v1, "Unable to initialize EGL14"

    .line 263
    .line 264
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    throw v0

    .line 268
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 269
    .line 270
    const-string v1, "Unable to get EGL14 display"

    .line 271
    .line 272
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    throw v0
.end method

.method public c(Landroid/view/Surface;)Lr0/c;
    .locals 4

    .line 1
    :try_start_0
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/opengl/EGLConfig;

    .line 8
    .line 9
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lc1/k2;->d:[I

    .line 13
    .line 14
    invoke-static {v0, v1, p1, v2}, Lr0/i;->i(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Landroid/view/Surface;[I)Landroid/opengl/EGLSurface;

    .line 15
    .line 16
    .line 17
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    iget-object p0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/opengl/EGLDisplay;

    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    new-array v1, v0, [I

    .line 24
    .line 25
    const/16 v2, 0x3057

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-static {p0, p1, v2, v1, v3}, Landroid/opengl/EGL14;->eglQuerySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I[II)Z

    .line 29
    .line 30
    .line 31
    aget v1, v1, v3

    .line 32
    .line 33
    new-array v0, v0, [I

    .line 34
    .line 35
    const/16 v2, 0x3056

    .line 36
    .line 37
    invoke-static {p0, p1, v2, v0, v3}, Landroid/opengl/EGL14;->eglQuerySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I[II)Z

    .line 38
    .line 39
    .line 40
    aget p0, v0, v3

    .line 41
    .line 42
    new-instance v0, Landroid/util/Size;

    .line 43
    .line 44
    invoke-direct {v0, v1, p0}, Landroid/util/Size;-><init>(II)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    invoke-virtual {v0}, Landroid/util/Size;->getHeight()I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    new-instance v1, Lr0/c;

    .line 56
    .line 57
    invoke-direct {v1, p1, p0, v0}, Lr0/c;-><init>(Landroid/opengl/EGLSurface;II)V

    .line 58
    .line 59
    .line 60
    return-object v1

    .line 61
    :catch_0
    move-exception p0

    .line 62
    new-instance p1, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v0, "Failed to create EGL surface: "

    .line 65
    .line 66
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    const-string v0, "OpenGlRenderer"

    .line 81
    .line 82
    invoke-static {v0, p1, p0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 83
    .line 84
    .line 85
    const/4 p0, 0x0

    .line 86
    return-object p0
.end method

.method public d()V
    .locals 6

    .line 1
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/opengl/EGLConfig;

    .line 8
    .line 9
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    sget-object v2, Lr0/i;->a:[I

    .line 13
    .line 14
    const/16 v2, 0x3056

    .line 15
    .line 16
    const/16 v3, 0x3038

    .line 17
    .line 18
    const/16 v4, 0x3057

    .line 19
    .line 20
    const/4 v5, 0x1

    .line 21
    filled-new-array {v4, v5, v2, v5, v3}, [I

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-static {v0, v1, v2, v3}, Landroid/opengl/EGL14;->eglCreatePbufferSurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;[II)Landroid/opengl/EGLSurface;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const-string v1, "eglCreatePbufferSurface"

    .line 31
    .line 32
    invoke-static {v1}, Lr0/i;->a(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iput-object v0, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string v0, "surface was null"

    .line 43
    .line 44
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0
.end method

.method public e(I)I
    .locals 4

    .line 1
    iget-object p0, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a0;

    .line 4
    .line 5
    iget v0, p0, Landroidx/collection/a0;->b:I

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    if-lez v0, :cond_4

    .line 11
    .line 12
    iget v1, p0, Landroidx/collection/a0;->b:I

    .line 13
    .line 14
    if-gt v0, v1, :cond_4

    .line 15
    .line 16
    add-int/lit8 v0, v0, -0x1

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    :goto_0
    if-gt v1, v0, :cond_1

    .line 20
    .line 21
    add-int v2, v1, v0

    .line 22
    .line 23
    ushr-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    iget-object v3, p0, Landroidx/collection/a0;->a:[I

    .line 26
    .line 27
    aget v3, v3, v2

    .line 28
    .line 29
    if-ge v3, p1, :cond_0

    .line 30
    .line 31
    add-int/lit8 v1, v2, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    if-le v3, p1, :cond_2

    .line 35
    .line 36
    add-int/lit8 v0, v2, -0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    neg-int v2, v1

    .line 42
    :cond_2
    const/4 p0, -0x1

    .line 43
    if-ge v2, p0, :cond_3

    .line 44
    .line 45
    add-int/lit8 v2, v2, 0x2

    .line 46
    .line 47
    neg-int p0, v2

    .line 48
    return p0

    .line 49
    :cond_3
    return v2

    .line 50
    :cond_4
    const-string p0, ""

    .line 51
    .line 52
    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const/4 p0, 0x0

    .line 56
    throw p0
.end method

.method public f(IIZ)F
    .locals 4

    .line 1
    iget-object v0, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/a0;

    .line 4
    .line 5
    iget v1, v0, Landroidx/collection/a0;->b:I

    .line 6
    .line 7
    add-int/lit8 v1, v1, -0x1

    .line 8
    .line 9
    const-wide/16 v2, 0x3e8

    .line 10
    .line 11
    if-lt p1, v1, :cond_0

    .line 12
    .line 13
    int-to-float p0, p2

    .line 14
    :goto_0
    long-to-float p1, v2

    .line 15
    div-float/2addr p0, p1

    .line 16
    return p0

    .line 17
    :cond_0
    invoke-virtual {v0, p1}, Landroidx/collection/a0;->c(I)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    add-int/lit8 p1, p1, 0x1

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Landroidx/collection/a0;->c(I)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-ne p2, v1, :cond_1

    .line 28
    .line 29
    int-to-float p0, v1

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    sub-int/2addr p1, v1

    .line 32
    iget-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Landroidx/collection/b0;

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Lc1/j2;

    .line 41
    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    iget-object v0, v0, Lc1/j2;->b:Lc1/w;

    .line 45
    .line 46
    if-nez v0, :cond_3

    .line 47
    .line 48
    :cond_2
    iget-object p0, p0, Lc1/k2;->h:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v0, p0

    .line 51
    check-cast v0, Lc1/w;

    .line 52
    .line 53
    :cond_3
    sub-int/2addr p2, v1

    .line 54
    int-to-float p0, p2

    .line 55
    int-to-float p1, p1

    .line 56
    div-float/2addr p0, p1

    .line 57
    invoke-interface {v0, p0}, Lc1/w;->b(F)F

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p3, :cond_4

    .line 62
    .line 63
    return p0

    .line 64
    :cond_4
    mul-float/2addr p1, p0

    .line 65
    int-to-float p0, v1

    .line 66
    add-float/2addr p1, p0

    .line 67
    long-to-float p0, v2

    .line 68
    div-float/2addr p1, p0

    .line 69
    return p1
.end method

.method public g(Lb0/y;)Lc6/b;
    .locals 4

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    const-string v1, "Failed to get GL or EGL extensions: "

    .line 4
    .line 5
    iget-object v2, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static {v2, v3}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    :try_start_0
    invoke-virtual {p0, p1, v2}, Lc1/k2;->b(Lb0/y;Lcom/google/firebase/messaging/w;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lc1/k2;->d()V

    .line 18
    .line 19
    .line 20
    iget-object p1, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Landroid/opengl/EGLSurface;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lc1/k2;->k(Landroid/opengl/EGLSurface;)V

    .line 25
    .line 26
    .line 27
    const/16 p1, 0x1f03

    .line 28
    .line 29
    invoke-static {p1}, Landroid/opengl/GLES20;->glGetString(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iget-object v2, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v2, Landroid/opengl/EGLDisplay;

    .line 36
    .line 37
    const/16 v3, 0x3055

    .line 38
    .line 39
    invoke-static {v2, v3}, Landroid/opengl/EGL14;->eglQueryString(Landroid/opengl/EGLDisplay;I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    new-instance v3, Lc6/b;

    .line 44
    .line 45
    if-eqz p1, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move-object p1, v0

    .line 49
    :goto_0
    if-eqz v2, :cond_1

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    move-object v2, v0

    .line 53
    :goto_1
    invoke-direct {v3, p1, v2}, Lc6/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lc1/k2;->m()V

    .line 57
    .line 58
    .line 59
    return-object v3

    .line 60
    :catchall_0
    move-exception p1

    .line 61
    goto :goto_2

    .line 62
    :catch_0
    move-exception p1

    .line 63
    :try_start_1
    const-string v2, "OpenGlRenderer"

    .line 64
    .line 65
    new-instance v3, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-static {v2, v1, p1}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    new-instance p1, Lc6/b;

    .line 85
    .line 86
    invoke-direct {p1, v0, v0}, Lc6/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Lc1/k2;->m()V

    .line 90
    .line 91
    .line 92
    return-object p1

    .line 93
    :goto_2
    invoke-virtual {p0}, Lc1/k2;->m()V

    .line 94
    .line 95
    .line 96
    throw p1
.end method

.method public i(Lb0/y;)Lr0/a;
    .locals 6

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 2
    .line 3
    iget-object v0, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {v0, v1}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 12
    .line 13
    const/16 v2, 0x1a

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-direct {v1, v2, v3}, Lcom/google/firebase/messaging/w;-><init>(IZ)V

    .line 17
    .line 18
    .line 19
    const-string v2, "0.0"

    .line 20
    .line 21
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 22
    .line 23
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 24
    .line 25
    const-string v2, ""

    .line 26
    .line 27
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 28
    .line 29
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 30
    .line 31
    :try_start_0
    invoke-virtual {p1}, Lb0/y;->a()Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lc1/k2;->g(Lb0/y;)Lc6/b;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    iget-object v4, v3, Lc6/b;->a:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v4, Ljava/lang/String;

    .line 44
    .line 45
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    iget-object v3, v3, Lc6/b;->b:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v3, Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const-string v5, "GL_EXT_YUV_target"

    .line 56
    .line 57
    invoke-virtual {v4, v5}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-nez v5, :cond_0

    .line 62
    .line 63
    const-string p1, "OpenGlRenderer"

    .line 64
    .line 65
    const-string v5, "Device does not support GL_EXT_YUV_target. Fallback to SDR."

    .line 66
    .line 67
    invoke-static {p1, v5}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    sget-object p1, Lb0/y;->d:Lb0/y;

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catch_0
    move-exception p1

    .line 74
    goto/16 :goto_1

    .line 75
    .line 76
    :cond_0
    :goto_0
    invoke-static {v3, p1}, Lr0/i;->f(Ljava/lang/String;Lb0/y;)[I

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    iput-object v5, p0, Lc1/k2;->d:[I

    .line 81
    .line 82
    iput-object v4, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 83
    .line 84
    iput-object v3, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 85
    .line 86
    :cond_1
    invoke-virtual {p0, p1, v1}, Lc1/k2;->b(Lb0/y;Lcom/google/firebase/messaging/w;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Lc1/k2;->d()V

    .line 90
    .line 91
    .line 92
    iget-object v3, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v3, Landroid/opengl/EGLSurface;

    .line 95
    .line 96
    invoke-virtual {p0, v3}, Lc1/k2;->k(Landroid/opengl/EGLSurface;)V

    .line 97
    .line 98
    .line 99
    invoke-static {}, Lr0/i;->j()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    if-eqz v3, :cond_7

    .line 104
    .line 105
    iput-object v3, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 106
    .line 107
    invoke-static {p1}, Lr0/i;->g(Lb0/y;)Ljava/util/HashMap;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    iput-object p1, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 112
    .line 113
    invoke-static {}, Lr0/i;->h()I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    iput p1, p0, Lc1/k2;->e:I

    .line 118
    .line 119
    invoke-virtual {p0, p1}, Lc1/k2;->p(I)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 120
    .line 121
    .line 122
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    iput-object p1, p0, Lc1/k2;->h:Ljava/lang/Object;

    .line 127
    .line 128
    const/4 p0, 0x1

    .line 129
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 130
    .line 131
    .line 132
    iget-object p0, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast p0, Ljava/lang/String;

    .line 135
    .line 136
    if-nez p0, :cond_2

    .line 137
    .line 138
    const-string v2, " glVersion"

    .line 139
    .line 140
    :cond_2
    iget-object p0, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p0, Ljava/lang/String;

    .line 143
    .line 144
    if-nez p0, :cond_3

    .line 145
    .line 146
    const-string p0, " eglVersion"

    .line 147
    .line 148
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    :cond_3
    iget-object p0, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p0, Ljava/lang/String;

    .line 155
    .line 156
    if-nez p0, :cond_4

    .line 157
    .line 158
    const-string p0, " glExtensions"

    .line 159
    .line 160
    invoke-static {v2, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    :cond_4
    iget-object p0, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p0, Ljava/lang/String;

    .line 167
    .line 168
    if-nez p0, :cond_5

    .line 169
    .line 170
    const-string p0, " eglExtensions"

    .line 171
    .line 172
    invoke-static {v2, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    :cond_5
    invoke-virtual {v2}, Ljava/lang/String;->isEmpty()Z

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    if-eqz p0, :cond_6

    .line 181
    .line 182
    new-instance p0, Lr0/a;

    .line 183
    .line 184
    iget-object p1, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast p1, Ljava/lang/String;

    .line 187
    .line 188
    iget-object v0, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v0, Ljava/lang/String;

    .line 191
    .line 192
    iget-object v2, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v2, Ljava/lang/String;

    .line 195
    .line 196
    iget-object v1, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v1, Ljava/lang/String;

    .line 199
    .line 200
    invoke-direct {p0, p1, v0, v2, v1}, Lr0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    return-object p0

    .line 204
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 205
    .line 206
    const-string p1, "Missing required properties:"

    .line 207
    .line 208
    invoke-virtual {p1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :cond_7
    :try_start_1
    new-instance p1, Ljava/lang/NullPointerException;

    .line 217
    .line 218
    const-string v0, "Null glVersion"

    .line 219
    .line 220
    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p1
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 224
    :goto_1
    invoke-virtual {p0}, Lc1/k2;->m()V

    .line 225
    .line 226
    .line 227
    throw p1
.end method

.method public j(Lc1/p;Lc1/p;Lc1/p;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/b0;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroidx/collection/a0;

    .line 8
    .line 9
    iget-object v2, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Laq/a;

    .line 12
    .line 13
    sget-object v3, Lc1/e2;->c:Laq/a;

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    if-eq v2, v3, :cond_0

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v2, v4

    .line 21
    :goto_0
    iget-object v3, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v3, Lc1/p;

    .line 24
    .line 25
    if-nez v3, :cond_3

    .line 26
    .line 27
    invoke-virtual {p1}, Lc1/p;->c()Lc1/p;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iput-object v3, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 32
    .line 33
    invoke-virtual {p3}, Lc1/p;->c()Lc1/p;

    .line 34
    .line 35
    .line 36
    move-result-object p3

    .line 37
    iput-object p3, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 38
    .line 39
    iget p3, v1, Landroidx/collection/a0;->b:I

    .line 40
    .line 41
    new-array v3, p3, [F

    .line 42
    .line 43
    move v5, v4

    .line 44
    :goto_1
    if-ge v5, p3, :cond_1

    .line 45
    .line 46
    invoke-virtual {v1, v5}, Landroidx/collection/a0;->c(I)I

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    int-to-float v6, v6

    .line 51
    const-wide/16 v7, 0x3e8

    .line 52
    .line 53
    long-to-float v7, v7

    .line 54
    div-float/2addr v6, v7

    .line 55
    aput v6, v3, v5

    .line 56
    .line 57
    add-int/lit8 v5, v5, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    iput-object v3, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 61
    .line 62
    iget p3, v1, Landroidx/collection/a0;->b:I

    .line 63
    .line 64
    new-array v3, p3, [I

    .line 65
    .line 66
    move v5, v4

    .line 67
    :goto_2
    if-ge v5, p3, :cond_2

    .line 68
    .line 69
    invoke-virtual {v1, v5}, Landroidx/collection/a0;->c(I)I

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    invoke-virtual {v0, v6}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    check-cast v6, Lc1/j2;

    .line 78
    .line 79
    aput v4, v3, v5

    .line 80
    .line 81
    add-int/lit8 v5, v5, 0x1

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_2
    iput-object v3, p0, Lc1/k2;->d:[I

    .line 85
    .line 86
    :cond_3
    if-nez v2, :cond_4

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_4
    iget-object p3, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p3, Laq/a;

    .line 92
    .line 93
    sget-object v2, Lc1/e2;->c:Laq/a;

    .line 94
    .line 95
    if-eq p3, v2, :cond_6

    .line 96
    .line 97
    iget-object p3, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p3, Lc1/p;

    .line 100
    .line 101
    invoke-static {p3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p3

    .line 105
    if-eqz p3, :cond_6

    .line 106
    .line 107
    iget-object p3, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast p3, Lc1/p;

    .line 110
    .line 111
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p3

    .line 115
    if-nez p3, :cond_5

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_5
    :goto_3
    return-void

    .line 119
    :cond_6
    :goto_4
    iput-object p1, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 120
    .line 121
    iput-object p2, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 122
    .line 123
    invoke-virtual {p1}, Lc1/p;->b()I

    .line 124
    .line 125
    .line 126
    move-result p3

    .line 127
    rem-int/lit8 p3, p3, 0x2

    .line 128
    .line 129
    invoke-virtual {p1}, Lc1/p;->b()I

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    add-int/2addr v2, p3

    .line 134
    new-array p3, v2, [F

    .line 135
    .line 136
    iput-object p3, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 137
    .line 138
    new-array p3, v2, [F

    .line 139
    .line 140
    iput-object p3, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 141
    .line 142
    iget p3, v1, Landroidx/collection/a0;->b:I

    .line 143
    .line 144
    new-array v3, p3, [[F

    .line 145
    .line 146
    move v5, v4

    .line 147
    :goto_5
    if-ge v5, p3, :cond_b

    .line 148
    .line 149
    invoke-virtual {v1, v5}, Landroidx/collection/a0;->c(I)I

    .line 150
    .line 151
    .line 152
    move-result v6

    .line 153
    invoke-virtual {v0, v6}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    check-cast v7, Lc1/j2;

    .line 158
    .line 159
    if-nez v6, :cond_7

    .line 160
    .line 161
    if-nez v7, :cond_7

    .line 162
    .line 163
    new-array v6, v2, [F

    .line 164
    .line 165
    move v7, v4

    .line 166
    :goto_6
    if-ge v7, v2, :cond_a

    .line 167
    .line 168
    invoke-virtual {p1, v7}, Lc1/p;->a(I)F

    .line 169
    .line 170
    .line 171
    move-result v8

    .line 172
    aput v8, v6, v7

    .line 173
    .line 174
    add-int/lit8 v7, v7, 0x1

    .line 175
    .line 176
    goto :goto_6

    .line 177
    :cond_7
    iget v8, p0, Lc1/k2;->e:I

    .line 178
    .line 179
    if-ne v6, v8, :cond_8

    .line 180
    .line 181
    if-nez v7, :cond_8

    .line 182
    .line 183
    new-array v6, v2, [F

    .line 184
    .line 185
    move v7, v4

    .line 186
    :goto_7
    if-ge v7, v2, :cond_a

    .line 187
    .line 188
    invoke-virtual {p2, v7}, Lc1/p;->a(I)F

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    aput v8, v6, v7

    .line 193
    .line 194
    add-int/lit8 v7, v7, 0x1

    .line 195
    .line 196
    goto :goto_7

    .line 197
    :cond_8
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    iget-object v6, v7, Lc1/j2;->a:Lc1/p;

    .line 201
    .line 202
    new-array v7, v2, [F

    .line 203
    .line 204
    move v8, v4

    .line 205
    :goto_8
    if-ge v8, v2, :cond_9

    .line 206
    .line 207
    invoke-virtual {v6, v8}, Lc1/p;->a(I)F

    .line 208
    .line 209
    .line 210
    move-result v9

    .line 211
    aput v9, v7, v8

    .line 212
    .line 213
    add-int/lit8 v8, v8, 0x1

    .line 214
    .line 215
    goto :goto_8

    .line 216
    :cond_9
    move-object v6, v7

    .line 217
    :cond_a
    aput-object v6, v3, v5

    .line 218
    .line 219
    add-int/lit8 v5, v5, 0x1

    .line 220
    .line 221
    goto :goto_5

    .line 222
    :cond_b
    new-instance p1, Laq/a;

    .line 223
    .line 224
    iget-object p2, p0, Lc1/k2;->d:[I

    .line 225
    .line 226
    iget-object p3, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p3, [F

    .line 229
    .line 230
    invoke-direct {p1, p2, p3, v3}, Laq/a;-><init>([I[F[[F)V

    .line 231
    .line 232
    .line 233
    iput-object p1, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 234
    .line 235
    return-void
.end method

.method public k(Landroid/opengl/EGLSurface;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Landroid/opengl/EGLContext;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 18
    .line 19
    iget-object p0, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Landroid/opengl/EGLContext;

    .line 22
    .line 23
    invoke-static {v0, p1, p1, p0}, Landroid/opengl/EGL14;->eglMakeCurrent(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "eglMakeCurrent failed"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public l(Landroid/view/Surface;)V
    .locals 2

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
    iget-object p0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    sget-object v0, Lr0/i;->j:Lr0/c;

    .line 27
    .line 28
    invoke-virtual {p0, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method public m()V
    .locals 6

    .line 1
    iget-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/util/Map;

    .line 8
    .line 9
    invoke-interface {v1}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lr0/g;

    .line 28
    .line 29
    iget v2, v2, Lr0/g;->a:I

    .line 30
    .line 31
    invoke-static {v2}, Landroid/opengl/GLES20;->glDeleteProgram(I)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 36
    .line 37
    iput-object v1, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 38
    .line 39
    const/4 v1, 0x0

    .line 40
    iput-object v1, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 41
    .line 42
    iget-object v2, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v2, Landroid/opengl/EGLDisplay;

    .line 45
    .line 46
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 47
    .line 48
    invoke-static {v2, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-nez v2, :cond_5

    .line 53
    .line 54
    iget-object v2, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Landroid/opengl/EGLDisplay;

    .line 57
    .line 58
    sget-object v3, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 59
    .line 60
    sget-object v4, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 61
    .line 62
    invoke-static {v2, v3, v3, v4}, Landroid/opengl/EGL14;->eglMakeCurrent(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    :cond_1
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-eqz v3, :cond_2

    .line 78
    .line 79
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Lr0/c;

    .line 84
    .line 85
    iget-object v4, v3, Lr0/c;->a:Landroid/opengl/EGLSurface;

    .line 86
    .line 87
    sget-object v5, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 88
    .line 89
    invoke-static {v4, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-nez v4, :cond_1

    .line 94
    .line 95
    iget-object v4, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v4, Landroid/opengl/EGLDisplay;

    .line 98
    .line 99
    iget-object v3, v3, Lr0/c;->a:Landroid/opengl/EGLSurface;

    .line 100
    .line 101
    invoke-static {v4, v3}, Landroid/opengl/EGL14;->eglDestroySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-nez v3, :cond_1

    .line 106
    .line 107
    const-string v3, "eglDestroySurface"

    .line 108
    .line 109
    :try_start_0
    invoke-static {v3}, Lr0/i;->a(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :catch_0
    move-exception v3

    .line 114
    const-string v4, "GLUtils"

    .line 115
    .line 116
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    invoke-static {v4, v5, v3}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 121
    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_2
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 125
    .line 126
    .line 127
    iget-object v0, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v0, Landroid/opengl/EGLSurface;

    .line 130
    .line 131
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 132
    .line 133
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-nez v0, :cond_3

    .line 138
    .line 139
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 142
    .line 143
    iget-object v2, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v2, Landroid/opengl/EGLSurface;

    .line 146
    .line 147
    invoke-static {v0, v2}, Landroid/opengl/EGL14;->eglDestroySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 148
    .line 149
    .line 150
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_SURFACE:Landroid/opengl/EGLSurface;

    .line 151
    .line 152
    iput-object v0, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 153
    .line 154
    :cond_3
    iget-object v0, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v0, Landroid/opengl/EGLContext;

    .line 157
    .line 158
    sget-object v2, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 159
    .line 160
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    if-nez v0, :cond_4

    .line 165
    .line 166
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 169
    .line 170
    iget-object v2, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v2, Landroid/opengl/EGLContext;

    .line 173
    .line 174
    invoke-static {v0, v2}, Landroid/opengl/EGL14;->eglDestroyContext(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;)Z

    .line 175
    .line 176
    .line 177
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_CONTEXT:Landroid/opengl/EGLContext;

    .line 178
    .line 179
    iput-object v0, p0, Lc1/k2;->j:Ljava/lang/Object;

    .line 180
    .line 181
    :cond_4
    invoke-static {}, Landroid/opengl/EGL14;->eglReleaseThread()Z

    .line 182
    .line 183
    .line 184
    iget-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v0, Landroid/opengl/EGLDisplay;

    .line 187
    .line 188
    invoke-static {v0}, Landroid/opengl/EGL14;->eglTerminate(Landroid/opengl/EGLDisplay;)Z

    .line 189
    .line 190
    .line 191
    sget-object v0, Landroid/opengl/EGL14;->EGL_NO_DISPLAY:Landroid/opengl/EGLDisplay;

    .line 192
    .line 193
    iput-object v0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 194
    .line 195
    :cond_5
    iput-object v1, p0, Lc1/k2;->k:Ljava/lang/Object;

    .line 196
    .line 197
    const/4 v0, -0x1

    .line 198
    iput v0, p0, Lc1/k2;->e:I

    .line 199
    .line 200
    sget-object v0, Lr0/f;->d:Lr0/f;

    .line 201
    .line 202
    iput-object v0, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 203
    .line 204
    iput-object v1, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 205
    .line 206
    iput-object v1, p0, Lc1/k2;->h:Ljava/lang/Object;

    .line 207
    .line 208
    return-void
.end method

.method public n(Landroid/view/Surface;Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/k2;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/view/Surface;

    .line 8
    .line 9
    if-ne v1, p1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    iput-object v1, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v1, p0, Lc1/k2;->l:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Landroid/opengl/EGLSurface;

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lc1/k2;->k(Landroid/opengl/EGLSurface;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    if-eqz p2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Lr0/c;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    sget-object p2, Lr0/i;->j:Lr0/c;

    .line 31
    .line 32
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    check-cast p1, Lr0/c;

    .line 37
    .line 38
    :goto_0
    if-eqz p1, :cond_2

    .line 39
    .line 40
    sget-object p2, Lr0/i;->j:Lr0/c;

    .line 41
    .line 42
    if-eq p1, p2, :cond_2

    .line 43
    .line 44
    :try_start_0
    iget-object p0, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Landroid/opengl/EGLDisplay;

    .line 47
    .line 48
    iget-object p1, p1, Lr0/c;->a:Landroid/opengl/EGLSurface;

    .line 49
    .line 50
    invoke-static {p0, p1}, Landroid/opengl/EGL14;->eglDestroySurface(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :catch_0
    move-exception p0

    .line 55
    new-instance p1, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string p2, "Failed to destroy EGL surface: "

    .line 58
    .line 59
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    const-string p2, "OpenGlRenderer"

    .line 74
    .line 75
    invoke-static {p2, p1, p0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    return-void
.end method

.method public o(J[FLandroid/view/Surface;)V
    .locals 6

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
    invoke-virtual {v0, p4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    const-string v3, "The surface is not registered."

    .line 25
    .line 26
    invoke-static {v3, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    check-cast v2, Lr0/c;

    .line 34
    .line 35
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    sget-object v3, Lr0/i;->j:Lr0/c;

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-virtual {p0, p4}, Lc1/k2;->c(Landroid/view/Surface;)Lr0/c;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    if-nez v2, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v0, p4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    :cond_1
    iget v0, v2, Lr0/c;->c:I

    .line 53
    .line 54
    iget v3, v2, Lr0/c;->b:I

    .line 55
    .line 56
    iget-object v2, v2, Lr0/c;->a:Landroid/opengl/EGLSurface;

    .line 57
    .line 58
    iget-object v4, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v4, Landroid/view/Surface;

    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    if-eq p4, v4, :cond_2

    .line 64
    .line 65
    invoke-virtual {p0, v2}, Lc1/k2;->k(Landroid/opengl/EGLSurface;)V

    .line 66
    .line 67
    .line 68
    iput-object p4, p0, Lc1/k2;->m:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-static {v5, v5, v3, v0}, Landroid/opengl/GLES20;->glViewport(IIII)V

    .line 71
    .line 72
    .line 73
    invoke-static {v5, v5, v3, v0}, Landroid/opengl/GLES20;->glScissor(IIII)V

    .line 74
    .line 75
    .line 76
    :cond_2
    iget-object v0, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Lr0/g;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    instance-of v3, v0, Lr0/h;

    .line 84
    .line 85
    if-eqz v3, :cond_3

    .line 86
    .line 87
    check-cast v0, Lr0/h;

    .line 88
    .line 89
    iget v0, v0, Lr0/h;->f:I

    .line 90
    .line 91
    invoke-static {v0, v1, v5, p3, v5}, Landroid/opengl/GLES20;->glUniformMatrix4fv(IIZ[FI)V

    .line 92
    .line 93
    .line 94
    const-string p3, "glUniformMatrix4fv"

    .line 95
    .line 96
    invoke-static {p3}, Lr0/i;->b(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    :cond_3
    const/4 p3, 0x5

    .line 100
    const/4 v0, 0x4

    .line 101
    invoke-static {p3, v5, v0}, Landroid/opengl/GLES20;->glDrawArrays(III)V

    .line 102
    .line 103
    .line 104
    const-string p3, "glDrawArrays"

    .line 105
    .line 106
    invoke-static {p3}, Lr0/i;->b(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iget-object p3, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p3, Landroid/opengl/EGLDisplay;

    .line 112
    .line 113
    invoke-static {p3, v2, p1, p2}, Landroid/opengl/EGLExt;->eglPresentationTimeANDROID(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;J)Z

    .line 114
    .line 115
    .line 116
    iget-object p1, p0, Lc1/k2;->i:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p1, Landroid/opengl/EGLDisplay;

    .line 119
    .line 120
    invoke-static {p1, v2}, Landroid/opengl/EGL14;->eglSwapBuffers(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-nez p1, :cond_4

    .line 125
    .line 126
    new-instance p1, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    const-string p2, "Failed to swap buffers with EGL error: 0x"

    .line 129
    .line 130
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-static {}, Landroid/opengl/EGL14;->eglGetError()I

    .line 134
    .line 135
    .line 136
    move-result p2

    .line 137
    invoke-static {p2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    const-string p2, "OpenGlRenderer"

    .line 149
    .line 150
    invoke-static {p2, p1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0, p4, v5}, Lc1/k2;->n(Landroid/view/Surface;Z)V

    .line 154
    .line 155
    .line 156
    :cond_4
    :goto_0
    return-void
.end method

.method public p(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/k2;->n:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Map;

    .line 4
    .line 5
    iget-object v1, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lr0/f;

    .line 8
    .line 9
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lr0/g;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget-object v1, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lr0/g;

    .line 20
    .line 21
    if-eq v1, v0, :cond_0

    .line 22
    .line 23
    iput-object v0, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-virtual {v0}, Lr0/g;->b()V

    .line 26
    .line 27
    .line 28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v1, "Using program for input format "

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Lr0/f;

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ": "

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lc1/k2;->o:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lr0/g;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    const-string v0, "OpenGlRenderer"

    .line 59
    .line 60
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 61
    .line 62
    .line 63
    :cond_0
    const p0, 0x84c0

    .line 64
    .line 65
    .line 66
    invoke-static {p0}, Landroid/opengl/GLES20;->glActiveTexture(I)V

    .line 67
    .line 68
    .line 69
    const-string p0, "glActiveTexture"

    .line 70
    .line 71
    invoke-static {p0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const p0, 0x8d65

    .line 75
    .line 76
    .line 77
    invoke-static {p0, p1}, Landroid/opengl/GLES20;->glBindTexture(II)V

    .line 78
    .line 79
    .line 80
    const-string p0, "glBindTexture"

    .line 81
    .line 82
    invoke-static {p0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    new-instance v0, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v1, "Unable to configure program for input format: "

    .line 91
    .line 92
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object p0, p0, Lc1/k2;->p:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lr0/f;

    .line 98
    .line 99
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p1
.end method

.method public t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    iget-object v3, v0, Lc1/k2;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Landroidx/collection/a0;

    .line 10
    .line 11
    const-wide/32 v4, 0xf4240

    .line 12
    .line 13
    .line 14
    div-long v4, p1, v4

    .line 15
    .line 16
    sget-object v6, Lc1/e2;->a:[I

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    int-to-long v7, v6

    .line 20
    sub-long/2addr v4, v7

    .line 21
    iget v7, v0, Lc1/k2;->e:I

    .line 22
    .line 23
    int-to-long v8, v7

    .line 24
    const-wide/16 v10, 0x0

    .line 25
    .line 26
    cmp-long v12, v4, v10

    .line 27
    .line 28
    if-gez v12, :cond_0

    .line 29
    .line 30
    move-wide v4, v10

    .line 31
    :cond_0
    cmp-long v10, v4, v8

    .line 32
    .line 33
    if-lez v10, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-wide v8, v4

    .line 37
    :goto_0
    long-to-int v4, v8

    .line 38
    iget-object v5, v0, Lc1/k2;->g:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v5, Landroidx/collection/b0;

    .line 41
    .line 42
    invoke-virtual {v5, v4}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v8

    .line 46
    check-cast v8, Lc1/j2;

    .line 47
    .line 48
    if-eqz v8, :cond_2

    .line 49
    .line 50
    iget-object v0, v8, Lc1/j2;->a:Lc1/p;

    .line 51
    .line 52
    return-object v0

    .line 53
    :cond_2
    if-lt v4, v7, :cond_3

    .line 54
    .line 55
    return-object v2

    .line 56
    :cond_3
    if-gtz v4, :cond_4

    .line 57
    .line 58
    return-object v1

    .line 59
    :cond_4
    move-object/from16 v7, p5

    .line 60
    .line 61
    invoke-virtual {v0, v1, v2, v7}, Lc1/k2;->j(Lc1/p;Lc1/p;Lc1/p;)V

    .line 62
    .line 63
    .line 64
    iget-object v7, v0, Lc1/k2;->l:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v7, Lc1/p;

    .line 67
    .line 68
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iget-object v8, v0, Lc1/k2;->p:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v8, Laq/a;

    .line 74
    .line 75
    sget-object v9, Lc1/e2;->c:Laq/a;

    .line 76
    .line 77
    const/4 v10, 0x1

    .line 78
    if-eq v8, v9, :cond_e

    .line 79
    .line 80
    invoke-virtual {v0, v4}, Lc1/k2;->e(I)I

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    invoke-virtual {v0, v1, v4, v6}, Lc1/k2;->f(IIZ)F

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    iget-object v2, v0, Lc1/k2;->j:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v2, [F

    .line 91
    .line 92
    iget-object v0, v0, Lc1/k2;->p:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Laq/a;

    .line 95
    .line 96
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, [[Lc1/r;

    .line 99
    .line 100
    array-length v3, v0

    .line 101
    sub-int/2addr v3, v10

    .line 102
    aget-object v4, v0, v6

    .line 103
    .line 104
    aget-object v4, v4, v6

    .line 105
    .line 106
    iget v4, v4, Lc1/r;->a:F

    .line 107
    .line 108
    aget-object v5, v0, v3

    .line 109
    .line 110
    aget-object v5, v5, v6

    .line 111
    .line 112
    iget v5, v5, Lc1/r;->b:F

    .line 113
    .line 114
    array-length v8, v2

    .line 115
    cmpg-float v9, v1, v4

    .line 116
    .line 117
    if-ltz v9, :cond_a

    .line 118
    .line 119
    cmpl-float v9, v1, v5

    .line 120
    .line 121
    if-lez v9, :cond_5

    .line 122
    .line 123
    goto :goto_4

    .line 124
    :cond_5
    array-length v3, v0

    .line 125
    move v4, v6

    .line 126
    move v5, v4

    .line 127
    :goto_1
    if-ge v4, v3, :cond_d

    .line 128
    .line 129
    move v9, v6

    .line 130
    move v11, v9

    .line 131
    :goto_2
    add-int/lit8 v12, v8, -0x1

    .line 132
    .line 133
    if-ge v9, v12, :cond_8

    .line 134
    .line 135
    aget-object v12, v0, v4

    .line 136
    .line 137
    aget-object v12, v12, v11

    .line 138
    .line 139
    iget v13, v12, Lc1/r;->b:F

    .line 140
    .line 141
    cmpg-float v13, v1, v13

    .line 142
    .line 143
    if-gtz v13, :cond_7

    .line 144
    .line 145
    iget-boolean v5, v12, Lc1/r;->p:Z

    .line 146
    .line 147
    if-eqz v5, :cond_6

    .line 148
    .line 149
    iget v5, v12, Lc1/r;->a:F

    .line 150
    .line 151
    sub-float v13, v1, v5

    .line 152
    .line 153
    iget v14, v12, Lc1/r;->k:F

    .line 154
    .line 155
    mul-float/2addr v13, v14

    .line 156
    iget v15, v12, Lc1/r;->c:F

    .line 157
    .line 158
    iget v6, v12, Lc1/r;->e:F

    .line 159
    .line 160
    invoke-static {v6, v15, v13, v15}, La7/g0;->b(FFFF)F

    .line 161
    .line 162
    .line 163
    move-result v6

    .line 164
    aput v6, v2, v9

    .line 165
    .line 166
    add-int/lit8 v6, v9, 0x1

    .line 167
    .line 168
    sub-float v5, v1, v5

    .line 169
    .line 170
    mul-float/2addr v5, v14

    .line 171
    iget v13, v12, Lc1/r;->d:F

    .line 172
    .line 173
    iget v12, v12, Lc1/r;->f:F

    .line 174
    .line 175
    invoke-static {v12, v13, v5, v13}, La7/g0;->b(FFFF)F

    .line 176
    .line 177
    .line 178
    move-result v5

    .line 179
    aput v5, v2, v6

    .line 180
    .line 181
    goto :goto_3

    .line 182
    :cond_6
    invoke-virtual {v12, v1}, Lc1/r;->c(F)V

    .line 183
    .line 184
    .line 185
    iget v5, v12, Lc1/r;->q:F

    .line 186
    .line 187
    iget v6, v12, Lc1/r;->n:F

    .line 188
    .line 189
    iget v13, v12, Lc1/r;->h:F

    .line 190
    .line 191
    mul-float/2addr v6, v13

    .line 192
    add-float/2addr v6, v5

    .line 193
    aput v6, v2, v9

    .line 194
    .line 195
    add-int/lit8 v5, v9, 0x1

    .line 196
    .line 197
    iget v6, v12, Lc1/r;->r:F

    .line 198
    .line 199
    iget v13, v12, Lc1/r;->o:F

    .line 200
    .line 201
    iget v12, v12, Lc1/r;->i:F

    .line 202
    .line 203
    mul-float/2addr v13, v12

    .line 204
    add-float/2addr v13, v6

    .line 205
    aput v13, v2, v5

    .line 206
    .line 207
    :goto_3
    move v5, v10

    .line 208
    :cond_7
    add-int/lit8 v9, v9, 0x2

    .line 209
    .line 210
    add-int/lit8 v11, v11, 0x1

    .line 211
    .line 212
    const/4 v6, 0x0

    .line 213
    goto :goto_2

    .line 214
    :cond_8
    if-eqz v5, :cond_9

    .line 215
    .line 216
    goto/16 :goto_8

    .line 217
    .line 218
    :cond_9
    add-int/lit8 v4, v4, 0x1

    .line 219
    .line 220
    const/4 v6, 0x0

    .line 221
    goto :goto_1

    .line 222
    :cond_a
    :goto_4
    cmpl-float v6, v1, v5

    .line 223
    .line 224
    if-lez v6, :cond_b

    .line 225
    .line 226
    move v4, v5

    .line 227
    goto :goto_5

    .line 228
    :cond_b
    const/4 v3, 0x0

    .line 229
    :goto_5
    sub-float/2addr v1, v4

    .line 230
    const/4 v5, 0x0

    .line 231
    const/4 v6, 0x0

    .line 232
    :goto_6
    add-int/lit8 v9, v8, -0x1

    .line 233
    .line 234
    if-ge v5, v9, :cond_d

    .line 235
    .line 236
    aget-object v9, v0, v3

    .line 237
    .line 238
    aget-object v9, v9, v6

    .line 239
    .line 240
    iget-boolean v11, v9, Lc1/r;->p:Z

    .line 241
    .line 242
    iget v12, v9, Lc1/r;->r:F

    .line 243
    .line 244
    iget v13, v9, Lc1/r;->q:F

    .line 245
    .line 246
    if-eqz v11, :cond_c

    .line 247
    .line 248
    iget v11, v9, Lc1/r;->a:F

    .line 249
    .line 250
    sub-float v14, v4, v11

    .line 251
    .line 252
    iget v15, v9, Lc1/r;->k:F

    .line 253
    .line 254
    mul-float/2addr v14, v15

    .line 255
    iget v10, v9, Lc1/r;->c:F

    .line 256
    .line 257
    move-object/from16 p0, v0

    .line 258
    .line 259
    iget v0, v9, Lc1/r;->e:F

    .line 260
    .line 261
    invoke-static {v0, v10, v14, v10}, La7/g0;->b(FFFF)F

    .line 262
    .line 263
    .line 264
    move-result v0

    .line 265
    mul-float/2addr v13, v1

    .line 266
    add-float/2addr v13, v0

    .line 267
    aput v13, v2, v5

    .line 268
    .line 269
    add-int/lit8 v0, v5, 0x1

    .line 270
    .line 271
    sub-float v10, v4, v11

    .line 272
    .line 273
    mul-float/2addr v10, v15

    .line 274
    iget v11, v9, Lc1/r;->d:F

    .line 275
    .line 276
    iget v9, v9, Lc1/r;->f:F

    .line 277
    .line 278
    invoke-static {v9, v11, v10, v11}, La7/g0;->b(FFFF)F

    .line 279
    .line 280
    .line 281
    move-result v9

    .line 282
    mul-float/2addr v12, v1

    .line 283
    add-float/2addr v12, v9

    .line 284
    aput v12, v2, v0

    .line 285
    .line 286
    goto :goto_7

    .line 287
    :cond_c
    move-object/from16 p0, v0

    .line 288
    .line 289
    invoke-virtual {v9, v4}, Lc1/r;->c(F)V

    .line 290
    .line 291
    .line 292
    iget v0, v9, Lc1/r;->n:F

    .line 293
    .line 294
    iget v10, v9, Lc1/r;->h:F

    .line 295
    .line 296
    mul-float/2addr v0, v10

    .line 297
    add-float/2addr v0, v13

    .line 298
    invoke-virtual {v9}, Lc1/r;->a()F

    .line 299
    .line 300
    .line 301
    move-result v10

    .line 302
    mul-float/2addr v10, v1

    .line 303
    add-float/2addr v10, v0

    .line 304
    aput v10, v2, v5

    .line 305
    .line 306
    add-int/lit8 v0, v5, 0x1

    .line 307
    .line 308
    iget v10, v9, Lc1/r;->o:F

    .line 309
    .line 310
    iget v11, v9, Lc1/r;->i:F

    .line 311
    .line 312
    mul-float/2addr v10, v11

    .line 313
    add-float/2addr v10, v12

    .line 314
    invoke-virtual {v9}, Lc1/r;->b()F

    .line 315
    .line 316
    .line 317
    move-result v9

    .line 318
    mul-float/2addr v9, v1

    .line 319
    add-float/2addr v9, v10

    .line 320
    aput v9, v2, v0

    .line 321
    .line 322
    :goto_7
    add-int/lit8 v5, v5, 0x2

    .line 323
    .line 324
    add-int/lit8 v6, v6, 0x1

    .line 325
    .line 326
    const/4 v10, 0x1

    .line 327
    move-object/from16 v0, p0

    .line 328
    .line 329
    goto :goto_6

    .line 330
    :cond_d
    :goto_8
    array-length v0, v2

    .line 331
    const/4 v6, 0x0

    .line 332
    :goto_9
    if-ge v6, v0, :cond_13

    .line 333
    .line 334
    aget v1, v2, v6

    .line 335
    .line 336
    invoke-virtual {v7, v6, v1}, Lc1/p;->e(IF)V

    .line 337
    .line 338
    .line 339
    add-int/lit8 v6, v6, 0x1

    .line 340
    .line 341
    goto :goto_9

    .line 342
    :cond_e
    invoke-virtual {v0, v4}, Lc1/k2;->e(I)I

    .line 343
    .line 344
    .line 345
    move-result v6

    .line 346
    const/4 v8, 0x1

    .line 347
    invoke-virtual {v0, v6, v4, v8}, Lc1/k2;->f(IIZ)F

    .line 348
    .line 349
    .line 350
    move-result v0

    .line 351
    invoke-virtual {v3, v6}, Landroidx/collection/a0;->c(I)I

    .line 352
    .line 353
    .line 354
    move-result v4

    .line 355
    invoke-virtual {v5, v4}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v4

    .line 359
    check-cast v4, Lc1/j2;

    .line 360
    .line 361
    if-eqz v4, :cond_10

    .line 362
    .line 363
    iget-object v4, v4, Lc1/j2;->a:Lc1/p;

    .line 364
    .line 365
    if-nez v4, :cond_f

    .line 366
    .line 367
    goto :goto_a

    .line 368
    :cond_f
    move-object v1, v4

    .line 369
    :cond_10
    :goto_a
    add-int/2addr v6, v8

    .line 370
    invoke-virtual {v3, v6}, Landroidx/collection/a0;->c(I)I

    .line 371
    .line 372
    .line 373
    move-result v3

    .line 374
    invoke-virtual {v5, v3}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    check-cast v3, Lc1/j2;

    .line 379
    .line 380
    if-eqz v3, :cond_12

    .line 381
    .line 382
    iget-object v3, v3, Lc1/j2;->a:Lc1/p;

    .line 383
    .line 384
    if-nez v3, :cond_11

    .line 385
    .line 386
    goto :goto_b

    .line 387
    :cond_11
    move-object v2, v3

    .line 388
    :cond_12
    :goto_b
    invoke-virtual {v7}, Lc1/p;->b()I

    .line 389
    .line 390
    .line 391
    move-result v3

    .line 392
    const/4 v6, 0x0

    .line 393
    :goto_c
    if-ge v6, v3, :cond_13

    .line 394
    .line 395
    invoke-virtual {v1, v6}, Lc1/p;->a(I)F

    .line 396
    .line 397
    .line 398
    move-result v4

    .line 399
    invoke-virtual {v2, v6}, Lc1/p;->a(I)F

    .line 400
    .line 401
    .line 402
    move-result v5

    .line 403
    const/4 v8, 0x1

    .line 404
    int-to-float v9, v8

    .line 405
    sub-float/2addr v9, v0

    .line 406
    mul-float/2addr v9, v4

    .line 407
    mul-float/2addr v5, v0

    .line 408
    add-float/2addr v5, v9

    .line 409
    invoke-virtual {v7, v6, v5}, Lc1/p;->e(IF)V

    .line 410
    .line 411
    .line 412
    add-int/lit8 v6, v6, 0x1

    .line 413
    .line 414
    goto :goto_c

    .line 415
    :cond_13
    return-object v7
.end method

.method public u()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public y()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/k2;->e:I

    .line 2
    .line 3
    return p0
.end method
