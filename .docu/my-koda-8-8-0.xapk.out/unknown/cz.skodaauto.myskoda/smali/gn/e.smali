.class public final Lgn/e;
.super Landroid/animation/ValueAnimator;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/Choreographer$FrameCallback;


# instance fields
.field public final d:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public final e:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public final f:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public g:F

.field public h:Z

.field public i:J

.field public j:F

.field public k:F

.field public l:I

.field public m:F

.field public n:F

.field public o:Lum/a;

.field public p:Z


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroid/animation/ValueAnimator;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lgn/e;->d:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 17
    .line 18
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lgn/e;->f:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 24
    .line 25
    const/high16 v0, 0x3f800000    # 1.0f

    .line 26
    .line 27
    iput v0, p0, Lgn/e;->g:F

    .line 28
    .line 29
    const/4 v0, 0x0

    .line 30
    iput-boolean v0, p0, Lgn/e;->h:Z

    .line 31
    .line 32
    const-wide/16 v1, 0x0

    .line 33
    .line 34
    iput-wide v1, p0, Lgn/e;->i:J

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    iput v1, p0, Lgn/e;->j:F

    .line 38
    .line 39
    iput v1, p0, Lgn/e;->k:F

    .line 40
    .line 41
    iput v0, p0, Lgn/e;->l:I

    .line 42
    .line 43
    const/high16 v1, -0x31000000

    .line 44
    .line 45
    iput v1, p0, Lgn/e;->m:F

    .line 46
    .line 47
    const/high16 v1, 0x4f000000

    .line 48
    .line 49
    iput v1, p0, Lgn/e;->n:F

    .line 50
    .line 51
    iput-boolean v0, p0, Lgn/e;->p:Z

    .line 52
    .line 53
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget p0, p0, Lgn/e;->k:F

    .line 8
    .line 9
    iget v1, v0, Lum/a;->l:F

    .line 10
    .line 11
    sub-float/2addr p0, v1

    .line 12
    iget v0, v0, Lum/a;->m:F

    .line 13
    .line 14
    sub-float/2addr v0, v1

    .line 15
    div-float/2addr p0, v0

    .line 16
    return p0
.end method

.method public final addListener(Landroid/animation/Animator$AnimatorListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addPauseListener(Landroid/animation/Animator$AnimatorPauseListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->f:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->d:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b()F
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget p0, p0, Lgn/e;->n:F

    .line 8
    .line 9
    const/high16 v1, 0x4f000000

    .line 10
    .line 11
    cmpl-float v1, p0, v1

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget p0, v0, Lum/a;->m:F

    .line 16
    .line 17
    :cond_1
    return p0
.end method

.method public final c()F
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget p0, p0, Lgn/e;->m:F

    .line 8
    .line 9
    const/high16 v1, -0x31000000

    .line 10
    .line 11
    cmpl-float v1, p0, v1

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget p0, v0, Lum/a;->l:F

    .line 16
    .line 17
    :cond_1
    return p0
.end method

.method public final cancel()V
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/animation/Animator$AnimatorListener;

    .line 18
    .line 19
    invoke-interface {v1, p0}, Landroid/animation/Animator$AnimatorListener;->onAnimationCancel(Landroid/animation/Animator;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {p0}, Lgn/e;->d()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p0, v0}, Lgn/e;->e(Z)V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    invoke-virtual {p0, v0}, Lgn/e;->h(Z)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final d()Z
    .locals 1

    .line 1
    iget p0, p0, Lgn/e;->g:F

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    cmpg-float p0, p0, v0

    .line 5
    .line 6
    if-gez p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public final doFrame(J)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lgn/e;->p:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lgn/e;->h(Z)V

    .line 7
    .line 8
    .line 9
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {v0, p0}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 17
    .line 18
    if-eqz v0, :cond_d

    .line 19
    .line 20
    iget-boolean v2, p0, Lgn/e;->p:Z

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    goto/16 :goto_6

    .line 25
    .line 26
    :cond_1
    iget-wide v2, p0, Lgn/e;->i:J

    .line 27
    .line 28
    const-wide/16 v4, 0x0

    .line 29
    .line 30
    cmp-long v6, v2, v4

    .line 31
    .line 32
    if-nez v6, :cond_2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    sub-long v4, p1, v2

    .line 36
    .line 37
    :goto_0
    const v2, 0x4e6e6b28    # 1.0E9f

    .line 38
    .line 39
    .line 40
    iget v0, v0, Lum/a;->n:F

    .line 41
    .line 42
    div-float/2addr v2, v0

    .line 43
    iget v0, p0, Lgn/e;->g:F

    .line 44
    .line 45
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    div-float/2addr v2, v0

    .line 50
    long-to-float v0, v4

    .line 51
    div-float/2addr v0, v2

    .line 52
    iget v2, p0, Lgn/e;->j:F

    .line 53
    .line 54
    invoke-virtual {p0}, Lgn/e;->d()Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-eqz v3, :cond_3

    .line 59
    .line 60
    neg-float v0, v0

    .line 61
    :cond_3
    add-float/2addr v2, v0

    .line 62
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    sget-object v4, Lgn/f;->a:Landroid/graphics/PointF;

    .line 71
    .line 72
    cmpl-float v0, v2, v0

    .line 73
    .line 74
    const/4 v4, 0x1

    .line 75
    if-ltz v0, :cond_4

    .line 76
    .line 77
    cmpg-float v0, v2, v3

    .line 78
    .line 79
    if-gtz v0, :cond_4

    .line 80
    .line 81
    move v1, v4

    .line 82
    :cond_4
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    invoke-static {v2, v0, v3}, Lgn/f;->b(FFF)F

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    iput v0, p0, Lgn/e;->j:F

    .line 95
    .line 96
    iput v0, p0, Lgn/e;->k:F

    .line 97
    .line 98
    iput-wide p1, p0, Lgn/e;->i:J

    .line 99
    .line 100
    if-nez v1, :cond_a

    .line 101
    .line 102
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->getRepeatCount()I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    const/4 v1, -0x1

    .line 107
    if-eq v0, v1, :cond_6

    .line 108
    .line 109
    iget v0, p0, Lgn/e;->l:I

    .line 110
    .line 111
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->getRepeatCount()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-lt v0, v1, :cond_6

    .line 116
    .line 117
    iget p1, p0, Lgn/e;->g:F

    .line 118
    .line 119
    const/4 p2, 0x0

    .line 120
    cmpg-float p1, p1, p2

    .line 121
    .line 122
    if-gez p1, :cond_5

    .line 123
    .line 124
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    goto :goto_1

    .line 129
    :cond_5
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    :goto_1
    iput p1, p0, Lgn/e;->j:F

    .line 134
    .line 135
    iput p1, p0, Lgn/e;->k:F

    .line 136
    .line 137
    invoke-virtual {p0, v4}, Lgn/e;->h(Z)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Lgn/e;->f()V

    .line 141
    .line 142
    .line 143
    invoke-virtual {p0}, Lgn/e;->d()Z

    .line 144
    .line 145
    .line 146
    move-result p1

    .line 147
    invoke-virtual {p0, p1}, Lgn/e;->e(Z)V

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_6
    invoke-virtual {p0}, Landroid/animation/ValueAnimator;->getRepeatMode()I

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    const/4 v1, 0x2

    .line 156
    if-ne v0, v1, :cond_7

    .line 157
    .line 158
    iget-boolean v0, p0, Lgn/e;->h:Z

    .line 159
    .line 160
    xor-int/2addr v0, v4

    .line 161
    iput-boolean v0, p0, Lgn/e;->h:Z

    .line 162
    .line 163
    iget v0, p0, Lgn/e;->g:F

    .line 164
    .line 165
    neg-float v0, v0

    .line 166
    iput v0, p0, Lgn/e;->g:F

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_7
    invoke-virtual {p0}, Lgn/e;->d()Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-eqz v0, :cond_8

    .line 174
    .line 175
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    goto :goto_2

    .line 180
    :cond_8
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    :goto_2
    iput v0, p0, Lgn/e;->j:F

    .line 185
    .line 186
    iput v0, p0, Lgn/e;->k:F

    .line 187
    .line 188
    :goto_3
    iput-wide p1, p0, Lgn/e;->i:J

    .line 189
    .line 190
    invoke-virtual {p0}, Lgn/e;->f()V

    .line 191
    .line 192
    .line 193
    iget-object p1, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 194
    .line 195
    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 200
    .line 201
    .line 202
    move-result p2

    .line 203
    if-eqz p2, :cond_9

    .line 204
    .line 205
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p2

    .line 209
    check-cast p2, Landroid/animation/Animator$AnimatorListener;

    .line 210
    .line 211
    invoke-interface {p2, p0}, Landroid/animation/Animator$AnimatorListener;->onAnimationRepeat(Landroid/animation/Animator;)V

    .line 212
    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_9
    iget p1, p0, Lgn/e;->l:I

    .line 216
    .line 217
    add-int/2addr p1, v4

    .line 218
    iput p1, p0, Lgn/e;->l:I

    .line 219
    .line 220
    goto :goto_5

    .line 221
    :cond_a
    invoke-virtual {p0}, Lgn/e;->f()V

    .line 222
    .line 223
    .line 224
    :goto_5
    iget-object p1, p0, Lgn/e;->o:Lum/a;

    .line 225
    .line 226
    if-nez p1, :cond_b

    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_b
    iget p1, p0, Lgn/e;->k:F

    .line 230
    .line 231
    iget p2, p0, Lgn/e;->m:F

    .line 232
    .line 233
    cmpg-float p2, p1, p2

    .line 234
    .line 235
    if-ltz p2, :cond_c

    .line 236
    .line 237
    iget p2, p0, Lgn/e;->n:F

    .line 238
    .line 239
    cmpl-float p1, p1, p2

    .line 240
    .line 241
    if-gtz p1, :cond_c

    .line 242
    .line 243
    goto :goto_6

    .line 244
    :cond_c
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 245
    .line 246
    iget p2, p0, Lgn/e;->m:F

    .line 247
    .line 248
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 249
    .line 250
    .line 251
    move-result-object p2

    .line 252
    iget v0, p0, Lgn/e;->n:F

    .line 253
    .line 254
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    iget p0, p0, Lgn/e;->k:F

    .line 259
    .line 260
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    filled-new-array {p2, v0, p0}, [Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    const-string p2, "Frame must be [%f,%f]. It is %f"

    .line 269
    .line 270
    invoke-static {p2, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    throw p1

    .line 278
    :cond_d
    :goto_6
    return-void
.end method

.method public final e(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/animation/Animator$AnimatorListener;

    .line 18
    .line 19
    invoke-interface {v1, p0, p1}, Landroid/animation/Animator$AnimatorListener;->onAnimationEnd(Landroid/animation/Animator;Z)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public final f()V
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->d:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/animation/ValueAnimator$AnimatorUpdateListener;

    .line 18
    .line 19
    invoke-interface {v1, p0}, Landroid/animation/ValueAnimator$AnimatorUpdateListener;->onAnimationUpdate(Landroid/animation/ValueAnimator;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public final getAnimatedFraction()F
    .locals 2

    .line 1
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Lgn/e;->d()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iget v1, p0, Lgn/e;->k:F

    .line 18
    .line 19
    sub-float/2addr v0, v1

    .line 20
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    :goto_0
    sub-float/2addr v1, p0

    .line 29
    div-float/2addr v0, v1

    .line 30
    return v0

    .line 31
    :cond_1
    iget v0, p0, Lgn/e;->k:F

    .line 32
    .line 33
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    sub-float/2addr v0, v1

    .line 38
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    goto :goto_0
.end method

.method public final getAnimatedValue()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lgn/e;->a()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getDuration()J
    .locals 2

    .line 1
    iget-object p0, p0, Lgn/e;->o:Lum/a;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    return-wide v0

    .line 8
    :cond_0
    invoke-virtual {p0}, Lum/a;->b()F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    float-to-long v0, p0

    .line 13
    return-wide v0
.end method

.method public final getStartDelay()J
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "LottieAnimator does not support getStartDelay."

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final h(Z)V
    .locals 1

    .line 1
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p0}, Landroid/view/Choreographer;->removeFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 6
    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    iput-boolean p1, p0, Lgn/e;->p:Z

    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final i(F)V
    .locals 2

    .line 1
    iget v0, p0, Lgn/e;->j:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0}, Lgn/e;->c()F

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p0}, Lgn/e;->b()F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-static {p1, v0, v1}, Lgn/f;->b(FFF)F

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iput p1, p0, Lgn/e;->j:F

    .line 21
    .line 22
    iput p1, p0, Lgn/e;->k:F

    .line 23
    .line 24
    const-wide/16 v0, 0x0

    .line 25
    .line 26
    iput-wide v0, p0, Lgn/e;->i:J

    .line 27
    .line 28
    invoke-virtual {p0}, Lgn/e;->f()V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final isRunning()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lgn/e;->p:Z

    .line 2
    .line 3
    return p0
.end method

.method public final j(FF)V
    .locals 2

    .line 1
    cmpl-float v0, p1, p2

    .line 2
    .line 3
    if-gtz v0, :cond_4

    .line 4
    .line 5
    iget-object v0, p0, Lgn/e;->o:Lum/a;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const v1, -0x800001

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget v1, v0, Lum/a;->l:F

    .line 14
    .line 15
    :goto_0
    if-nez v0, :cond_1

    .line 16
    .line 17
    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 18
    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    iget v0, v0, Lum/a;->m:F

    .line 22
    .line 23
    :goto_1
    invoke-static {p1, v1, v0}, Lgn/f;->b(FFF)F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    invoke-static {p2, v1, v0}, Lgn/f;->b(FFF)F

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    iget v0, p0, Lgn/e;->m:F

    .line 32
    .line 33
    cmpl-float v0, p1, v0

    .line 34
    .line 35
    if-nez v0, :cond_3

    .line 36
    .line 37
    iget v0, p0, Lgn/e;->n:F

    .line 38
    .line 39
    cmpl-float v0, p2, v0

    .line 40
    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    return-void

    .line 45
    :cond_3
    :goto_2
    iput p1, p0, Lgn/e;->m:F

    .line 46
    .line 47
    iput p2, p0, Lgn/e;->n:F

    .line 48
    .line 49
    iget v0, p0, Lgn/e;->k:F

    .line 50
    .line 51
    invoke-static {v0, p1, p2}, Lgn/f;->b(FFF)F

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    float-to-int p1, p1

    .line 56
    int-to-float p1, p1

    .line 57
    invoke-virtual {p0, p1}, Lgn/e;->i(F)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    new-instance v0, Ljava/lang/StringBuilder;

    .line 64
    .line 65
    const-string v1, "minFrame ("

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string p1, ") must be <= maxFrame ("

    .line 74
    .line 75
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string p1, ")"

    .line 82
    .line 83
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0
.end method

.method public final removeAllListeners()V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeAllUpdateListeners()V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->d:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeListener(Landroid/animation/Animator$AnimatorListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->remove(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removePauseListener(Landroid/animation/Animator$AnimatorPauseListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->f:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->remove(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgn/e;->d:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->remove(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final bridge synthetic setDuration(J)Landroid/animation/Animator;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lgn/e;->setDuration(J)Landroid/animation/ValueAnimator;

    const/4 p0, 0x0

    throw p0
.end method

.method public final setDuration(J)Landroid/animation/ValueAnimator;
    .locals 0

    .line 2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    const-string p1, "LottieAnimator does not support setDuration."

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final setInterpolator(Landroid/animation/TimeInterpolator;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "LottieAnimator does not support setInterpolator."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final setRepeatMode(I)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroid/animation/ValueAnimator;->setRepeatMode(I)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p1, v0, :cond_0

    .line 6
    .line 7
    iget-boolean p1, p0, Lgn/e;->h:Z

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    iput-boolean p1, p0, Lgn/e;->h:Z

    .line 13
    .line 14
    iget p1, p0, Lgn/e;->g:F

    .line 15
    .line 16
    neg-float p1, p1

    .line 17
    iput p1, p0, Lgn/e;->g:F

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final setStartDelay(J)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "LottieAnimator does not support setStartDelay."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
