.class public final Lka/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public d:I

.field public e:I

.field public f:Landroid/widget/OverScroller;

.field public g:Landroid/view/animation/Interpolator;

.field public h:Z

.field public i:Z

.field public final synthetic j:Landroidx/recyclerview/widget/RecyclerView;


# direct methods
.method public constructor <init>(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lka/u0;->j:Landroidx/recyclerview/widget/RecyclerView;

    .line 5
    .line 6
    sget-object v0, Landroidx/recyclerview/widget/RecyclerView;->O1:Lk6/d;

    .line 7
    .line 8
    iput-object v0, p0, Lka/u0;->g:Landroid/view/animation/Interpolator;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-boolean v1, p0, Lka/u0;->h:Z

    .line 12
    .line 13
    iput-boolean v1, p0, Lka/u0;->i:Z

    .line 14
    .line 15
    new-instance v1, Landroid/widget/OverScroller;

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-direct {v1, p1, v0}, Landroid/widget/OverScroller;-><init>(Landroid/content/Context;Landroid/view/animation/Interpolator;)V

    .line 22
    .line 23
    .line 24
    iput-object v1, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(II)V
    .locals 12

    .line 1
    const/4 v0, 0x2

    .line 2
    iget-object v1, p0, Lka/u0;->j:Landroidx/recyclerview/widget/RecyclerView;

    .line 3
    .line 4
    invoke-virtual {v1, v0}, Landroidx/recyclerview/widget/RecyclerView;->setScrollState(I)V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput v0, p0, Lka/u0;->e:I

    .line 9
    .line 10
    iput v0, p0, Lka/u0;->d:I

    .line 11
    .line 12
    iget-object v0, p0, Lka/u0;->g:Landroid/view/animation/Interpolator;

    .line 13
    .line 14
    sget-object v2, Landroidx/recyclerview/widget/RecyclerView;->O1:Lk6/d;

    .line 15
    .line 16
    if-eq v0, v2, :cond_0

    .line 17
    .line 18
    iput-object v2, p0, Lka/u0;->g:Landroid/view/animation/Interpolator;

    .line 19
    .line 20
    new-instance v0, Landroid/widget/OverScroller;

    .line 21
    .line 22
    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-direct {v0, v1, v2}, Landroid/widget/OverScroller;-><init>(Landroid/content/Context;Landroid/view/animation/Interpolator;)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 30
    .line 31
    :cond_0
    iget-object v3, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 32
    .line 33
    const/high16 v10, -0x80000000

    .line 34
    .line 35
    const v11, 0x7fffffff

    .line 36
    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    const/high16 v8, -0x80000000

    .line 41
    .line 42
    const v9, 0x7fffffff

    .line 43
    .line 44
    .line 45
    move v6, p1

    .line 46
    move v7, p2

    .line 47
    invoke-virtual/range {v3 .. v11}, Landroid/widget/OverScroller;->fling(IIIIIIII)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Lka/u0;->b()V

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lka/u0;->h:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lka/u0;->i:Z

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lka/u0;->j:Landroidx/recyclerview/widget/RecyclerView;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 12
    .line 13
    .line 14
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final c(IIILandroid/view/animation/Interpolator;)V
    .locals 9

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lka/u0;->j:Landroidx/recyclerview/widget/RecyclerView;

    .line 5
    .line 6
    if-ne p3, v0, :cond_3

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 9
    .line 10
    .line 11
    move-result p3

    .line 12
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-le p3, v0, :cond_0

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v3, v1

    .line 21
    :goto_0
    if-eqz v3, :cond_1

    .line 22
    .line 23
    invoke-virtual {v2}, Landroid/view/View;->getWidth()I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-virtual {v2}, Landroid/view/View;->getHeight()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    :goto_1
    if-eqz v3, :cond_2

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move p3, v0

    .line 36
    :goto_2
    int-to-float p3, p3

    .line 37
    int-to-float v0, v4

    .line 38
    div-float/2addr p3, v0

    .line 39
    const/high16 v0, 0x3f800000    # 1.0f

    .line 40
    .line 41
    add-float/2addr p3, v0

    .line 42
    const/high16 v0, 0x43960000    # 300.0f

    .line 43
    .line 44
    mul-float/2addr p3, v0

    .line 45
    float-to-int p3, p3

    .line 46
    const/16 v0, 0x7d0

    .line 47
    .line 48
    invoke-static {p3, v0}, Ljava/lang/Math;->min(II)I

    .line 49
    .line 50
    .line 51
    move-result p3

    .line 52
    :cond_3
    move v8, p3

    .line 53
    if-nez p4, :cond_4

    .line 54
    .line 55
    sget-object p4, Landroidx/recyclerview/widget/RecyclerView;->O1:Lk6/d;

    .line 56
    .line 57
    :cond_4
    iget-object p3, p0, Lka/u0;->g:Landroid/view/animation/Interpolator;

    .line 58
    .line 59
    if-eq p3, p4, :cond_5

    .line 60
    .line 61
    iput-object p4, p0, Lka/u0;->g:Landroid/view/animation/Interpolator;

    .line 62
    .line 63
    new-instance p3, Landroid/widget/OverScroller;

    .line 64
    .line 65
    invoke-virtual {v2}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-direct {p3, v0, p4}, Landroid/widget/OverScroller;-><init>(Landroid/content/Context;Landroid/view/animation/Interpolator;)V

    .line 70
    .line 71
    .line 72
    iput-object p3, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 73
    .line 74
    :cond_5
    iput v1, p0, Lka/u0;->e:I

    .line 75
    .line 76
    iput v1, p0, Lka/u0;->d:I

    .line 77
    .line 78
    const/4 p3, 0x2

    .line 79
    invoke-virtual {v2, p3}, Landroidx/recyclerview/widget/RecyclerView;->setScrollState(I)V

    .line 80
    .line 81
    .line 82
    iget-object v3, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 83
    .line 84
    const/4 v4, 0x0

    .line 85
    const/4 v5, 0x0

    .line 86
    move v6, p1

    .line 87
    move v7, p2

    .line 88
    invoke-virtual/range {v3 .. v8}, Landroid/widget/OverScroller;->startScroll(IIIII)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Lka/u0;->b()V

    .line 92
    .line 93
    .line 94
    return-void
.end method

.method public final run()V
    .locals 14

    .line 1
    iget-object v0, p0, Lka/u0;->j:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    iget-object v8, v0, Landroidx/recyclerview/widget/RecyclerView;->C1:[I

    .line 4
    .line 5
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    const/4 v9, 0x0

    .line 19
    iput-boolean v9, p0, Lka/u0;->i:Z

    .line 20
    .line 21
    const/4 v10, 0x1

    .line 22
    iput-boolean v10, p0, Lka/u0;->h:Z

    .line 23
    .line 24
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->n()V

    .line 25
    .line 26
    .line 27
    iget-object v11, p0, Lka/u0;->f:Landroid/widget/OverScroller;

    .line 28
    .line 29
    invoke-virtual {v11}, Landroid/widget/OverScroller;->computeScrollOffset()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1d

    .line 34
    .line 35
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getCurrX()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getCurrY()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    iget v3, p0, Lka/u0;->d:I

    .line 44
    .line 45
    sub-int v3, v1, v3

    .line 46
    .line 47
    iget v4, p0, Lka/u0;->e:I

    .line 48
    .line 49
    sub-int v4, v2, v4

    .line 50
    .line 51
    iput v1, p0, Lka/u0;->d:I

    .line 52
    .line 53
    iput v2, p0, Lka/u0;->e:I

    .line 54
    .line 55
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->I:Landroid/widget/EdgeEffect;

    .line 56
    .line 57
    iget-object v2, v0, Landroidx/recyclerview/widget/RecyclerView;->K:Landroid/widget/EdgeEffect;

    .line 58
    .line 59
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    invoke-static {v3, v1, v2, v5}, Landroidx/recyclerview/widget/RecyclerView;->m(ILandroid/widget/EdgeEffect;Landroid/widget/EdgeEffect;I)I

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    iget-object v2, v0, Landroidx/recyclerview/widget/RecyclerView;->J:Landroid/widget/EdgeEffect;

    .line 68
    .line 69
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->L:Landroid/widget/EdgeEffect;

    .line 70
    .line 71
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    invoke-static {v4, v2, v3, v5}, Landroidx/recyclerview/widget/RecyclerView;->m(ILandroid/widget/EdgeEffect;Landroid/widget/EdgeEffect;I)I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    iget-object v4, v0, Landroidx/recyclerview/widget/RecyclerView;->C1:[I

    .line 80
    .line 81
    aput v9, v4, v9

    .line 82
    .line 83
    aput v9, v4, v10

    .line 84
    .line 85
    const/4 v5, 0x0

    .line 86
    const/4 v3, 0x1

    .line 87
    invoke-virtual/range {v0 .. v5}, Landroidx/recyclerview/widget/RecyclerView;->s(III[I[I)Z

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    if-eqz v3, :cond_1

    .line 92
    .line 93
    aget v3, v8, v9

    .line 94
    .line 95
    sub-int/2addr v1, v3

    .line 96
    aget v3, v8, v10

    .line 97
    .line 98
    sub-int/2addr v2, v3

    .line 99
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getOverScrollMode()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    const/4 v12, 0x2

    .line 104
    if-eq v3, v12, :cond_2

    .line 105
    .line 106
    invoke-virtual {v0, v1, v2}, Landroidx/recyclerview/widget/RecyclerView;->l(II)V

    .line 107
    .line 108
    .line 109
    :cond_2
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->o:Lka/y;

    .line 110
    .line 111
    if-eqz v3, :cond_6

    .line 112
    .line 113
    aput v9, v8, v9

    .line 114
    .line 115
    aput v9, v8, v10

    .line 116
    .line 117
    invoke-virtual {v0, v1, v2, v8}, Landroidx/recyclerview/widget/RecyclerView;->b0(II[I)V

    .line 118
    .line 119
    .line 120
    aget v3, v8, v9

    .line 121
    .line 122
    aget v4, v8, v10

    .line 123
    .line 124
    sub-int/2addr v1, v3

    .line 125
    sub-int/2addr v2, v4

    .line 126
    iget-object v5, v0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 127
    .line 128
    iget-object v5, v5, Lka/f0;->e:Lka/s;

    .line 129
    .line 130
    if-eqz v5, :cond_5

    .line 131
    .line 132
    iget-boolean v6, v5, Lka/s;->d:Z

    .line 133
    .line 134
    if-nez v6, :cond_5

    .line 135
    .line 136
    iget-boolean v6, v5, Lka/s;->e:Z

    .line 137
    .line 138
    if-eqz v6, :cond_5

    .line 139
    .line 140
    iget-object v6, v0, Landroidx/recyclerview/widget/RecyclerView;->q1:Lka/r0;

    .line 141
    .line 142
    invoke-virtual {v6}, Lka/r0;->b()I

    .line 143
    .line 144
    .line 145
    move-result v6

    .line 146
    if-nez v6, :cond_3

    .line 147
    .line 148
    invoke-virtual {v5}, Lka/s;->i()V

    .line 149
    .line 150
    .line 151
    goto :goto_0

    .line 152
    :cond_3
    iget v7, v5, Lka/s;->a:I

    .line 153
    .line 154
    if-lt v7, v6, :cond_4

    .line 155
    .line 156
    sub-int/2addr v6, v10

    .line 157
    iput v6, v5, Lka/s;->a:I

    .line 158
    .line 159
    invoke-virtual {v5, v3, v4}, Lka/s;->g(II)V

    .line 160
    .line 161
    .line 162
    goto :goto_0

    .line 163
    :cond_4
    invoke-virtual {v5, v3, v4}, Lka/s;->g(II)V

    .line 164
    .line 165
    .line 166
    :cond_5
    :goto_0
    move v13, v3

    .line 167
    move v3, v1

    .line 168
    move v1, v13

    .line 169
    move v13, v4

    .line 170
    move v4, v2

    .line 171
    move v2, v13

    .line 172
    goto :goto_1

    .line 173
    :cond_6
    move v3, v1

    .line 174
    move v4, v2

    .line 175
    move v1, v9

    .line 176
    move v2, v1

    .line 177
    :goto_1
    iget-object v5, v0, Landroidx/recyclerview/widget/RecyclerView;->r:Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    if-nez v5, :cond_7

    .line 184
    .line 185
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 186
    .line 187
    .line 188
    :cond_7
    iget-object v7, v0, Landroidx/recyclerview/widget/RecyclerView;->C1:[I

    .line 189
    .line 190
    aput v9, v7, v9

    .line 191
    .line 192
    aput v9, v7, v10

    .line 193
    .line 194
    const/4 v5, 0x0

    .line 195
    const/4 v6, 0x1

    .line 196
    invoke-virtual/range {v0 .. v7}, Landroidx/recyclerview/widget/RecyclerView;->t(IIII[II[I)V

    .line 197
    .line 198
    .line 199
    aget v5, v8, v9

    .line 200
    .line 201
    sub-int/2addr v3, v5

    .line 202
    aget v5, v8, v10

    .line 203
    .line 204
    sub-int/2addr v4, v5

    .line 205
    if-nez v1, :cond_8

    .line 206
    .line 207
    if-eqz v2, :cond_9

    .line 208
    .line 209
    :cond_8
    invoke-virtual {v0, v1, v2}, Landroidx/recyclerview/widget/RecyclerView;->u(II)V

    .line 210
    .line 211
    .line 212
    :cond_9
    invoke-static {v0}, Landroidx/recyclerview/widget/RecyclerView;->d(Landroidx/recyclerview/widget/RecyclerView;)Z

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    if-nez v5, :cond_a

    .line 217
    .line 218
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 219
    .line 220
    .line 221
    :cond_a
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getCurrX()I

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getFinalX()I

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    if-ne v5, v6, :cond_b

    .line 230
    .line 231
    move v5, v10

    .line 232
    goto :goto_2

    .line 233
    :cond_b
    move v5, v9

    .line 234
    :goto_2
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getCurrY()I

    .line 235
    .line 236
    .line 237
    move-result v6

    .line 238
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getFinalY()I

    .line 239
    .line 240
    .line 241
    move-result v7

    .line 242
    if-ne v6, v7, :cond_c

    .line 243
    .line 244
    move v6, v10

    .line 245
    goto :goto_3

    .line 246
    :cond_c
    move v6, v9

    .line 247
    :goto_3
    invoke-virtual {v11}, Landroid/widget/OverScroller;->isFinished()Z

    .line 248
    .line 249
    .line 250
    move-result v7

    .line 251
    if-nez v7, :cond_f

    .line 252
    .line 253
    if-nez v5, :cond_d

    .line 254
    .line 255
    if-eqz v3, :cond_e

    .line 256
    .line 257
    :cond_d
    if-nez v6, :cond_f

    .line 258
    .line 259
    if-eqz v4, :cond_e

    .line 260
    .line 261
    goto :goto_4

    .line 262
    :cond_e
    move v5, v9

    .line 263
    goto :goto_5

    .line 264
    :cond_f
    :goto_4
    move v5, v10

    .line 265
    :goto_5
    iget-object v6, v0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 266
    .line 267
    iget-object v6, v6, Lka/f0;->e:Lka/s;

    .line 268
    .line 269
    if-eqz v6, :cond_10

    .line 270
    .line 271
    iget-boolean v6, v6, Lka/s;->d:Z

    .line 272
    .line 273
    if-eqz v6, :cond_10

    .line 274
    .line 275
    goto/16 :goto_a

    .line 276
    .line 277
    :cond_10
    if-eqz v5, :cond_1c

    .line 278
    .line 279
    invoke-virtual {v0}, Landroid/view/View;->getOverScrollMode()I

    .line 280
    .line 281
    .line 282
    move-result v1

    .line 283
    if-eq v1, v12, :cond_1a

    .line 284
    .line 285
    invoke-virtual {v11}, Landroid/widget/OverScroller;->getCurrVelocity()F

    .line 286
    .line 287
    .line 288
    move-result v1

    .line 289
    float-to-int v1, v1

    .line 290
    if-gez v3, :cond_11

    .line 291
    .line 292
    neg-int v2, v1

    .line 293
    goto :goto_6

    .line 294
    :cond_11
    if-lez v3, :cond_12

    .line 295
    .line 296
    move v2, v1

    .line 297
    goto :goto_6

    .line 298
    :cond_12
    move v2, v9

    .line 299
    :goto_6
    if-gez v4, :cond_13

    .line 300
    .line 301
    neg-int v1, v1

    .line 302
    goto :goto_7

    .line 303
    :cond_13
    if-lez v4, :cond_14

    .line 304
    .line 305
    goto :goto_7

    .line 306
    :cond_14
    move v1, v9

    .line 307
    :goto_7
    if-gez v2, :cond_15

    .line 308
    .line 309
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->w()V

    .line 310
    .line 311
    .line 312
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->I:Landroid/widget/EdgeEffect;

    .line 313
    .line 314
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 315
    .line 316
    .line 317
    move-result v3

    .line 318
    if-eqz v3, :cond_16

    .line 319
    .line 320
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->I:Landroid/widget/EdgeEffect;

    .line 321
    .line 322
    neg-int v4, v2

    .line 323
    invoke-virtual {v3, v4}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 324
    .line 325
    .line 326
    goto :goto_8

    .line 327
    :cond_15
    if-lez v2, :cond_16

    .line 328
    .line 329
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->x()V

    .line 330
    .line 331
    .line 332
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->K:Landroid/widget/EdgeEffect;

    .line 333
    .line 334
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 335
    .line 336
    .line 337
    move-result v3

    .line 338
    if-eqz v3, :cond_16

    .line 339
    .line 340
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->K:Landroid/widget/EdgeEffect;

    .line 341
    .line 342
    invoke-virtual {v3, v2}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 343
    .line 344
    .line 345
    :cond_16
    :goto_8
    if-gez v1, :cond_17

    .line 346
    .line 347
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->y()V

    .line 348
    .line 349
    .line 350
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->J:Landroid/widget/EdgeEffect;

    .line 351
    .line 352
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    if-eqz v3, :cond_18

    .line 357
    .line 358
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->J:Landroid/widget/EdgeEffect;

    .line 359
    .line 360
    neg-int v4, v1

    .line 361
    invoke-virtual {v3, v4}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 362
    .line 363
    .line 364
    goto :goto_9

    .line 365
    :cond_17
    if-lez v1, :cond_18

    .line 366
    .line 367
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->v()V

    .line 368
    .line 369
    .line 370
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->L:Landroid/widget/EdgeEffect;

    .line 371
    .line 372
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 373
    .line 374
    .line 375
    move-result v3

    .line 376
    if-eqz v3, :cond_18

    .line 377
    .line 378
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->L:Landroid/widget/EdgeEffect;

    .line 379
    .line 380
    invoke-virtual {v3, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 381
    .line 382
    .line 383
    :cond_18
    :goto_9
    if-nez v2, :cond_19

    .line 384
    .line 385
    if-eqz v1, :cond_1a

    .line 386
    .line 387
    :cond_19
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 388
    .line 389
    invoke-virtual {v0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 390
    .line 391
    .line 392
    :cond_1a
    sget-boolean v1, Landroidx/recyclerview/widget/RecyclerView;->M1:Z

    .line 393
    .line 394
    if-eqz v1, :cond_1d

    .line 395
    .line 396
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->g0:Landroidx/collection/i;

    .line 397
    .line 398
    iget-object v2, v1, Landroidx/collection/i;->c:[I

    .line 399
    .line 400
    if-eqz v2, :cond_1b

    .line 401
    .line 402
    const/4 v3, -0x1

    .line 403
    invoke-static {v2, v3}, Ljava/util/Arrays;->fill([II)V

    .line 404
    .line 405
    .line 406
    :cond_1b
    iput v9, v1, Landroidx/collection/i;->d:I

    .line 407
    .line 408
    goto :goto_b

    .line 409
    :cond_1c
    :goto_a
    invoke-virtual {p0}, Lka/u0;->b()V

    .line 410
    .line 411
    .line 412
    iget-object v3, v0, Landroidx/recyclerview/widget/RecyclerView;->f0:Lka/m;

    .line 413
    .line 414
    if-eqz v3, :cond_1d

    .line 415
    .line 416
    invoke-virtual {v3, v0, v1, v2}, Lka/m;->a(Landroidx/recyclerview/widget/RecyclerView;II)V

    .line 417
    .line 418
    .line 419
    :cond_1d
    :goto_b
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 420
    .line 421
    iget-object v1, v1, Lka/f0;->e:Lka/s;

    .line 422
    .line 423
    if-eqz v1, :cond_1e

    .line 424
    .line 425
    iget-boolean v2, v1, Lka/s;->d:Z

    .line 426
    .line 427
    if-eqz v2, :cond_1e

    .line 428
    .line 429
    invoke-virtual {v1, v9, v9}, Lka/s;->g(II)V

    .line 430
    .line 431
    .line 432
    :cond_1e
    iput-boolean v9, p0, Lka/u0;->h:Z

    .line 433
    .line 434
    iget-boolean v1, p0, Lka/u0;->i:Z

    .line 435
    .line 436
    if-eqz v1, :cond_1f

    .line 437
    .line 438
    invoke-virtual {v0, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 439
    .line 440
    .line 441
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 442
    .line 443
    invoke-virtual {v0, p0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 444
    .line 445
    .line 446
    return-void

    .line 447
    :cond_1f
    invoke-virtual {v0, v9}, Landroidx/recyclerview/widget/RecyclerView;->setScrollState(I)V

    .line 448
    .line 449
    .line 450
    invoke-virtual {v0, v10}, Landroidx/recyclerview/widget/RecyclerView;->h0(I)V

    .line 451
    .line 452
    .line 453
    return-void
.end method
