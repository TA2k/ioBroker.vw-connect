.class public abstract Lm/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnTouchListener;
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final d:F

.field public final e:I

.field public final f:I

.field public final g:Landroid/view/View;

.field public h:Lm/o1;

.field public i:Lm/o1;

.field public j:Z

.field public k:I

.field public final l:[I


# direct methods
.method public constructor <init>(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    new-array v1, v0, [I

    .line 6
    .line 7
    iput-object v1, p0, Lm/p1;->l:[I

    .line 8
    .line 9
    iput-object p1, p0, Lm/p1;->g:Landroid/view/View;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-virtual {p1, v1}, Landroid/view/View;->setLongClickable(Z)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, p0}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1}, Landroid/view/ViewConfiguration;->getScaledTouchSlop()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    int-to-float p1, p1

    .line 31
    iput p1, p0, Lm/p1;->d:F

    .line 32
    .line 33
    invoke-static {}, Landroid/view/ViewConfiguration;->getTapTimeout()I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    iput p1, p0, Lm/p1;->e:I

    .line 38
    .line 39
    invoke-static {}, Landroid/view/ViewConfiguration;->getLongPressTimeout()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    add-int/2addr v1, p1

    .line 44
    div-int/2addr v1, v0

    .line 45
    iput v1, p0, Lm/p1;->f:I

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lm/p1;->i:Lm/o1;

    .line 2
    .line 3
    iget-object v1, p0, Lm/p1;->g:Landroid/view/View;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p0, p0, Lm/p1;->h:Lm/o1;

    .line 11
    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 15
    .line 16
    .line 17
    :cond_1
    return-void
.end method

.method public abstract b()Ll/b0;
.end method

.method public abstract c()Z
.end method

.method public d()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lm/p1;->b()Ll/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Ll/b0;->a()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p0}, Ll/b0;->dismiss()V

    .line 14
    .line 15
    .line 16
    :cond_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z
    .locals 12

    .line 1
    iget-boolean p1, p0, Lm/p1;->j:Z

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    iget-object v1, p0, Lm/p1;->g:Landroid/view/View;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz p1, :cond_5

    .line 9
    .line 10
    invoke-virtual {p0}, Lm/p1;->b()Ll/b0;

    .line 11
    .line 12
    .line 13
    move-result-object v4

    .line 14
    if-eqz v4, :cond_3

    .line 15
    .line 16
    invoke-interface {v4}, Ll/b0;->a()Z

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    if-nez v5, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-interface {v4}, Ll/b0;->n()Lm/m1;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    if-eqz v4, :cond_3

    .line 28
    .line 29
    invoke-virtual {v4}, Landroid/view/View;->isShown()Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-nez v5, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    invoke-static {p2}, Landroid/view/MotionEvent;->obtainNoHistory(Landroid/view/MotionEvent;)Landroid/view/MotionEvent;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    iget-object v6, p0, Lm/p1;->l:[I

    .line 41
    .line 42
    invoke-virtual {v1, v6}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 43
    .line 44
    .line 45
    aget v1, v6, v2

    .line 46
    .line 47
    int-to-float v1, v1

    .line 48
    aget v7, v6, v3

    .line 49
    .line 50
    int-to-float v7, v7

    .line 51
    invoke-virtual {v5, v1, v7}, Landroid/view/MotionEvent;->offsetLocation(FF)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4, v6}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 55
    .line 56
    .line 57
    aget v1, v6, v2

    .line 58
    .line 59
    neg-int v1, v1

    .line 60
    int-to-float v1, v1

    .line 61
    aget v6, v6, v3

    .line 62
    .line 63
    neg-int v6, v6

    .line 64
    int-to-float v6, v6

    .line 65
    invoke-virtual {v5, v1, v6}, Landroid/view/MotionEvent;->offsetLocation(FF)V

    .line 66
    .line 67
    .line 68
    iget v1, p0, Lm/p1;->k:I

    .line 69
    .line 70
    invoke-virtual {v4, v5, v1}, Lm/m1;->b(Landroid/view/MotionEvent;I)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    invoke-virtual {v5}, Landroid/view/MotionEvent;->recycle()V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p2}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-eq p2, v3, :cond_2

    .line 82
    .line 83
    if-eq p2, v0, :cond_2

    .line 84
    .line 85
    move p2, v3

    .line 86
    goto :goto_0

    .line 87
    :cond_2
    move p2, v2

    .line 88
    :goto_0
    if-eqz v1, :cond_3

    .line 89
    .line 90
    if-eqz p2, :cond_3

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    :goto_1
    invoke-virtual {p0}, Lm/p1;->d()Z

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    if-nez p2, :cond_4

    .line 98
    .line 99
    :goto_2
    move p2, v3

    .line 100
    goto/16 :goto_5

    .line 101
    .line 102
    :cond_4
    move p2, v2

    .line 103
    goto/16 :goto_5

    .line 104
    .line 105
    :cond_5
    invoke-virtual {v1}, Landroid/view/View;->isEnabled()Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-nez v4, :cond_6

    .line 110
    .line 111
    goto/16 :goto_3

    .line 112
    .line 113
    :cond_6
    invoke-virtual {p2}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_a

    .line 118
    .line 119
    if-eq v4, v3, :cond_9

    .line 120
    .line 121
    const/4 v5, 0x2

    .line 122
    if-eq v4, v5, :cond_7

    .line 123
    .line 124
    if-eq v4, v0, :cond_9

    .line 125
    .line 126
    goto/16 :goto_3

    .line 127
    .line 128
    :cond_7
    iget v0, p0, Lm/p1;->k:I

    .line 129
    .line 130
    invoke-virtual {p2, v0}, Landroid/view/MotionEvent;->findPointerIndex(I)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-ltz v0, :cond_d

    .line 135
    .line 136
    invoke-virtual {p2, v0}, Landroid/view/MotionEvent;->getX(I)F

    .line 137
    .line 138
    .line 139
    move-result v4

    .line 140
    invoke-virtual {p2, v0}, Landroid/view/MotionEvent;->getY(I)F

    .line 141
    .line 142
    .line 143
    move-result p2

    .line 144
    iget v0, p0, Lm/p1;->d:F

    .line 145
    .line 146
    neg-float v5, v0

    .line 147
    cmpl-float v6, v4, v5

    .line 148
    .line 149
    if-ltz v6, :cond_8

    .line 150
    .line 151
    cmpl-float v5, p2, v5

    .line 152
    .line 153
    if-ltz v5, :cond_8

    .line 154
    .line 155
    invoke-virtual {v1}, Landroid/view/View;->getRight()I

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    invoke-virtual {v1}, Landroid/view/View;->getLeft()I

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    sub-int/2addr v5, v6

    .line 164
    int-to-float v5, v5

    .line 165
    add-float/2addr v5, v0

    .line 166
    cmpg-float v4, v4, v5

    .line 167
    .line 168
    if-gez v4, :cond_8

    .line 169
    .line 170
    invoke-virtual {v1}, Landroid/view/View;->getBottom()I

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    invoke-virtual {v1}, Landroid/view/View;->getTop()I

    .line 175
    .line 176
    .line 177
    move-result v5

    .line 178
    sub-int/2addr v4, v5

    .line 179
    int-to-float v4, v4

    .line 180
    add-float/2addr v4, v0

    .line 181
    cmpg-float p2, p2, v4

    .line 182
    .line 183
    if-gez p2, :cond_8

    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_8
    invoke-virtual {p0}, Lm/p1;->a()V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 190
    .line 191
    .line 192
    move-result-object p2

    .line 193
    invoke-interface {p2, v3}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p0}, Lm/p1;->c()Z

    .line 197
    .line 198
    .line 199
    move-result p2

    .line 200
    if-eqz p2, :cond_d

    .line 201
    .line 202
    move p2, v3

    .line 203
    goto :goto_4

    .line 204
    :cond_9
    invoke-virtual {p0}, Lm/p1;->a()V

    .line 205
    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_a
    invoke-virtual {p2, v2}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    iput p2, p0, Lm/p1;->k:I

    .line 213
    .line 214
    iget-object p2, p0, Lm/p1;->h:Lm/o1;

    .line 215
    .line 216
    if-nez p2, :cond_b

    .line 217
    .line 218
    new-instance p2, Lm/o1;

    .line 219
    .line 220
    const/4 v0, 0x0

    .line 221
    invoke-direct {p2, p0, v0}, Lm/o1;-><init>(Lm/p1;I)V

    .line 222
    .line 223
    .line 224
    iput-object p2, p0, Lm/p1;->h:Lm/o1;

    .line 225
    .line 226
    :cond_b
    iget-object p2, p0, Lm/p1;->h:Lm/o1;

    .line 227
    .line 228
    iget v0, p0, Lm/p1;->e:I

    .line 229
    .line 230
    int-to-long v4, v0

    .line 231
    invoke-virtual {v1, p2, v4, v5}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 232
    .line 233
    .line 234
    iget-object p2, p0, Lm/p1;->i:Lm/o1;

    .line 235
    .line 236
    if-nez p2, :cond_c

    .line 237
    .line 238
    new-instance p2, Lm/o1;

    .line 239
    .line 240
    const/4 v0, 0x1

    .line 241
    invoke-direct {p2, p0, v0}, Lm/o1;-><init>(Lm/p1;I)V

    .line 242
    .line 243
    .line 244
    iput-object p2, p0, Lm/p1;->i:Lm/o1;

    .line 245
    .line 246
    :cond_c
    iget-object p2, p0, Lm/p1;->i:Lm/o1;

    .line 247
    .line 248
    iget v0, p0, Lm/p1;->f:I

    .line 249
    .line 250
    int-to-long v4, v0

    .line 251
    invoke-virtual {v1, p2, v4, v5}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 252
    .line 253
    .line 254
    :cond_d
    :goto_3
    move p2, v2

    .line 255
    :goto_4
    if-eqz p2, :cond_e

    .line 256
    .line 257
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 258
    .line 259
    .line 260
    move-result-wide v4

    .line 261
    const/4 v10, 0x0

    .line 262
    const/4 v11, 0x0

    .line 263
    const/4 v8, 0x3

    .line 264
    const/4 v9, 0x0

    .line 265
    move-wide v6, v4

    .line 266
    invoke-static/range {v4 .. v11}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    invoke-virtual {v1, v0}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 271
    .line 272
    .line 273
    invoke-virtual {v0}, Landroid/view/MotionEvent;->recycle()V

    .line 274
    .line 275
    .line 276
    :cond_e
    :goto_5
    iput-boolean p2, p0, Lm/p1;->j:Z

    .line 277
    .line 278
    if-nez p2, :cond_10

    .line 279
    .line 280
    if-eqz p1, :cond_f

    .line 281
    .line 282
    goto :goto_6

    .line 283
    :cond_f
    return v2

    .line 284
    :cond_10
    :goto_6
    return v3
.end method

.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    iput-boolean p1, p0, Lm/p1;->j:Z

    .line 3
    .line 4
    const/4 p1, -0x1

    .line 5
    iput p1, p0, Lm/p1;->k:I

    .line 6
    .line 7
    iget-object p1, p0, Lm/p1;->h:Lm/o1;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lm/p1;->g:Landroid/view/View;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method
