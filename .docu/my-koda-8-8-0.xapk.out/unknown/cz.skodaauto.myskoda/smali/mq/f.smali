.class public final Lmq/f;
.super Lwq/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/graphics/drawable/Drawable$Callback;
.implements Lrq/h;


# static fields
.field public static final X1:[I

.field public static final Y1:Landroid/graphics/drawable/ShapeDrawable;


# instance fields
.field public final A1:Landroid/graphics/PointF;

.field public final B1:Landroid/graphics/Path;

.field public final C1:Lrq/i;

.field public D1:I

.field public E1:I

.field public F1:I

.field public G:Landroid/content/res/ColorStateList;

.field public G1:I

.field public H:Landroid/content/res/ColorStateList;

.field public H1:I

.field public I:F

.field public I1:I

.field public J:F

.field public J1:Z

.field public K:Landroid/content/res/ColorStateList;

.field public K1:I

.field public L:F

.field public L1:I

.field public M:Landroid/content/res/ColorStateList;

.field public M1:Landroid/graphics/ColorFilter;

.field public N:Ljava/lang/CharSequence;

.field public N1:Landroid/graphics/PorterDuffColorFilter;

.field public O:Z

.field public O1:Landroid/content/res/ColorStateList;

.field public P:Landroid/graphics/drawable/Drawable;

.field public P1:Landroid/graphics/PorterDuff$Mode;

.field public Q:Landroid/content/res/ColorStateList;

.field public Q1:[I

.field public R:F

.field public R1:Landroid/content/res/ColorStateList;

.field public S:Z

.field public S1:Ljava/lang/ref/WeakReference;

.field public T:Z

.field public T1:Landroid/text/TextUtils$TruncateAt;

.field public U:Landroid/graphics/drawable/Drawable;

.field public U1:Z

.field public V:Landroid/graphics/drawable/RippleDrawable;

.field public V1:I

.field public W:Landroid/content/res/ColorStateList;

.field public W1:Z

.field public X:F

.field public Y:Landroid/text/SpannableStringBuilder;

.field public Z:Z

.field public a0:Z

.field public b0:Landroid/graphics/drawable/Drawable;

.field public c0:Landroid/content/res/ColorStateList;

.field public d0:Leq/b;

.field public e0:Leq/b;

.field public f0:F

.field public g0:F

.field public q1:F

.field public r1:F

.field public s1:F

.field public t1:F

.field public u1:F

.field public v1:F

.field public final w1:Landroid/content/Context;

.field public final x1:Landroid/graphics/Paint;

.field public final y1:Landroid/graphics/Paint$FontMetrics;

.field public final z1:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const v0, 0x101009e

    .line 2
    .line 3
    .line 4
    filled-new-array {v0}, [I

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lmq/f;->X1:[I

    .line 9
    .line 10
    new-instance v0, Landroid/graphics/drawable/ShapeDrawable;

    .line 11
    .line 12
    new-instance v1, Landroid/graphics/drawable/shapes/OvalShape;

    .line 13
    .line 14
    invoke-direct {v1}, Landroid/graphics/drawable/shapes/OvalShape;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Landroid/graphics/drawable/ShapeDrawable;-><init>(Landroid/graphics/drawable/shapes/Shape;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lmq/f;->Y1:Landroid/graphics/drawable/ShapeDrawable;

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 2

    .line 1
    const v0, 0x7f0400ef

    .line 2
    .line 3
    .line 4
    const v1, 0x7f130515

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, p1, p2, v0, v1}, Lwq/i;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 8
    .line 9
    .line 10
    const/high16 p2, -0x40800000    # -1.0f

    .line 11
    .line 12
    iput p2, p0, Lmq/f;->J:F

    .line 13
    .line 14
    new-instance p2, Landroid/graphics/Paint;

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    invoke-direct {p2, v0}, Landroid/graphics/Paint;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object p2, p0, Lmq/f;->x1:Landroid/graphics/Paint;

    .line 21
    .line 22
    new-instance p2, Landroid/graphics/Paint$FontMetrics;

    .line 23
    .line 24
    invoke-direct {p2}, Landroid/graphics/Paint$FontMetrics;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p2, p0, Lmq/f;->y1:Landroid/graphics/Paint$FontMetrics;

    .line 28
    .line 29
    new-instance p2, Landroid/graphics/RectF;

    .line 30
    .line 31
    invoke-direct {p2}, Landroid/graphics/RectF;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p2, p0, Lmq/f;->z1:Landroid/graphics/RectF;

    .line 35
    .line 36
    new-instance p2, Landroid/graphics/PointF;

    .line 37
    .line 38
    invoke-direct {p2}, Landroid/graphics/PointF;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lmq/f;->A1:Landroid/graphics/PointF;

    .line 42
    .line 43
    new-instance p2, Landroid/graphics/Path;

    .line 44
    .line 45
    invoke-direct {p2}, Landroid/graphics/Path;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p2, p0, Lmq/f;->B1:Landroid/graphics/Path;

    .line 49
    .line 50
    const/16 p2, 0xff

    .line 51
    .line 52
    iput p2, p0, Lmq/f;->L1:I

    .line 53
    .line 54
    sget-object p2, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    .line 55
    .line 56
    iput-object p2, p0, Lmq/f;->P1:Landroid/graphics/PorterDuff$Mode;

    .line 57
    .line 58
    new-instance p2, Ljava/lang/ref/WeakReference;

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    invoke-direct {p2, v1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput-object p2, p0, Lmq/f;->S1:Ljava/lang/ref/WeakReference;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lwq/i;->j(Landroid/content/Context;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Lmq/f;->w1:Landroid/content/Context;

    .line 70
    .line 71
    new-instance p2, Lrq/i;

    .line 72
    .line 73
    invoke-direct {p2, p0}, Lrq/i;-><init>(Lmq/f;)V

    .line 74
    .line 75
    .line 76
    iput-object p2, p0, Lmq/f;->C1:Lrq/i;

    .line 77
    .line 78
    const-string v1, ""

    .line 79
    .line 80
    iput-object v1, p0, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 81
    .line 82
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-virtual {p1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    iget p1, p1, Landroid/util/DisplayMetrics;->density:F

    .line 91
    .line 92
    iget-object p2, p2, Lrq/i;->a:Landroid/text/TextPaint;

    .line 93
    .line 94
    iput p1, p2, Landroid/text/TextPaint;->density:F

    .line 95
    .line 96
    sget-object p1, Lmq/f;->X1:[I

    .line 97
    .line 98
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 99
    .line 100
    .line 101
    invoke-virtual {p0, p1}, Lmq/f;->Q([I)Z

    .line 102
    .line 103
    .line 104
    iput-boolean v0, p0, Lmq/f;->U1:Z

    .line 105
    .line 106
    sget-object p0, Lmq/f;->Y1:Landroid/graphics/drawable/ShapeDrawable;

    .line 107
    .line 108
    const/4 p1, -0x1

    .line 109
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    .line 110
    .line 111
    .line 112
    return-void
.end method

.method public static a0(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    .line 5
    .line 6
    .line 7
    :cond_0
    return-void
.end method

.method public static x(Landroid/content/res/ColorStateList;)Z
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public static y(Landroid/graphics/drawable/Drawable;)Z
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method


# virtual methods
.method public final A([I[I)Z
    .locals 9

    .line 1
    invoke-super {p0, p1}, Lwq/i;->onStateChange([I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lmq/f;->G:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    iget v3, p0, Lmq/f;->D1:I

    .line 11
    .line 12
    invoke-virtual {v1, p1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v1, v2

    .line 18
    :goto_0
    invoke-virtual {p0, v1}, Lwq/i;->c(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget v3, p0, Lmq/f;->D1:I

    .line 23
    .line 24
    const/4 v4, 0x1

    .line 25
    if-eq v3, v1, :cond_1

    .line 26
    .line 27
    iput v1, p0, Lmq/f;->D1:I

    .line 28
    .line 29
    move v0, v4

    .line 30
    :cond_1
    iget-object v3, p0, Lmq/f;->H:Landroid/content/res/ColorStateList;

    .line 31
    .line 32
    if-eqz v3, :cond_2

    .line 33
    .line 34
    iget v5, p0, Lmq/f;->E1:I

    .line 35
    .line 36
    invoke-virtual {v3, p1, v5}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    move v3, v2

    .line 42
    :goto_1
    invoke-virtual {p0, v3}, Lwq/i;->c(I)I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    iget v5, p0, Lmq/f;->E1:I

    .line 47
    .line 48
    if-eq v5, v3, :cond_3

    .line 49
    .line 50
    iput v3, p0, Lmq/f;->E1:I

    .line 51
    .line 52
    move v0, v4

    .line 53
    :cond_3
    invoke-static {v3, v1}, Ls5/a;->c(II)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget v3, p0, Lmq/f;->F1:I

    .line 58
    .line 59
    if-eq v3, v1, :cond_4

    .line 60
    .line 61
    move v3, v4

    .line 62
    goto :goto_2

    .line 63
    :cond_4
    move v3, v2

    .line 64
    :goto_2
    iget-object v5, p0, Lwq/i;->e:Lwq/g;

    .line 65
    .line 66
    iget-object v5, v5, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 67
    .line 68
    if-nez v5, :cond_5

    .line 69
    .line 70
    move v5, v4

    .line 71
    goto :goto_3

    .line 72
    :cond_5
    move v5, v2

    .line 73
    :goto_3
    or-int/2addr v3, v5

    .line 74
    if-eqz v3, :cond_6

    .line 75
    .line 76
    iput v1, p0, Lmq/f;->F1:I

    .line 77
    .line 78
    invoke-static {v1}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-virtual {p0, v0}, Lwq/i;->m(Landroid/content/res/ColorStateList;)V

    .line 83
    .line 84
    .line 85
    move v0, v4

    .line 86
    :cond_6
    iget-object v1, p0, Lmq/f;->K:Landroid/content/res/ColorStateList;

    .line 87
    .line 88
    if-eqz v1, :cond_7

    .line 89
    .line 90
    iget v3, p0, Lmq/f;->G1:I

    .line 91
    .line 92
    invoke-virtual {v1, p1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    goto :goto_4

    .line 97
    :cond_7
    move v1, v2

    .line 98
    :goto_4
    iget v3, p0, Lmq/f;->G1:I

    .line 99
    .line 100
    if-eq v3, v1, :cond_8

    .line 101
    .line 102
    iput v1, p0, Lmq/f;->G1:I

    .line 103
    .line 104
    move v0, v4

    .line 105
    :cond_8
    iget-object v1, p0, Lmq/f;->R1:Landroid/content/res/ColorStateList;

    .line 106
    .line 107
    if-eqz v1, :cond_e

    .line 108
    .line 109
    array-length v1, p1

    .line 110
    move v3, v2

    .line 111
    move v5, v3

    .line 112
    move v6, v5

    .line 113
    :goto_5
    if-ge v3, v1, :cond_d

    .line 114
    .line 115
    aget v7, p1, v3

    .line 116
    .line 117
    const v8, 0x101009e

    .line 118
    .line 119
    .line 120
    if-ne v7, v8, :cond_9

    .line 121
    .line 122
    move v5, v4

    .line 123
    goto :goto_7

    .line 124
    :cond_9
    const v8, 0x101009c

    .line 125
    .line 126
    .line 127
    if-ne v7, v8, :cond_a

    .line 128
    .line 129
    :goto_6
    move v6, v4

    .line 130
    goto :goto_7

    .line 131
    :cond_a
    const v8, 0x10100a7

    .line 132
    .line 133
    .line 134
    if-ne v7, v8, :cond_b

    .line 135
    .line 136
    goto :goto_6

    .line 137
    :cond_b
    const v8, 0x1010367

    .line 138
    .line 139
    .line 140
    if-ne v7, v8, :cond_c

    .line 141
    .line 142
    goto :goto_6

    .line 143
    :cond_c
    :goto_7
    add-int/lit8 v3, v3, 0x1

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_d
    if-eqz v5, :cond_e

    .line 147
    .line 148
    if-eqz v6, :cond_e

    .line 149
    .line 150
    iget-object v1, p0, Lmq/f;->R1:Landroid/content/res/ColorStateList;

    .line 151
    .line 152
    iget v3, p0, Lmq/f;->H1:I

    .line 153
    .line 154
    invoke-virtual {v1, p1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    goto :goto_8

    .line 159
    :cond_e
    move v1, v2

    .line 160
    :goto_8
    iget v3, p0, Lmq/f;->H1:I

    .line 161
    .line 162
    if-eq v3, v1, :cond_f

    .line 163
    .line 164
    iput v1, p0, Lmq/f;->H1:I

    .line 165
    .line 166
    :cond_f
    iget-object v1, p0, Lmq/f;->C1:Lrq/i;

    .line 167
    .line 168
    iget-object v1, v1, Lrq/i;->f:Luq/c;

    .line 169
    .line 170
    if-eqz v1, :cond_10

    .line 171
    .line 172
    iget-object v1, v1, Luq/c;->k:Landroid/content/res/ColorStateList;

    .line 173
    .line 174
    if-eqz v1, :cond_10

    .line 175
    .line 176
    iget v3, p0, Lmq/f;->I1:I

    .line 177
    .line 178
    invoke-virtual {v1, p1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    goto :goto_9

    .line 183
    :cond_10
    move v1, v2

    .line 184
    :goto_9
    iget v3, p0, Lmq/f;->I1:I

    .line 185
    .line 186
    if-eq v3, v1, :cond_11

    .line 187
    .line 188
    iput v1, p0, Lmq/f;->I1:I

    .line 189
    .line 190
    move v0, v4

    .line 191
    :cond_11
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    if-nez v1, :cond_12

    .line 196
    .line 197
    goto :goto_b

    .line 198
    :cond_12
    array-length v3, v1

    .line 199
    move v5, v2

    .line 200
    :goto_a
    if-ge v5, v3, :cond_14

    .line 201
    .line 202
    aget v6, v1, v5

    .line 203
    .line 204
    const v7, 0x10100a0

    .line 205
    .line 206
    .line 207
    if-ne v6, v7, :cond_13

    .line 208
    .line 209
    iget-boolean v1, p0, Lmq/f;->Z:Z

    .line 210
    .line 211
    if-eqz v1, :cond_14

    .line 212
    .line 213
    move v1, v4

    .line 214
    goto :goto_c

    .line 215
    :cond_13
    add-int/lit8 v5, v5, 0x1

    .line 216
    .line 217
    goto :goto_a

    .line 218
    :cond_14
    :goto_b
    move v1, v2

    .line 219
    :goto_c
    iget-boolean v3, p0, Lmq/f;->J1:Z

    .line 220
    .line 221
    if-eq v3, v1, :cond_16

    .line 222
    .line 223
    iget-object v3, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 224
    .line 225
    if-eqz v3, :cond_16

    .line 226
    .line 227
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 228
    .line 229
    .line 230
    move-result v0

    .line 231
    iput-boolean v1, p0, Lmq/f;->J1:Z

    .line 232
    .line 233
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    cmpl-float v0, v0, v1

    .line 238
    .line 239
    if-eqz v0, :cond_15

    .line 240
    .line 241
    move v0, v4

    .line 242
    move v1, v0

    .line 243
    goto :goto_d

    .line 244
    :cond_15
    move v1, v2

    .line 245
    move v0, v4

    .line 246
    goto :goto_d

    .line 247
    :cond_16
    move v1, v2

    .line 248
    :goto_d
    iget-object v3, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 249
    .line 250
    if-eqz v3, :cond_17

    .line 251
    .line 252
    iget v5, p0, Lmq/f;->K1:I

    .line 253
    .line 254
    invoke-virtual {v3, p1, v5}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 255
    .line 256
    .line 257
    move-result v3

    .line 258
    goto :goto_e

    .line 259
    :cond_17
    move v3, v2

    .line 260
    :goto_e
    iget v5, p0, Lmq/f;->K1:I

    .line 261
    .line 262
    if-eq v5, v3, :cond_1a

    .line 263
    .line 264
    iput v3, p0, Lmq/f;->K1:I

    .line 265
    .line 266
    iget-object v0, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 267
    .line 268
    iget-object v3, p0, Lmq/f;->P1:Landroid/graphics/PorterDuff$Mode;

    .line 269
    .line 270
    if-eqz v0, :cond_19

    .line 271
    .line 272
    if-nez v3, :cond_18

    .line 273
    .line 274
    goto :goto_f

    .line 275
    :cond_18
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-virtual {v0, v5, v2}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    new-instance v5, Landroid/graphics/PorterDuffColorFilter;

    .line 284
    .line 285
    invoke-direct {v5, v0, v3}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 286
    .line 287
    .line 288
    goto :goto_10

    .line 289
    :cond_19
    :goto_f
    const/4 v5, 0x0

    .line 290
    :goto_10
    iput-object v5, p0, Lmq/f;->N1:Landroid/graphics/PorterDuffColorFilter;

    .line 291
    .line 292
    goto :goto_11

    .line 293
    :cond_1a
    move v4, v0

    .line 294
    :goto_11
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 295
    .line 296
    invoke-static {v0}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 297
    .line 298
    .line 299
    move-result v0

    .line 300
    if-eqz v0, :cond_1b

    .line 301
    .line 302
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 303
    .line 304
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 305
    .line 306
    .line 307
    move-result v0

    .line 308
    or-int/2addr v4, v0

    .line 309
    :cond_1b
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 310
    .line 311
    invoke-static {v0}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    if-eqz v0, :cond_1c

    .line 316
    .line 317
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 318
    .line 319
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 320
    .line 321
    .line 322
    move-result v0

    .line 323
    or-int/2addr v4, v0

    .line 324
    :cond_1c
    iget-object v0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 325
    .line 326
    invoke-static {v0}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 327
    .line 328
    .line 329
    move-result v0

    .line 330
    if-eqz v0, :cond_1d

    .line 331
    .line 332
    array-length v0, p1

    .line 333
    array-length v3, p2

    .line 334
    add-int/2addr v0, v3

    .line 335
    new-array v0, v0, [I

    .line 336
    .line 337
    array-length v3, p1

    .line 338
    invoke-static {p1, v2, v0, v2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 339
    .line 340
    .line 341
    array-length p1, p1

    .line 342
    array-length v3, p2

    .line 343
    invoke-static {p2, v2, v0, p1, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 344
    .line 345
    .line 346
    iget-object p1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 347
    .line 348
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 349
    .line 350
    .line 351
    move-result p1

    .line 352
    or-int/2addr v4, p1

    .line 353
    :cond_1d
    iget-object p1, p0, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 354
    .line 355
    invoke-static {p1}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 356
    .line 357
    .line 358
    move-result p1

    .line 359
    if-eqz p1, :cond_1e

    .line 360
    .line 361
    iget-object p1, p0, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 362
    .line 363
    invoke-virtual {p1, p2}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 364
    .line 365
    .line 366
    move-result p1

    .line 367
    or-int/2addr v4, p1

    .line 368
    :cond_1e
    if-eqz v4, :cond_1f

    .line 369
    .line 370
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 371
    .line 372
    .line 373
    :cond_1f
    if-eqz v1, :cond_20

    .line 374
    .line 375
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 376
    .line 377
    .line 378
    :cond_20
    return v4
.end method

.method public final B(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->Z:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-boolean p1, p0, Lmq/f;->Z:Z

    .line 6
    .line 7
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    iget-boolean p1, p0, Lmq/f;->J1:Z

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    iput-boolean p1, p0, Lmq/f;->J1:Z

    .line 19
    .line 20
    :cond_0
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 25
    .line 26
    .line 27
    cmpl-float p1, v0, p1

    .line 28
    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final C(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iput-object p1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 10
    .line 11
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 16
    .line 17
    invoke-static {v1}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 21
    .line 22
    invoke-virtual {p0, v1}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 26
    .line 27
    .line 28
    cmpl-float p1, v0, p1

    .line 29
    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 33
    .line 34
    .line 35
    :cond_0
    return-void
.end method

.method public final D(Landroid/content/res/ColorStateList;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lmq/f;->c0:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->c0:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    iget-boolean v0, p0, Lmq/f;->a0:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-boolean v1, p0, Lmq/f;->Z:Z

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final E(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->a0:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iput-boolean p1, p0, Lmq/f;->a0:Z

    .line 10
    .line 11
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eq v0, p1, :cond_1

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object p1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    invoke-static {p1}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method public final F(F)V
    .locals 2

    .line 1
    iget v0, p0, Lmq/f;->J:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iput p1, p0, Lmq/f;->J:F

    .line 8
    .line 9
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 10
    .line 11
    iget-object v0, v0, Lwq/g;->a:Lwq/m;

    .line 12
    .line 13
    invoke-virtual {v0}, Lwq/m;->f()Lwq/l;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Lwq/a;

    .line 18
    .line 19
    invoke-direct {v1, p1}, Lwq/a;-><init>(F)V

    .line 20
    .line 21
    .line 22
    iput-object v1, v0, Lwq/l;->e:Lwq/d;

    .line 23
    .line 24
    new-instance v1, Lwq/a;

    .line 25
    .line 26
    invoke-direct {v1, p1}, Lwq/a;-><init>(F)V

    .line 27
    .line 28
    .line 29
    iput-object v1, v0, Lwq/l;->f:Lwq/d;

    .line 30
    .line 31
    new-instance v1, Lwq/a;

    .line 32
    .line 33
    invoke-direct {v1, p1}, Lwq/a;-><init>(F)V

    .line 34
    .line 35
    .line 36
    iput-object v1, v0, Lwq/l;->g:Lwq/d;

    .line 37
    .line 38
    new-instance v1, Lwq/a;

    .line 39
    .line 40
    invoke-direct {v1, p1}, Lwq/a;-><init>(F)V

    .line 41
    .line 42
    .line 43
    iput-object v1, v0, Lwq/l;->h:Lwq/d;

    .line 44
    .line 45
    invoke-virtual {v0}, Lwq/l;->a()Lwq/m;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, p1}, Lwq/i;->setShapeAppearanceModel(Lwq/m;)V

    .line 50
    .line 51
    .line 52
    :cond_0
    return-void
.end method

.method public final G(Landroid/graphics/drawable/Drawable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    instance-of v2, v0, Lt5/a;

    .line 7
    .line 8
    if-eqz v2, :cond_1

    .line 9
    .line 10
    check-cast v0, Lt5/a;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v0, v1

    .line 15
    :cond_1
    :goto_0
    if-eq v0, p1, :cond_4

    .line 16
    .line 17
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :cond_2
    iput-object v1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 28
    .line 29
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    invoke-static {v0}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 45
    .line 46
    .line 47
    :cond_3
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 48
    .line 49
    .line 50
    cmpl-float p1, v2, p1

    .line 51
    .line 52
    if-eqz p1, :cond_4

    .line 53
    .line 54
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 55
    .line 56
    .line 57
    :cond_4
    return-void
.end method

.method public final H(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->R:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput p1, p0, Lmq/f;->R:F

    .line 12
    .line 13
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 18
    .line 19
    .line 20
    cmpl-float p1, v0, p1

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final I(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lmq/f;->S:Z

    .line 3
    .line 4
    iget-object v0, p0, Lmq/f;->Q:Landroid/content/res/ColorStateList;

    .line 5
    .line 6
    if-eq v0, p1, :cond_1

    .line 7
    .line 8
    iput-object p1, p0, Lmq/f;->Q:Landroid/content/res/ColorStateList;

    .line 9
    .line 10
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final J(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->O:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iput-boolean p1, p0, Lmq/f;->O:Z

    .line 10
    .line 11
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eq v0, p1, :cond_1

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object p1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    invoke-static {p1}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method public final K(Landroid/content/res/ColorStateList;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lmq/f;->K:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->K:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    iget-boolean v0, p0, Lmq/f;->W1:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 12
    .line 13
    iget-object v1, v0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 14
    .line 15
    if-eq v1, p1, :cond_0

    .line 16
    .line 17
    iput-object p1, v0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 31
    .line 32
    .line 33
    :cond_1
    return-void
.end method

.method public final L(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->L:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iput p1, p0, Lmq/f;->L:F

    .line 8
    .line 9
    iget-object v0, p0, Lmq/f;->x1:Landroid/graphics/Paint;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 12
    .line 13
    .line 14
    iget-boolean v0, p0, Lmq/f;->W1:Z

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 19
    .line 20
    iput p1, v0, Lwq/g;->k:F

    .line 21
    .line 22
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 23
    .line 24
    .line 25
    :cond_0
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final M(Landroid/graphics/drawable/Drawable;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    instance-of v2, v0, Lt5/a;

    .line 7
    .line 8
    if-eqz v2, :cond_1

    .line 9
    .line 10
    check-cast v0, Lt5/a;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v0, v1

    .line 15
    :cond_1
    :goto_0
    if-eq v0, p1, :cond_5

    .line 16
    .line 17
    invoke-virtual {p0}, Lmq/f;->v()F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :cond_2
    iput-object v1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 28
    .line 29
    new-instance p1, Landroid/graphics/drawable/RippleDrawable;

    .line 30
    .line 31
    iget-object v1, p0, Lmq/f;->M:Landroid/content/res/ColorStateList;

    .line 32
    .line 33
    if-eqz v1, :cond_3

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_3
    const/4 v1, 0x0

    .line 37
    invoke-static {v1}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    :goto_1
    iget-object v3, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 42
    .line 43
    sget-object v4, Lmq/f;->Y1:Landroid/graphics/drawable/ShapeDrawable;

    .line 44
    .line 45
    invoke-direct {p1, v1, v3, v4}, Landroid/graphics/drawable/RippleDrawable;-><init>(Landroid/content/res/ColorStateList;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 49
    .line 50
    invoke-virtual {p0}, Lmq/f;->v()F

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    invoke-static {v0}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_4

    .line 62
    .line 63
    iget-object v0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 66
    .line 67
    .line 68
    :cond_4
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 69
    .line 70
    .line 71
    cmpl-float p1, v2, p1

    .line 72
    .line 73
    if-eqz p1, :cond_5

    .line 74
    .line 75
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 76
    .line 77
    .line 78
    :cond_5
    return-void
.end method

.method public final N(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->u1:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iput p1, p0, Lmq/f;->u1:F

    .line 8
    .line 9
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final O(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->X:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iput p1, p0, Lmq/f;->X:F

    .line 8
    .line 9
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final P(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->t1:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iput p1, p0, Lmq/f;->t1:F

    .line 8
    .line 9
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final Q([I)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->Q1:[I

    .line 2
    .line 3
    invoke-static {v0, p1}, Ljava/util/Arrays;->equals([I[I)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Lmq/f;->Q1:[I

    .line 10
    .line 11
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {p0, v0, p1}, Lmq/f;->A([I[I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0
.end method

.method public final R(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->W:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->W:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 23
    .line 24
    .line 25
    :cond_1
    return-void
.end method

.method public final S(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->T:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iput-boolean p1, p0, Lmq/f;->T:Z

    .line 10
    .line 11
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eq v0, p1, :cond_1

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object p1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lmq/f;->s(Landroid/graphics/drawable/Drawable;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object p1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    invoke-static {p1}, Lmq/f;->a0(Landroid/graphics/drawable/Drawable;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method public final T(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->q1:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput p1, p0, Lmq/f;->q1:F

    .line 12
    .line 13
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 18
    .line 19
    .line 20
    cmpl-float p1, v0, p1

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final U(F)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->g0:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput p1, p0, Lmq/f;->g0:F

    .line 12
    .line 13
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 18
    .line 19
    .line 20
    cmpl-float p1, v0, p1

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final V(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->M:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->M:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    iput-object p1, p0, Lmq/f;->R1:Landroid/content/res/ColorStateList;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final W(Luq/c;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lmq/f;->C1:Lrq/i;

    .line 2
    .line 3
    iget-object v1, v0, Lrq/i;->b:Lmq/b;

    .line 4
    .line 5
    iget-object v2, v0, Lrq/i;->a:Landroid/text/TextPaint;

    .line 6
    .line 7
    iget-object v3, v0, Lrq/i;->f:Luq/c;

    .line 8
    .line 9
    if-eq v3, p1, :cond_2

    .line 10
    .line 11
    iput-object p1, v0, Lrq/i;->f:Luq/c;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    iget-object p0, p0, Lmq/f;->w1:Landroid/content/Context;

    .line 16
    .line 17
    invoke-virtual {p1, p0, v2, v1}, Luq/c;->e(Landroid/content/Context;Landroid/text/TextPaint;Llp/y9;)V

    .line 18
    .line 19
    .line 20
    iget-object v3, v0, Lrq/i;->e:Ljava/lang/ref/WeakReference;

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    check-cast v3, Lrq/h;

    .line 27
    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    invoke-interface {v3}, Lrq/h;->getState()[I

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iput-object v3, v2, Landroid/text/TextPaint;->drawableState:[I

    .line 35
    .line 36
    :cond_0
    invoke-virtual {p1, p0, v2, v1}, Luq/c;->d(Landroid/content/Context;Landroid/text/TextPaint;Llp/y9;)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    iput-boolean p0, v0, Lrq/i;->d:Z

    .line 41
    .line 42
    :cond_1
    iget-object p0, v0, Lrq/i;->e:Ljava/lang/ref/WeakReference;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lrq/h;

    .line 49
    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    move-object p1, p0

    .line 53
    check-cast p1, Lmq/f;

    .line 54
    .line 55
    invoke-virtual {p1}, Lmq/f;->z()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1}, Lwq/i;->invalidateSelf()V

    .line 59
    .line 60
    .line 61
    invoke-interface {p0}, Lrq/h;->getState()[I

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p1, p0}, Lmq/f;->onStateChange([I)Z

    .line 66
    .line 67
    .line 68
    :cond_2
    return-void
.end method

.method public final X()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->a0:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-boolean p0, p0, Lmq/f;->J1:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final Y()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->O:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final Z()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->T:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final draw(Landroid/graphics/Canvas;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 4
    .line 5
    .line 6
    move-result-object v7

    .line 7
    invoke-virtual {v7}, Landroid/graphics/Rect;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_18

    .line 12
    .line 13
    iget v6, v0, Lmq/f;->L1:I

    .line 14
    .line 15
    if-nez v6, :cond_0

    .line 16
    .line 17
    goto/16 :goto_a

    .line 18
    .line 19
    :cond_0
    const/16 v8, 0xff

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    if-ge v6, v8, :cond_1

    .line 23
    .line 24
    iget v1, v7, Landroid/graphics/Rect;->left:I

    .line 25
    .line 26
    int-to-float v2, v1

    .line 27
    iget v1, v7, Landroid/graphics/Rect;->top:I

    .line 28
    .line 29
    int-to-float v3, v1

    .line 30
    iget v1, v7, Landroid/graphics/Rect;->right:I

    .line 31
    .line 32
    int-to-float v4, v1

    .line 33
    iget v1, v7, Landroid/graphics/Rect;->bottom:I

    .line 34
    .line 35
    int-to-float v5, v1

    .line 36
    move-object/from16 v1, p1

    .line 37
    .line 38
    invoke-virtual/range {v1 .. v6}, Landroid/graphics/Canvas;->saveLayerAlpha(FFFFI)I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    move v10, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_1
    move-object/from16 v1, p1

    .line 45
    .line 46
    move v10, v9

    .line 47
    :goto_0
    iget-boolean v2, v0, Lmq/f;->W1:Z

    .line 48
    .line 49
    move v3, v2

    .line 50
    iget-object v2, v0, Lmq/f;->x1:Landroid/graphics/Paint;

    .line 51
    .line 52
    iget-object v11, v0, Lmq/f;->z1:Landroid/graphics/RectF;

    .line 53
    .line 54
    if-nez v3, :cond_2

    .line 55
    .line 56
    iget v3, v0, Lmq/f;->D1:I

    .line 57
    .line 58
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColor(I)V

    .line 59
    .line 60
    .line 61
    sget-object v3, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 62
    .line 63
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v11, v7}, Landroid/graphics/RectF;->set(Landroid/graphics/Rect;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    invoke-virtual {v1, v11, v3, v4, v2}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 78
    .line 79
    .line 80
    :cond_2
    iget-boolean v3, v0, Lmq/f;->W1:Z

    .line 81
    .line 82
    if-nez v3, :cond_4

    .line 83
    .line 84
    iget v3, v0, Lmq/f;->E1:I

    .line 85
    .line 86
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColor(I)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 90
    .line 91
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 92
    .line 93
    .line 94
    iget-object v3, v0, Lmq/f;->M1:Landroid/graphics/ColorFilter;

    .line 95
    .line 96
    if-eqz v3, :cond_3

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    iget-object v3, v0, Lmq/f;->N1:Landroid/graphics/PorterDuffColorFilter;

    .line 100
    .line 101
    :goto_1
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v11, v7}, Landroid/graphics/RectF;->set(Landroid/graphics/Rect;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    invoke-virtual {v1, v11, v3, v4, v2}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 116
    .line 117
    .line 118
    :cond_4
    iget-boolean v3, v0, Lmq/f;->W1:Z

    .line 119
    .line 120
    if-eqz v3, :cond_5

    .line 121
    .line 122
    invoke-super/range {p0 .. p1}, Lwq/i;->draw(Landroid/graphics/Canvas;)V

    .line 123
    .line 124
    .line 125
    :cond_5
    iget v3, v0, Lmq/f;->L:F

    .line 126
    .line 127
    const/4 v12, 0x0

    .line 128
    cmpl-float v3, v3, v12

    .line 129
    .line 130
    const/high16 v13, 0x40000000    # 2.0f

    .line 131
    .line 132
    if-lez v3, :cond_8

    .line 133
    .line 134
    iget-boolean v3, v0, Lmq/f;->W1:Z

    .line 135
    .line 136
    if-nez v3, :cond_8

    .line 137
    .line 138
    iget v3, v0, Lmq/f;->G1:I

    .line 139
    .line 140
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColor(I)V

    .line 141
    .line 142
    .line 143
    sget-object v3, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 144
    .line 145
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 146
    .line 147
    .line 148
    iget-boolean v3, v0, Lmq/f;->W1:Z

    .line 149
    .line 150
    if-nez v3, :cond_7

    .line 151
    .line 152
    iget-object v3, v0, Lmq/f;->M1:Landroid/graphics/ColorFilter;

    .line 153
    .line 154
    if-eqz v3, :cond_6

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_6
    iget-object v3, v0, Lmq/f;->N1:Landroid/graphics/PorterDuffColorFilter;

    .line 158
    .line 159
    :goto_2
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 160
    .line 161
    .line 162
    :cond_7
    iget v3, v7, Landroid/graphics/Rect;->left:I

    .line 163
    .line 164
    int-to-float v3, v3

    .line 165
    iget v4, v0, Lmq/f;->L:F

    .line 166
    .line 167
    div-float/2addr v4, v13

    .line 168
    add-float/2addr v3, v4

    .line 169
    iget v5, v7, Landroid/graphics/Rect;->top:I

    .line 170
    .line 171
    int-to-float v5, v5

    .line 172
    add-float/2addr v5, v4

    .line 173
    iget v6, v7, Landroid/graphics/Rect;->right:I

    .line 174
    .line 175
    int-to-float v6, v6

    .line 176
    sub-float/2addr v6, v4

    .line 177
    iget v14, v7, Landroid/graphics/Rect;->bottom:I

    .line 178
    .line 179
    int-to-float v14, v14

    .line 180
    sub-float/2addr v14, v4

    .line 181
    invoke-virtual {v11, v3, v5, v6, v14}, Landroid/graphics/RectF;->set(FFFF)V

    .line 182
    .line 183
    .line 184
    iget v3, v0, Lmq/f;->J:F

    .line 185
    .line 186
    iget v4, v0, Lmq/f;->L:F

    .line 187
    .line 188
    div-float/2addr v4, v13

    .line 189
    sub-float/2addr v3, v4

    .line 190
    invoke-virtual {v1, v11, v3, v3, v2}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 191
    .line 192
    .line 193
    :cond_8
    iget v3, v0, Lmq/f;->H1:I

    .line 194
    .line 195
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setColor(I)V

    .line 196
    .line 197
    .line 198
    sget-object v3, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 199
    .line 200
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v11, v7}, Landroid/graphics/RectF;->set(Landroid/graphics/Rect;)V

    .line 204
    .line 205
    .line 206
    iget-boolean v3, v0, Lmq/f;->W1:Z

    .line 207
    .line 208
    if-nez v3, :cond_9

    .line 209
    .line 210
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 211
    .line 212
    .line 213
    move-result v3

    .line 214
    invoke-virtual {v0}, Lmq/f;->w()F

    .line 215
    .line 216
    .line 217
    move-result v4

    .line 218
    invoke-virtual {v1, v11, v3, v4, v2}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 219
    .line 220
    .line 221
    move/from16 v21, v13

    .line 222
    .line 223
    :goto_3
    move-object v13, v0

    .line 224
    goto :goto_4

    .line 225
    :cond_9
    new-instance v3, Landroid/graphics/RectF;

    .line 226
    .line 227
    invoke-direct {v3, v7}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 228
    .line 229
    .line 230
    iget-object v4, v0, Lwq/i;->e:Lwq/g;

    .line 231
    .line 232
    iget-object v15, v4, Lwq/g;->a:Lwq/m;

    .line 233
    .line 234
    iget-object v5, v0, Lwq/i;->C:[F

    .line 235
    .line 236
    iget v4, v4, Lwq/g;->j:F

    .line 237
    .line 238
    iget-object v6, v0, Lwq/i;->t:Lpv/g;

    .line 239
    .line 240
    iget-object v14, v0, Lwq/i;->u:Lac/i;

    .line 241
    .line 242
    move/from16 v21, v13

    .line 243
    .line 244
    iget-object v13, v0, Lmq/f;->B1:Landroid/graphics/Path;

    .line 245
    .line 246
    move-object/from16 v18, v3

    .line 247
    .line 248
    move/from16 v17, v4

    .line 249
    .line 250
    move-object/from16 v16, v5

    .line 251
    .line 252
    move-object/from16 v19, v6

    .line 253
    .line 254
    move-object/from16 v20, v13

    .line 255
    .line 256
    invoke-virtual/range {v14 .. v20}, Lac/i;->b(Lwq/m;[FFLandroid/graphics/RectF;Lpv/g;Landroid/graphics/Path;)V

    .line 257
    .line 258
    .line 259
    move-object/from16 v3, v20

    .line 260
    .line 261
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 262
    .line 263
    .line 264
    move-result-object v6

    .line 265
    iget-object v4, v0, Lwq/i;->e:Lwq/g;

    .line 266
    .line 267
    iget-object v4, v4, Lwq/g;->a:Lwq/m;

    .line 268
    .line 269
    iget-object v5, v0, Lwq/i;->C:[F

    .line 270
    .line 271
    invoke-virtual/range {v0 .. v6}, Lwq/i;->d(Landroid/graphics/Canvas;Landroid/graphics/Paint;Landroid/graphics/Path;Lwq/m;[FLandroid/graphics/RectF;)V

    .line 272
    .line 273
    .line 274
    goto :goto_3

    .line 275
    :goto_4
    invoke-virtual {v13}, Lmq/f;->Y()Z

    .line 276
    .line 277
    .line 278
    move-result v0

    .line 279
    if-eqz v0, :cond_a

    .line 280
    .line 281
    invoke-virtual {v13, v7, v11}, Lmq/f;->t(Landroid/graphics/Rect;Landroid/graphics/RectF;)V

    .line 282
    .line 283
    .line 284
    iget v0, v11, Landroid/graphics/RectF;->left:F

    .line 285
    .line 286
    iget v2, v11, Landroid/graphics/RectF;->top:F

    .line 287
    .line 288
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 289
    .line 290
    .line 291
    iget-object v3, v13, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 292
    .line 293
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 294
    .line 295
    .line 296
    move-result v4

    .line 297
    float-to-int v4, v4

    .line 298
    invoke-virtual {v11}, Landroid/graphics/RectF;->height()F

    .line 299
    .line 300
    .line 301
    move-result v5

    .line 302
    float-to-int v5, v5

    .line 303
    invoke-virtual {v3, v9, v9, v4, v5}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 304
    .line 305
    .line 306
    iget-object v3, v13, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 307
    .line 308
    invoke-virtual {v3, v1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 309
    .line 310
    .line 311
    neg-float v0, v0

    .line 312
    neg-float v2, v2

    .line 313
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 314
    .line 315
    .line 316
    :cond_a
    invoke-virtual {v13}, Lmq/f;->X()Z

    .line 317
    .line 318
    .line 319
    move-result v0

    .line 320
    if-eqz v0, :cond_b

    .line 321
    .line 322
    invoke-virtual {v13, v7, v11}, Lmq/f;->t(Landroid/graphics/Rect;Landroid/graphics/RectF;)V

    .line 323
    .line 324
    .line 325
    iget v0, v11, Landroid/graphics/RectF;->left:F

    .line 326
    .line 327
    iget v2, v11, Landroid/graphics/RectF;->top:F

    .line 328
    .line 329
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 330
    .line 331
    .line 332
    iget-object v3, v13, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 333
    .line 334
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 335
    .line 336
    .line 337
    move-result v4

    .line 338
    float-to-int v4, v4

    .line 339
    invoke-virtual {v11}, Landroid/graphics/RectF;->height()F

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    float-to-int v5, v5

    .line 344
    invoke-virtual {v3, v9, v9, v4, v5}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 345
    .line 346
    .line 347
    iget-object v3, v13, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 348
    .line 349
    invoke-virtual {v3, v1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 350
    .line 351
    .line 352
    neg-float v0, v0

    .line 353
    neg-float v2, v2

    .line 354
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 355
    .line 356
    .line 357
    :cond_b
    iget-boolean v0, v13, Lmq/f;->U1:Z

    .line 358
    .line 359
    if-eqz v0, :cond_14

    .line 360
    .line 361
    iget-object v0, v13, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 362
    .line 363
    if-eqz v0, :cond_14

    .line 364
    .line 365
    iget-object v0, v13, Lmq/f;->A1:Landroid/graphics/PointF;

    .line 366
    .line 367
    invoke-virtual {v0, v12, v12}, Landroid/graphics/PointF;->set(FF)V

    .line 368
    .line 369
    .line 370
    sget-object v2, Landroid/graphics/Paint$Align;->LEFT:Landroid/graphics/Paint$Align;

    .line 371
    .line 372
    iget-object v3, v13, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 373
    .line 374
    iget-object v4, v13, Lmq/f;->C1:Lrq/i;

    .line 375
    .line 376
    if-eqz v3, :cond_d

    .line 377
    .line 378
    iget v3, v13, Lmq/f;->f0:F

    .line 379
    .line 380
    invoke-virtual {v13}, Lmq/f;->u()F

    .line 381
    .line 382
    .line 383
    move-result v5

    .line 384
    add-float/2addr v5, v3

    .line 385
    iget v3, v13, Lmq/f;->r1:F

    .line 386
    .line 387
    add-float/2addr v5, v3

    .line 388
    invoke-virtual {v13}, Landroid/graphics/drawable/Drawable;->getLayoutDirection()I

    .line 389
    .line 390
    .line 391
    move-result v3

    .line 392
    if-nez v3, :cond_c

    .line 393
    .line 394
    iget v3, v7, Landroid/graphics/Rect;->left:I

    .line 395
    .line 396
    int-to-float v3, v3

    .line 397
    add-float/2addr v3, v5

    .line 398
    iput v3, v0, Landroid/graphics/PointF;->x:F

    .line 399
    .line 400
    goto :goto_5

    .line 401
    :cond_c
    iget v2, v7, Landroid/graphics/Rect;->right:I

    .line 402
    .line 403
    int-to-float v2, v2

    .line 404
    sub-float/2addr v2, v5

    .line 405
    iput v2, v0, Landroid/graphics/PointF;->x:F

    .line 406
    .line 407
    sget-object v2, Landroid/graphics/Paint$Align;->RIGHT:Landroid/graphics/Paint$Align;

    .line 408
    .line 409
    :goto_5
    invoke-virtual {v7}, Landroid/graphics/Rect;->centerY()I

    .line 410
    .line 411
    .line 412
    move-result v3

    .line 413
    int-to-float v3, v3

    .line 414
    iget-object v5, v4, Lrq/i;->a:Landroid/text/TextPaint;

    .line 415
    .line 416
    iget-object v6, v13, Lmq/f;->y1:Landroid/graphics/Paint$FontMetrics;

    .line 417
    .line 418
    invoke-virtual {v5, v6}, Landroid/graphics/Paint;->getFontMetrics(Landroid/graphics/Paint$FontMetrics;)F

    .line 419
    .line 420
    .line 421
    iget v5, v6, Landroid/graphics/Paint$FontMetrics;->descent:F

    .line 422
    .line 423
    iget v6, v6, Landroid/graphics/Paint$FontMetrics;->ascent:F

    .line 424
    .line 425
    add-float/2addr v5, v6

    .line 426
    div-float v5, v5, v21

    .line 427
    .line 428
    sub-float/2addr v3, v5

    .line 429
    iput v3, v0, Landroid/graphics/PointF;->y:F

    .line 430
    .line 431
    :cond_d
    invoke-virtual {v11}, Landroid/graphics/RectF;->setEmpty()V

    .line 432
    .line 433
    .line 434
    iget-object v3, v13, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 435
    .line 436
    if-eqz v3, :cond_f

    .line 437
    .line 438
    iget v3, v13, Lmq/f;->f0:F

    .line 439
    .line 440
    invoke-virtual {v13}, Lmq/f;->u()F

    .line 441
    .line 442
    .line 443
    move-result v5

    .line 444
    add-float/2addr v5, v3

    .line 445
    iget v3, v13, Lmq/f;->r1:F

    .line 446
    .line 447
    add-float/2addr v5, v3

    .line 448
    iget v3, v13, Lmq/f;->v1:F

    .line 449
    .line 450
    invoke-virtual {v13}, Lmq/f;->v()F

    .line 451
    .line 452
    .line 453
    move-result v6

    .line 454
    add-float/2addr v6, v3

    .line 455
    iget v3, v13, Lmq/f;->s1:F

    .line 456
    .line 457
    add-float/2addr v6, v3

    .line 458
    invoke-virtual {v13}, Landroid/graphics/drawable/Drawable;->getLayoutDirection()I

    .line 459
    .line 460
    .line 461
    move-result v3

    .line 462
    if-nez v3, :cond_e

    .line 463
    .line 464
    iget v3, v7, Landroid/graphics/Rect;->left:I

    .line 465
    .line 466
    int-to-float v3, v3

    .line 467
    add-float/2addr v3, v5

    .line 468
    iput v3, v11, Landroid/graphics/RectF;->left:F

    .line 469
    .line 470
    iget v3, v7, Landroid/graphics/Rect;->right:I

    .line 471
    .line 472
    int-to-float v3, v3

    .line 473
    sub-float/2addr v3, v6

    .line 474
    iput v3, v11, Landroid/graphics/RectF;->right:F

    .line 475
    .line 476
    goto :goto_6

    .line 477
    :cond_e
    iget v3, v7, Landroid/graphics/Rect;->left:I

    .line 478
    .line 479
    int-to-float v3, v3

    .line 480
    add-float/2addr v3, v6

    .line 481
    iput v3, v11, Landroid/graphics/RectF;->left:F

    .line 482
    .line 483
    iget v3, v7, Landroid/graphics/Rect;->right:I

    .line 484
    .line 485
    int-to-float v3, v3

    .line 486
    sub-float/2addr v3, v5

    .line 487
    iput v3, v11, Landroid/graphics/RectF;->right:F

    .line 488
    .line 489
    :goto_6
    iget v3, v7, Landroid/graphics/Rect;->top:I

    .line 490
    .line 491
    int-to-float v3, v3

    .line 492
    iput v3, v11, Landroid/graphics/RectF;->top:F

    .line 493
    .line 494
    iget v3, v7, Landroid/graphics/Rect;->bottom:I

    .line 495
    .line 496
    int-to-float v3, v3

    .line 497
    iput v3, v11, Landroid/graphics/RectF;->bottom:F

    .line 498
    .line 499
    :cond_f
    iget-object v3, v4, Lrq/i;->f:Luq/c;

    .line 500
    .line 501
    iget-object v6, v4, Lrq/i;->a:Landroid/text/TextPaint;

    .line 502
    .line 503
    if-eqz v3, :cond_10

    .line 504
    .line 505
    invoke-virtual {v13}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 506
    .line 507
    .line 508
    move-result-object v3

    .line 509
    iput-object v3, v6, Landroid/text/TextPaint;->drawableState:[I

    .line 510
    .line 511
    iget-object v3, v4, Lrq/i;->f:Luq/c;

    .line 512
    .line 513
    iget-object v5, v4, Lrq/i;->b:Lmq/b;

    .line 514
    .line 515
    iget-object v12, v13, Lmq/f;->w1:Landroid/content/Context;

    .line 516
    .line 517
    invoke-virtual {v3, v12, v6, v5}, Luq/c;->d(Landroid/content/Context;Landroid/text/TextPaint;Llp/y9;)V

    .line 518
    .line 519
    .line 520
    :cond_10
    invoke-virtual {v6, v2}, Landroid/graphics/Paint;->setTextAlign(Landroid/graphics/Paint$Align;)V

    .line 521
    .line 522
    .line 523
    iget-object v2, v13, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 524
    .line 525
    invoke-interface {v2}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    invoke-virtual {v4, v2}, Lrq/i;->a(Ljava/lang/String;)F

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 534
    .line 535
    .line 536
    move-result v2

    .line 537
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 538
    .line 539
    .line 540
    move-result v3

    .line 541
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 542
    .line 543
    .line 544
    move-result v3

    .line 545
    if-le v2, v3, :cond_11

    .line 546
    .line 547
    const/4 v2, 0x1

    .line 548
    move v12, v2

    .line 549
    goto :goto_7

    .line 550
    :cond_11
    move v12, v9

    .line 551
    :goto_7
    if-eqz v12, :cond_12

    .line 552
    .line 553
    invoke-virtual {v1}, Landroid/graphics/Canvas;->save()I

    .line 554
    .line 555
    .line 556
    move-result v2

    .line 557
    invoke-virtual {v1, v11}, Landroid/graphics/Canvas;->clipRect(Landroid/graphics/RectF;)Z

    .line 558
    .line 559
    .line 560
    move v14, v2

    .line 561
    goto :goto_8

    .line 562
    :cond_12
    move v14, v9

    .line 563
    :goto_8
    iget-object v2, v13, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 564
    .line 565
    if-eqz v12, :cond_13

    .line 566
    .line 567
    iget-object v3, v13, Lmq/f;->T1:Landroid/text/TextUtils$TruncateAt;

    .line 568
    .line 569
    if-eqz v3, :cond_13

    .line 570
    .line 571
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 572
    .line 573
    .line 574
    move-result v3

    .line 575
    iget-object v4, v13, Lmq/f;->T1:Landroid/text/TextUtils$TruncateAt;

    .line 576
    .line 577
    invoke-static {v2, v6, v3, v4}, Landroid/text/TextUtils;->ellipsize(Ljava/lang/CharSequence;Landroid/text/TextPaint;FLandroid/text/TextUtils$TruncateAt;)Ljava/lang/CharSequence;

    .line 578
    .line 579
    .line 580
    move-result-object v2

    .line 581
    :cond_13
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 582
    .line 583
    .line 584
    move-result v3

    .line 585
    iget v4, v0, Landroid/graphics/PointF;->x:F

    .line 586
    .line 587
    iget v5, v0, Landroid/graphics/PointF;->y:F

    .line 588
    .line 589
    move-object v1, v2

    .line 590
    const/4 v2, 0x0

    .line 591
    move-object/from16 v0, p1

    .line 592
    .line 593
    invoke-virtual/range {v0 .. v6}, Landroid/graphics/Canvas;->drawText(Ljava/lang/CharSequence;IIFFLandroid/graphics/Paint;)V

    .line 594
    .line 595
    .line 596
    move-object v1, v0

    .line 597
    if-eqz v12, :cond_14

    .line 598
    .line 599
    invoke-virtual {v1, v14}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 600
    .line 601
    .line 602
    :cond_14
    invoke-virtual {v13}, Lmq/f;->Z()Z

    .line 603
    .line 604
    .line 605
    move-result v0

    .line 606
    if-eqz v0, :cond_17

    .line 607
    .line 608
    invoke-virtual {v11}, Landroid/graphics/RectF;->setEmpty()V

    .line 609
    .line 610
    .line 611
    invoke-virtual {v13}, Lmq/f;->Z()Z

    .line 612
    .line 613
    .line 614
    move-result v0

    .line 615
    if-eqz v0, :cond_16

    .line 616
    .line 617
    iget v0, v13, Lmq/f;->v1:F

    .line 618
    .line 619
    iget v2, v13, Lmq/f;->u1:F

    .line 620
    .line 621
    add-float/2addr v0, v2

    .line 622
    invoke-virtual {v13}, Landroid/graphics/drawable/Drawable;->getLayoutDirection()I

    .line 623
    .line 624
    .line 625
    move-result v2

    .line 626
    if-nez v2, :cond_15

    .line 627
    .line 628
    iget v2, v7, Landroid/graphics/Rect;->right:I

    .line 629
    .line 630
    int-to-float v2, v2

    .line 631
    sub-float/2addr v2, v0

    .line 632
    iput v2, v11, Landroid/graphics/RectF;->right:F

    .line 633
    .line 634
    iget v0, v13, Lmq/f;->X:F

    .line 635
    .line 636
    sub-float/2addr v2, v0

    .line 637
    iput v2, v11, Landroid/graphics/RectF;->left:F

    .line 638
    .line 639
    goto :goto_9

    .line 640
    :cond_15
    iget v2, v7, Landroid/graphics/Rect;->left:I

    .line 641
    .line 642
    int-to-float v2, v2

    .line 643
    add-float/2addr v2, v0

    .line 644
    iput v2, v11, Landroid/graphics/RectF;->left:F

    .line 645
    .line 646
    iget v0, v13, Lmq/f;->X:F

    .line 647
    .line 648
    add-float/2addr v2, v0

    .line 649
    iput v2, v11, Landroid/graphics/RectF;->right:F

    .line 650
    .line 651
    :goto_9
    invoke-virtual {v7}, Landroid/graphics/Rect;->exactCenterY()F

    .line 652
    .line 653
    .line 654
    move-result v0

    .line 655
    iget v2, v13, Lmq/f;->X:F

    .line 656
    .line 657
    div-float v3, v2, v21

    .line 658
    .line 659
    sub-float/2addr v0, v3

    .line 660
    iput v0, v11, Landroid/graphics/RectF;->top:F

    .line 661
    .line 662
    add-float/2addr v0, v2

    .line 663
    iput v0, v11, Landroid/graphics/RectF;->bottom:F

    .line 664
    .line 665
    :cond_16
    iget v0, v11, Landroid/graphics/RectF;->left:F

    .line 666
    .line 667
    iget v2, v11, Landroid/graphics/RectF;->top:F

    .line 668
    .line 669
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 670
    .line 671
    .line 672
    iget-object v3, v13, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 673
    .line 674
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 675
    .line 676
    .line 677
    move-result v4

    .line 678
    float-to-int v4, v4

    .line 679
    invoke-virtual {v11}, Landroid/graphics/RectF;->height()F

    .line 680
    .line 681
    .line 682
    move-result v5

    .line 683
    float-to-int v5, v5

    .line 684
    invoke-virtual {v3, v9, v9, v4, v5}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 685
    .line 686
    .line 687
    iget-object v3, v13, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 688
    .line 689
    iget-object v4, v13, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 690
    .line 691
    invoke-virtual {v4}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 692
    .line 693
    .line 694
    move-result-object v4

    .line 695
    invoke-virtual {v3, v4}, Landroid/graphics/drawable/Drawable;->setBounds(Landroid/graphics/Rect;)V

    .line 696
    .line 697
    .line 698
    iget-object v3, v13, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 699
    .line 700
    invoke-virtual {v3}, Landroid/graphics/drawable/Drawable;->jumpToCurrentState()V

    .line 701
    .line 702
    .line 703
    iget-object v3, v13, Lmq/f;->V:Landroid/graphics/drawable/RippleDrawable;

    .line 704
    .line 705
    invoke-virtual {v3, v1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 706
    .line 707
    .line 708
    neg-float v0, v0

    .line 709
    neg-float v2, v2

    .line 710
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 711
    .line 712
    .line 713
    :cond_17
    iget v0, v13, Lmq/f;->L1:I

    .line 714
    .line 715
    if-ge v0, v8, :cond_18

    .line 716
    .line 717
    invoke-virtual {v1, v10}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 718
    .line 719
    .line 720
    :cond_18
    :goto_a
    return-void
.end method

.method public final getAlpha()I
    .locals 0

    .line 1
    iget p0, p0, Lmq/f;->L1:I

    .line 2
    .line 3
    return p0
.end method

.method public final getColorFilter()Landroid/graphics/ColorFilter;
    .locals 0

    .line 1
    iget-object p0, p0, Lmq/f;->M1:Landroid/graphics/ColorFilter;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getIntrinsicHeight()I
    .locals 0

    .line 1
    iget p0, p0, Lmq/f;->I:F

    .line 2
    .line 3
    float-to-int p0, p0

    .line 4
    return p0
.end method

.method public final getIntrinsicWidth()I
    .locals 3

    .line 1
    iget v0, p0, Lmq/f;->f0:F

    .line 2
    .line 3
    invoke-virtual {p0}, Lmq/f;->u()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    add-float/2addr v1, v0

    .line 8
    iget v0, p0, Lmq/f;->r1:F

    .line 9
    .line 10
    add-float/2addr v1, v0

    .line 11
    iget-object v0, p0, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v2, p0, Lmq/f;->C1:Lrq/i;

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Lrq/i;->a(Ljava/lang/String;)F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    add-float/2addr v0, v1

    .line 24
    iget v1, p0, Lmq/f;->s1:F

    .line 25
    .line 26
    add-float/2addr v0, v1

    .line 27
    invoke-virtual {p0}, Lmq/f;->v()F

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    add-float/2addr v1, v0

    .line 32
    iget v0, p0, Lmq/f;->v1:F

    .line 33
    .line 34
    add-float/2addr v1, v0

    .line 35
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    iget p0, p0, Lmq/f;->V1:I

    .line 40
    .line 41
    invoke-static {v0, p0}, Ljava/lang/Math;->min(II)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0
.end method

.method public final getOpacity()I
    .locals 0

    .line 1
    const/4 p0, -0x3

    .line 2
    return p0
.end method

.method public final getOutline(Landroid/graphics/Outline;)V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lmq/f;->W1:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Lwq/i;->getOutline(Landroid/graphics/Outline;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {v0}, Landroid/graphics/Rect;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    iget v1, p0, Lmq/f;->J:F

    .line 20
    .line 21
    invoke-virtual {p1, v0, v1}, Landroid/graphics/Outline;->setRoundRect(Landroid/graphics/Rect;F)V

    .line 22
    .line 23
    .line 24
    move-object v2, p1

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p0}, Lmq/f;->getIntrinsicWidth()I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    iget v0, p0, Lmq/f;->I:F

    .line 31
    .line 32
    float-to-int v6, v0

    .line 33
    iget v7, p0, Lmq/f;->J:F

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v4, 0x0

    .line 37
    move-object v2, p1

    .line 38
    invoke-virtual/range {v2 .. v7}, Landroid/graphics/Outline;->setRoundRect(IIIIF)V

    .line 39
    .line 40
    .line 41
    :goto_0
    iget p0, p0, Lmq/f;->L1:I

    .line 42
    .line 43
    int-to-float p0, p0

    .line 44
    const/high16 p1, 0x437f0000    # 255.0f

    .line 45
    .line 46
    div-float/2addr p0, p1

    .line 47
    invoke-virtual {v2, p0}, Landroid/graphics/Outline;->setAlpha(F)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public final invalidateDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, p0}, Landroid/graphics/drawable/Drawable$Callback;->invalidateDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final isStateful()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->G:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    invoke-static {v0}, Lmq/f;->x(Landroid/content/res/ColorStateList;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object v0, p0, Lmq/f;->H:Landroid/content/res/ColorStateList;

    .line 10
    .line 11
    invoke-static {v0}, Lmq/f;->x(Landroid/content/res/ColorStateList;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_3

    .line 16
    .line 17
    iget-object v0, p0, Lmq/f;->K:Landroid/content/res/ColorStateList;

    .line 18
    .line 19
    invoke-static {v0}, Lmq/f;->x(Landroid/content/res/ColorStateList;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_3

    .line 24
    .line 25
    iget-object v0, p0, Lmq/f;->C1:Lrq/i;

    .line 26
    .line 27
    iget-object v0, v0, Lrq/i;->f:Luq/c;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    iget-object v0, v0, Luq/c;->k:Landroid/content/res/ColorStateList;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-boolean v0, p0, Lmq/f;->a0:Z

    .line 43
    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    iget-boolean v0, p0, Lmq/f;->Z:Z

    .line 51
    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 56
    .line 57
    invoke-static {v0}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-nez v0, :cond_3

    .line 62
    .line 63
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 64
    .line 65
    invoke-static {v0}, Lmq/f;->y(Landroid/graphics/drawable/Drawable;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_3

    .line 70
    .line 71
    iget-object p0, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 72
    .line 73
    invoke-static {p0}, Lmq/f;->x(Landroid/content/res/ColorStateList;)Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-eqz p0, :cond_2

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_2
    const/4 p0, 0x0

    .line 81
    return p0

    .line 82
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 83
    return p0
.end method

.method public final onLayoutDirectionChanged(I)Z
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/graphics/drawable/Drawable;->onLayoutDirectionChanged(I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLayoutDirection(I)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    or-int/2addr v0, v1

    .line 18
    :cond_0
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLayoutDirection(I)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    or-int/2addr v0, v1

    .line 31
    :cond_1
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    iget-object v1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 38
    .line 39
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLayoutDirection(I)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    or-int/2addr v0, p1

    .line 44
    :cond_2
    if-eqz v0, :cond_3

    .line 45
    .line 46
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 47
    .line 48
    .line 49
    :cond_3
    const/4 p0, 0x1

    .line 50
    return p0
.end method

.method public final onLevelChange(I)Z
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/graphics/drawable/Drawable;->onLevelChange(I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    or-int/2addr v0, v1

    .line 18
    :cond_0
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    or-int/2addr v0, v1

    .line 31
    :cond_1
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    iget-object v1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 38
    .line 39
    invoke-virtual {v1, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    or-int/2addr v0, p1

    .line 44
    :cond_2
    if-eqz v0, :cond_3

    .line 45
    .line 46
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 47
    .line 48
    .line 49
    :cond_3
    return v0
.end method

.method public final onStateChange([I)Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->W1:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Lwq/i;->onStateChange([I)Z

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lmq/f;->Q1:[I

    .line 9
    .line 10
    invoke-virtual {p0, p1, v0}, Lmq/f;->A([I[I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public final s(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getLayoutDirection()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setLayoutDirection(I)Z

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getLevel()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, 0x0

    .line 26
    invoke-virtual {p1, v0, v1}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 30
    .line 31
    if-ne p1, v0, :cond_2

    .line 32
    .line 33
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    iget-object v0, p0, Lmq/f;->Q1:[I

    .line 40
    .line 41
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 42
    .line 43
    .line 44
    :cond_1
    iget-object p0, p0, Lmq/f;->W:Landroid/content/res/ColorStateList;

    .line 45
    .line 46
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 51
    .line 52
    if-ne p1, v0, :cond_3

    .line 53
    .line 54
    iget-boolean v1, p0, Lmq/f;->S:Z

    .line 55
    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    iget-object v1, p0, Lmq/f;->Q:Landroid/content/res/ColorStateList;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 61
    .line 62
    .line 63
    :cond_3
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 74
    .line 75
    .line 76
    :cond_4
    :goto_0
    return-void
.end method

.method public final scheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, p0, p2, p3, p4}, Landroid/graphics/drawable/Drawable$Callback;->scheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;J)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final setAlpha(I)V
    .locals 1

    .line 1
    iget v0, p0, Lmq/f;->L1:I

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput p1, p0, Lmq/f;->L1:I

    .line 6
    .line 7
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final setColorFilter(Landroid/graphics/ColorFilter;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->M1:Landroid/graphics/ColorFilter;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->M1:Landroid/graphics/ColorFilter;

    .line 6
    .line 7
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final setTintList(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0, p1}, Lmq/f;->onStateChange([I)Z

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final setTintMode(Landroid/graphics/PorterDuff$Mode;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lmq/f;->P1:Landroid/graphics/PorterDuff$Mode;

    .line 2
    .line 3
    if-eq v0, p1, :cond_2

    .line 4
    .line 5
    iput-object p1, p0, Lmq/f;->P1:Landroid/graphics/PorterDuff$Mode;

    .line 6
    .line 7
    iget-object v0, p0, Lmq/f;->O1:Landroid/content/res/ColorStateList;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v0, v1, v2}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    new-instance v1, Landroid/graphics/PorterDuffColorFilter;

    .line 24
    .line 25
    invoke-direct {v1, v0, p1}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 30
    :goto_1
    iput-object v1, p0, Lmq/f;->N1:Landroid/graphics/PorterDuffColorFilter;

    .line 31
    .line 32
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 33
    .line 34
    .line 35
    :cond_2
    return-void
.end method

.method public final setVisible(ZZ)Z
    .locals 2

    .line 1
    invoke-super {p0, p1, p2}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    invoke-virtual {v1, p1, p2}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    or-int/2addr v0, v1

    .line 18
    :cond_0
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 25
    .line 26
    invoke-virtual {v1, p1, p2}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    or-int/2addr v0, v1

    .line 31
    :cond_1
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    iget-object v1, p0, Lmq/f;->U:Landroid/graphics/drawable/Drawable;

    .line 38
    .line 39
    invoke-virtual {v1, p1, p2}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    or-int/2addr v0, p1

    .line 44
    :cond_2
    if-eqz v0, :cond_3

    .line 45
    .line 46
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 47
    .line 48
    .line 49
    :cond_3
    return v0
.end method

.method public final t(Landroid/graphics/Rect;Landroid/graphics/RectF;)V
    .locals 5

    .line 1
    invoke-virtual {p2}, Landroid/graphics/RectF;->setEmpty()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    return-void

    .line 18
    :cond_1
    :goto_0
    iget v0, p0, Lmq/f;->f0:F

    .line 19
    .line 20
    iget v1, p0, Lmq/f;->g0:F

    .line 21
    .line 22
    add-float/2addr v0, v1

    .line 23
    iget-boolean v1, p0, Lmq/f;->J1:Z

    .line 24
    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget-object v1, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_2
    iget-object v1, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 31
    .line 32
    :goto_1
    iget v2, p0, Lmq/f;->R:F

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    cmpg-float v4, v2, v3

    .line 36
    .line 37
    if-gtz v4, :cond_3

    .line 38
    .line 39
    if-eqz v1, :cond_3

    .line 40
    .line 41
    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    int-to-float v2, v1

    .line 46
    :cond_3
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getLayoutDirection()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_4

    .line 51
    .line 52
    iget v1, p1, Landroid/graphics/Rect;->left:I

    .line 53
    .line 54
    int-to-float v1, v1

    .line 55
    add-float/2addr v1, v0

    .line 56
    iput v1, p2, Landroid/graphics/RectF;->left:F

    .line 57
    .line 58
    add-float/2addr v1, v2

    .line 59
    iput v1, p2, Landroid/graphics/RectF;->right:F

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_4
    iget v1, p1, Landroid/graphics/Rect;->right:I

    .line 63
    .line 64
    int-to-float v1, v1

    .line 65
    sub-float/2addr v1, v0

    .line 66
    iput v1, p2, Landroid/graphics/RectF;->right:F

    .line 67
    .line 68
    sub-float/2addr v1, v2

    .line 69
    iput v1, p2, Landroid/graphics/RectF;->left:F

    .line 70
    .line 71
    :goto_2
    iget-boolean v0, p0, Lmq/f;->J1:Z

    .line 72
    .line 73
    if-eqz v0, :cond_5

    .line 74
    .line 75
    iget-object v0, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_5
    iget-object v0, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 79
    .line 80
    :goto_3
    iget v1, p0, Lmq/f;->R:F

    .line 81
    .line 82
    cmpg-float v2, v1, v3

    .line 83
    .line 84
    if-gtz v2, :cond_6

    .line 85
    .line 86
    if-eqz v0, :cond_6

    .line 87
    .line 88
    iget-object p0, p0, Lmq/f;->w1:Landroid/content/Context;

    .line 89
    .line 90
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    const/16 v1, 0x18

    .line 95
    .line 96
    int-to-float v1, v1

    .line 97
    invoke-virtual {p0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const/4 v2, 0x1

    .line 102
    invoke-static {v2, v1, p0}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    float-to-double v1, p0

    .line 107
    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    .line 108
    .line 109
    .line 110
    move-result-wide v1

    .line 111
    double-to-float v1, v1

    .line 112
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    int-to-float p0, p0

    .line 117
    cmpg-float p0, p0, v1

    .line 118
    .line 119
    if-gtz p0, :cond_6

    .line 120
    .line 121
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    int-to-float v1, p0

    .line 126
    :cond_6
    invoke-virtual {p1}, Landroid/graphics/Rect;->exactCenterY()F

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    const/high16 p1, 0x40000000    # 2.0f

    .line 131
    .line 132
    div-float p1, v1, p1

    .line 133
    .line 134
    sub-float/2addr p0, p1

    .line 135
    iput p0, p2, Landroid/graphics/RectF;->top:F

    .line 136
    .line 137
    add-float/2addr p0, v1

    .line 138
    iput p0, p2, Landroid/graphics/RectF;->bottom:F

    .line 139
    .line 140
    return-void
.end method

.method public final u()F
    .locals 4

    .line 1
    invoke-virtual {p0}, Lmq/f;->Y()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Lmq/f;->X()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    return v1

    .line 16
    :cond_1
    :goto_0
    iget v0, p0, Lmq/f;->g0:F

    .line 17
    .line 18
    iget-boolean v2, p0, Lmq/f;->J1:Z

    .line 19
    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    iget-object v2, p0, Lmq/f;->b0:Landroid/graphics/drawable/Drawable;

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_2
    iget-object v2, p0, Lmq/f;->P:Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    :goto_1
    iget v3, p0, Lmq/f;->R:F

    .line 28
    .line 29
    cmpg-float v1, v3, v1

    .line 30
    .line 31
    if-gtz v1, :cond_3

    .line 32
    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    invoke-virtual {v2}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    int-to-float v3, v1

    .line 40
    :cond_3
    add-float/2addr v3, v0

    .line 41
    iget p0, p0, Lmq/f;->q1:F

    .line 42
    .line 43
    add-float/2addr v3, p0

    .line 44
    return v3
.end method

.method public final unscheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, p0, p2}, Landroid/graphics/drawable/Drawable$Callback;->unscheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final v()F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lmq/f;->Z()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lmq/f;->t1:F

    .line 8
    .line 9
    iget v1, p0, Lmq/f;->X:F

    .line 10
    .line 11
    add-float/2addr v0, v1

    .line 12
    iget p0, p0, Lmq/f;->u1:F

    .line 13
    .line 14
    add-float/2addr v0, p0

    .line 15
    return v0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final w()F
    .locals 1

    .line 1
    iget-boolean v0, p0, Lmq/f;->W1:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lwq/i;->C:[F

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x3

    .line 10
    aget p0, v0, p0

    .line 11
    .line 12
    return p0

    .line 13
    :cond_0
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 14
    .line 15
    iget-object v0, v0, Lwq/g;->a:Lwq/m;

    .line 16
    .line 17
    iget-object v0, v0, Lwq/m;->e:Lwq/d;

    .line 18
    .line 19
    invoke-virtual {p0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-interface {v0, p0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_1
    iget p0, p0, Lmq/f;->J:F

    .line 29
    .line 30
    return p0
.end method

.method public final z()V
    .locals 1

    .line 1
    iget-object p0, p0, Lmq/f;->S1:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lmq/e;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    check-cast p0, Lcom/google/android/material/chip/Chip;

    .line 12
    .line 13
    iget v0, p0, Lcom/google/android/material/chip/Chip;->s:I

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Lcom/google/android/material/chip/Chip;->b(I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/view/View;->invalidateOutline()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method
