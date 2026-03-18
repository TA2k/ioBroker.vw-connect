.class public Lm/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll/b0;


# instance fields
.field public A:Landroid/graphics/Rect;

.field public B:Z

.field public final C:Lm/z;

.field public final d:Landroid/content/Context;

.field public e:Landroid/widget/ListAdapter;

.field public f:Lm/m1;

.field public final g:I

.field public h:I

.field public i:I

.field public j:I

.field public final k:I

.field public l:Z

.field public m:Z

.field public n:Z

.field public o:I

.field public final p:I

.field public q:Lm/w1;

.field public r:Landroid/view/View;

.field public s:Landroid/widget/AdapterView$OnItemClickListener;

.field public t:Landroid/widget/AdapterView$OnItemSelectedListener;

.field public final u:Lm/v1;

.field public final v:Lm/y1;

.field public final w:Lm/x1;

.field public final x:Lm/v1;

.field public final y:Landroid/os/Handler;

.field public final z:Landroid/graphics/Rect;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 p4, -0x2

    .line 5
    iput p4, p0, Lm/z1;->g:I

    .line 6
    .line 7
    iput p4, p0, Lm/z1;->h:I

    .line 8
    .line 9
    const/16 p4, 0x3ea

    .line 10
    .line 11
    iput p4, p0, Lm/z1;->k:I

    .line 12
    .line 13
    const/4 p4, 0x0

    .line 14
    iput p4, p0, Lm/z1;->o:I

    .line 15
    .line 16
    const v0, 0x7fffffff

    .line 17
    .line 18
    .line 19
    iput v0, p0, Lm/z1;->p:I

    .line 20
    .line 21
    new-instance v0, Lm/v1;

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    invoke-direct {v0, p0, v1}, Lm/v1;-><init>(Lm/z1;I)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lm/z1;->u:Lm/v1;

    .line 28
    .line 29
    new-instance v0, Lm/y1;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Lm/y1;-><init>(Lm/z1;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lm/z1;->v:Lm/y1;

    .line 35
    .line 36
    new-instance v0, Lm/x1;

    .line 37
    .line 38
    invoke-direct {v0, p0}, Lm/x1;-><init>(Lm/z1;)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Lm/z1;->w:Lm/x1;

    .line 42
    .line 43
    new-instance v0, Lm/v1;

    .line 44
    .line 45
    const/4 v1, 0x0

    .line 46
    invoke-direct {v0, p0, v1}, Lm/v1;-><init>(Lm/z1;I)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lm/z1;->x:Lm/v1;

    .line 50
    .line 51
    new-instance v0, Landroid/graphics/Rect;

    .line 52
    .line 53
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 54
    .line 55
    .line 56
    iput-object v0, p0, Lm/z1;->z:Landroid/graphics/Rect;

    .line 57
    .line 58
    iput-object p1, p0, Lm/z1;->d:Landroid/content/Context;

    .line 59
    .line 60
    new-instance v0, Landroid/os/Handler;

    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/content/Context;->getMainLooper()Landroid/os/Looper;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 67
    .line 68
    .line 69
    iput-object v0, p0, Lm/z1;->y:Landroid/os/Handler;

    .line 70
    .line 71
    sget-object v0, Lg/a;->o:[I

    .line 72
    .line 73
    invoke-virtual {p1, p2, v0, p3, p4}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-virtual {v0, p4, p4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    iput v1, p0, Lm/z1;->i:I

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    invoke-virtual {v0, v1, p4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    iput v2, p0, Lm/z1;->j:I

    .line 89
    .line 90
    if-eqz v2, :cond_0

    .line 91
    .line 92
    iput-boolean v1, p0, Lm/z1;->l:Z

    .line 93
    .line 94
    :cond_0
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    .line 95
    .line 96
    .line 97
    new-instance v0, Lm/z;

    .line 98
    .line 99
    invoke-direct {v0, p1, p2, p3, p4}, Landroid/widget/PopupWindow;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 100
    .line 101
    .line 102
    sget-object v2, Lg/a;->s:[I

    .line 103
    .line 104
    invoke-virtual {p1, p2, v2, p3, p4}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    const/4 p3, 0x2

    .line 109
    invoke-virtual {p2, p3}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    if-eqz v2, :cond_1

    .line 114
    .line 115
    invoke-virtual {p2, p3, p4}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 116
    .line 117
    .line 118
    move-result p3

    .line 119
    invoke-virtual {v0, p3}, Landroid/widget/PopupWindow;->setOverlapAnchor(Z)V

    .line 120
    .line 121
    .line 122
    :cond_1
    invoke-virtual {p2, p4}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 123
    .line 124
    .line 125
    move-result p3

    .line 126
    if-eqz p3, :cond_2

    .line 127
    .line 128
    invoke-virtual {p2, p4, p4}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 129
    .line 130
    .line 131
    move-result p3

    .line 132
    if-eqz p3, :cond_2

    .line 133
    .line 134
    invoke-static {p1, p3}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    goto :goto_0

    .line 139
    :cond_2
    invoke-virtual {p2, p4}, Landroid/content/res/TypedArray;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    :goto_0
    invoke-virtual {v0, p1}, Landroid/widget/PopupWindow;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 147
    .line 148
    .line 149
    iput-object v0, p0, Lm/z1;->C:Lm/z;

    .line 150
    .line 151
    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    .line 152
    .line 153
    .line 154
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm/z1;->C:Lm/z;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()V
    .locals 13

    .line 1
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 2
    .line 3
    iget-object v1, p0, Lm/z1;->d:Landroid/content/Context;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    iget-object v3, p0, Lm/z1;->C:Lm/z;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    iget-boolean v0, p0, Lm/z1;->B:Z

    .line 11
    .line 12
    xor-int/2addr v0, v2

    .line 13
    invoke-virtual {p0, v1, v0}, Lm/z1;->p(Landroid/content/Context;Z)Lm/m1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iput-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 18
    .line 19
    iget-object v4, p0, Lm/z1;->e:Landroid/widget/ListAdapter;

    .line 20
    .line 21
    invoke-virtual {v0, v4}, Landroid/widget/AbsListView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 25
    .line 26
    iget-object v4, p0, Lm/z1;->s:Landroid/widget/AdapterView$OnItemClickListener;

    .line 27
    .line 28
    invoke-virtual {v0, v4}, Landroid/widget/AdapterView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 32
    .line 33
    invoke-virtual {v0, v2}, Landroid/view/View;->setFocusable(Z)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 37
    .line 38
    invoke-virtual {v0, v2}, Landroid/view/View;->setFocusableInTouchMode(Z)V

    .line 39
    .line 40
    .line 41
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 42
    .line 43
    new-instance v4, Lm/s1;

    .line 44
    .line 45
    invoke-direct {v4, p0}, Lm/s1;-><init>(Lm/z1;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, v4}, Landroid/widget/AdapterView;->setOnItemSelectedListener(Landroid/widget/AdapterView$OnItemSelectedListener;)V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 52
    .line 53
    iget-object v4, p0, Lm/z1;->w:Lm/x1;

    .line 54
    .line 55
    invoke-virtual {v0, v4}, Landroid/widget/AbsListView;->setOnScrollListener(Landroid/widget/AbsListView$OnScrollListener;)V

    .line 56
    .line 57
    .line 58
    iget-object v0, p0, Lm/z1;->t:Landroid/widget/AdapterView$OnItemSelectedListener;

    .line 59
    .line 60
    if-eqz v0, :cond_0

    .line 61
    .line 62
    iget-object v4, p0, Lm/z1;->f:Lm/m1;

    .line 63
    .line 64
    invoke-virtual {v4, v0}, Landroid/widget/AdapterView;->setOnItemSelectedListener(Landroid/widget/AdapterView$OnItemSelectedListener;)V

    .line 65
    .line 66
    .line 67
    :cond_0
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 68
    .line 69
    invoke-virtual {v3, v0}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    invoke-virtual {v3}, Landroid/widget/PopupWindow;->getContentView()Landroid/view/View;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    check-cast v0, Landroid/view/ViewGroup;

    .line 78
    .line 79
    :goto_0
    invoke-virtual {v3}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    iget-object v4, p0, Lm/z1;->z:Landroid/graphics/Rect;

    .line 84
    .line 85
    const/4 v5, 0x0

    .line 86
    if-eqz v0, :cond_2

    .line 87
    .line 88
    invoke-virtual {v0, v4}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    .line 89
    .line 90
    .line 91
    iget v0, v4, Landroid/graphics/Rect;->top:I

    .line 92
    .line 93
    iget v6, v4, Landroid/graphics/Rect;->bottom:I

    .line 94
    .line 95
    add-int/2addr v6, v0

    .line 96
    iget-boolean v7, p0, Lm/z1;->l:Z

    .line 97
    .line 98
    if-nez v7, :cond_3

    .line 99
    .line 100
    neg-int v0, v0

    .line 101
    iput v0, p0, Lm/z1;->j:I

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_2
    invoke-virtual {v4}, Landroid/graphics/Rect;->setEmpty()V

    .line 105
    .line 106
    .line 107
    move v6, v5

    .line 108
    :cond_3
    :goto_1
    invoke-virtual {v3}, Landroid/widget/PopupWindow;->getInputMethodMode()I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    const/4 v7, 0x2

    .line 113
    if-ne v0, v7, :cond_4

    .line 114
    .line 115
    move v0, v2

    .line 116
    goto :goto_2

    .line 117
    :cond_4
    move v0, v5

    .line 118
    :goto_2
    iget-object v8, p0, Lm/z1;->r:Landroid/view/View;

    .line 119
    .line 120
    iget v9, p0, Lm/z1;->j:I

    .line 121
    .line 122
    invoke-static {v3, v8, v9, v0}, Lm/t1;->a(Landroid/widget/PopupWindow;Landroid/view/View;IZ)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    iget v8, p0, Lm/z1;->g:I

    .line 127
    .line 128
    const/4 v9, -0x2

    .line 129
    const/4 v10, -0x1

    .line 130
    if-ne v8, v10, :cond_5

    .line 131
    .line 132
    add-int/2addr v0, v6

    .line 133
    goto :goto_5

    .line 134
    :cond_5
    iget v11, p0, Lm/z1;->h:I

    .line 135
    .line 136
    if-eq v11, v9, :cond_7

    .line 137
    .line 138
    const/high16 v12, 0x40000000    # 2.0f

    .line 139
    .line 140
    if-eq v11, v10, :cond_6

    .line 141
    .line 142
    invoke-static {v11, v12}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    goto :goto_3

    .line 147
    :cond_6
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    iget v1, v1, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 156
    .line 157
    iget v11, v4, Landroid/graphics/Rect;->left:I

    .line 158
    .line 159
    iget v4, v4, Landroid/graphics/Rect;->right:I

    .line 160
    .line 161
    add-int/2addr v11, v4

    .line 162
    sub-int/2addr v1, v11

    .line 163
    invoke-static {v1, v12}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    goto :goto_3

    .line 168
    :cond_7
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    iget v1, v1, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 177
    .line 178
    iget v11, v4, Landroid/graphics/Rect;->left:I

    .line 179
    .line 180
    iget v4, v4, Landroid/graphics/Rect;->right:I

    .line 181
    .line 182
    add-int/2addr v11, v4

    .line 183
    sub-int/2addr v1, v11

    .line 184
    const/high16 v4, -0x80000000

    .line 185
    .line 186
    invoke-static {v1, v4}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    :goto_3
    iget-object v4, p0, Lm/z1;->f:Lm/m1;

    .line 191
    .line 192
    invoke-virtual {v4, v1, v0}, Lm/m1;->a(II)I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-lez v0, :cond_8

    .line 197
    .line 198
    iget-object v1, p0, Lm/z1;->f:Lm/m1;

    .line 199
    .line 200
    invoke-virtual {v1}, Landroid/view/View;->getPaddingTop()I

    .line 201
    .line 202
    .line 203
    move-result v1

    .line 204
    iget-object v4, p0, Lm/z1;->f:Lm/m1;

    .line 205
    .line 206
    invoke-virtual {v4}, Landroid/view/View;->getPaddingBottom()I

    .line 207
    .line 208
    .line 209
    move-result v4

    .line 210
    add-int/2addr v4, v1

    .line 211
    add-int/2addr v4, v6

    .line 212
    goto :goto_4

    .line 213
    :cond_8
    move v4, v5

    .line 214
    :goto_4
    add-int/2addr v0, v4

    .line 215
    :goto_5
    invoke-virtual {v3}, Landroid/widget/PopupWindow;->getInputMethodMode()I

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    if-ne v1, v7, :cond_9

    .line 220
    .line 221
    move v1, v2

    .line 222
    goto :goto_6

    .line 223
    :cond_9
    move v1, v5

    .line 224
    :goto_6
    iget v4, p0, Lm/z1;->k:I

    .line 225
    .line 226
    invoke-virtual {v3, v4}, Landroid/widget/PopupWindow;->setWindowLayoutType(I)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v3}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 230
    .line 231
    .line 232
    move-result v4

    .line 233
    if-eqz v4, :cond_15

    .line 234
    .line 235
    iget-object v4, p0, Lm/z1;->r:Landroid/view/View;

    .line 236
    .line 237
    invoke-virtual {v4}, Landroid/view/View;->isAttachedToWindow()Z

    .line 238
    .line 239
    .line 240
    move-result v4

    .line 241
    if-nez v4, :cond_a

    .line 242
    .line 243
    goto/16 :goto_e

    .line 244
    .line 245
    :cond_a
    iget v4, p0, Lm/z1;->h:I

    .line 246
    .line 247
    if-ne v4, v10, :cond_b

    .line 248
    .line 249
    move v4, v10

    .line 250
    goto :goto_7

    .line 251
    :cond_b
    if-ne v4, v9, :cond_c

    .line 252
    .line 253
    iget-object v4, p0, Lm/z1;->r:Landroid/view/View;

    .line 254
    .line 255
    invoke-virtual {v4}, Landroid/view/View;->getWidth()I

    .line 256
    .line 257
    .line 258
    move-result v4

    .line 259
    :cond_c
    :goto_7
    if-ne v8, v10, :cond_11

    .line 260
    .line 261
    if-eqz v1, :cond_d

    .line 262
    .line 263
    move v8, v0

    .line 264
    goto :goto_8

    .line 265
    :cond_d
    move v8, v10

    .line 266
    :goto_8
    if-eqz v1, :cond_f

    .line 267
    .line 268
    iget v0, p0, Lm/z1;->h:I

    .line 269
    .line 270
    if-ne v0, v10, :cond_e

    .line 271
    .line 272
    move v0, v10

    .line 273
    goto :goto_9

    .line 274
    :cond_e
    move v0, v5

    .line 275
    :goto_9
    invoke-virtual {v3, v0}, Landroid/widget/PopupWindow;->setWidth(I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v3, v5}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 279
    .line 280
    .line 281
    goto :goto_a

    .line 282
    :cond_f
    iget v0, p0, Lm/z1;->h:I

    .line 283
    .line 284
    if-ne v0, v10, :cond_10

    .line 285
    .line 286
    move v5, v10

    .line 287
    :cond_10
    invoke-virtual {v3, v5}, Landroid/widget/PopupWindow;->setWidth(I)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v3, v10}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 291
    .line 292
    .line 293
    goto :goto_a

    .line 294
    :cond_11
    if-ne v8, v9, :cond_12

    .line 295
    .line 296
    move v8, v0

    .line 297
    :cond_12
    :goto_a
    invoke-virtual {v3, v2}, Landroid/widget/PopupWindow;->setOutsideTouchable(Z)V

    .line 298
    .line 299
    .line 300
    move v0, v4

    .line 301
    iget-object v4, p0, Lm/z1;->r:Landroid/view/View;

    .line 302
    .line 303
    iget v5, p0, Lm/z1;->i:I

    .line 304
    .line 305
    iget v6, p0, Lm/z1;->j:I

    .line 306
    .line 307
    if-gez v0, :cond_13

    .line 308
    .line 309
    move v7, v10

    .line 310
    goto :goto_b

    .line 311
    :cond_13
    move v7, v0

    .line 312
    :goto_b
    if-gez v8, :cond_14

    .line 313
    .line 314
    move v8, v10

    .line 315
    :cond_14
    invoke-virtual/range {v3 .. v8}, Landroid/widget/PopupWindow;->update(Landroid/view/View;IIII)V

    .line 316
    .line 317
    .line 318
    return-void

    .line 319
    :cond_15
    iget v1, p0, Lm/z1;->h:I

    .line 320
    .line 321
    if-ne v1, v10, :cond_16

    .line 322
    .line 323
    move v1, v10

    .line 324
    goto :goto_c

    .line 325
    :cond_16
    if-ne v1, v9, :cond_17

    .line 326
    .line 327
    iget-object v1, p0, Lm/z1;->r:Landroid/view/View;

    .line 328
    .line 329
    invoke-virtual {v1}, Landroid/view/View;->getWidth()I

    .line 330
    .line 331
    .line 332
    move-result v1

    .line 333
    :cond_17
    :goto_c
    if-ne v8, v10, :cond_18

    .line 334
    .line 335
    move v8, v10

    .line 336
    goto :goto_d

    .line 337
    :cond_18
    if-ne v8, v9, :cond_19

    .line 338
    .line 339
    move v8, v0

    .line 340
    :cond_19
    :goto_d
    invoke-virtual {v3, v1}, Landroid/widget/PopupWindow;->setWidth(I)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v3, v8}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 344
    .line 345
    .line 346
    invoke-static {v3, v2}, Lm/u1;->b(Landroid/widget/PopupWindow;Z)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v3, v2}, Landroid/widget/PopupWindow;->setOutsideTouchable(Z)V

    .line 350
    .line 351
    .line 352
    iget-object v0, p0, Lm/z1;->v:Lm/y1;

    .line 353
    .line 354
    invoke-virtual {v3, v0}, Landroid/widget/PopupWindow;->setTouchInterceptor(Landroid/view/View$OnTouchListener;)V

    .line 355
    .line 356
    .line 357
    iget-boolean v0, p0, Lm/z1;->n:Z

    .line 358
    .line 359
    if-eqz v0, :cond_1a

    .line 360
    .line 361
    iget-boolean v0, p0, Lm/z1;->m:Z

    .line 362
    .line 363
    invoke-virtual {v3, v0}, Landroid/widget/PopupWindow;->setOverlapAnchor(Z)V

    .line 364
    .line 365
    .line 366
    :cond_1a
    iget-object v0, p0, Lm/z1;->A:Landroid/graphics/Rect;

    .line 367
    .line 368
    invoke-static {v3, v0}, Lm/u1;->a(Landroid/widget/PopupWindow;Landroid/graphics/Rect;)V

    .line 369
    .line 370
    .line 371
    iget-object v0, p0, Lm/z1;->r:Landroid/view/View;

    .line 372
    .line 373
    iget v1, p0, Lm/z1;->i:I

    .line 374
    .line 375
    iget v4, p0, Lm/z1;->j:I

    .line 376
    .line 377
    iget v5, p0, Lm/z1;->o:I

    .line 378
    .line 379
    invoke-virtual {v3, v0, v1, v4, v5}, Landroid/widget/PopupWindow;->showAsDropDown(Landroid/view/View;III)V

    .line 380
    .line 381
    .line 382
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 383
    .line 384
    invoke-virtual {v0, v10}, Landroid/widget/AdapterView;->setSelection(I)V

    .line 385
    .line 386
    .line 387
    iget-boolean v0, p0, Lm/z1;->B:Z

    .line 388
    .line 389
    if-eqz v0, :cond_1b

    .line 390
    .line 391
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 392
    .line 393
    invoke-virtual {v0}, Lm/m1;->isInTouchMode()Z

    .line 394
    .line 395
    .line 396
    move-result v0

    .line 397
    if-eqz v0, :cond_1c

    .line 398
    .line 399
    :cond_1b
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 400
    .line 401
    if-eqz v0, :cond_1c

    .line 402
    .line 403
    invoke-virtual {v0, v2}, Lm/m1;->setListSelectionHidden(Z)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    .line 407
    .line 408
    .line 409
    :cond_1c
    iget-boolean v0, p0, Lm/z1;->B:Z

    .line 410
    .line 411
    if-nez v0, :cond_1d

    .line 412
    .line 413
    iget-object v0, p0, Lm/z1;->y:Landroid/os/Handler;

    .line 414
    .line 415
    iget-object p0, p0, Lm/z1;->x:Lm/v1;

    .line 416
    .line 417
    invoke-virtual {v0, p0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 418
    .line 419
    .line 420
    :cond_1d
    :goto_e
    return-void
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lm/z1;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final d(I)V
    .locals 0

    .line 1
    iput p1, p0, Lm/z1;->i:I

    .line 2
    .line 3
    return-void
.end method

.method public final dismiss()V
    .locals 2

    .line 1
    iget-object v0, p0, Lm/z1;->C:Lm/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    .line 8
    .line 9
    .line 10
    iput-object v1, p0, Lm/z1;->f:Lm/m1;

    .line 11
    .line 12
    iget-object v0, p0, Lm/z1;->y:Landroid/os/Handler;

    .line 13
    .line 14
    iget-object p0, p0, Lm/z1;->u:Lm/v1;

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final f()Landroid/graphics/drawable/Drawable;
    .locals 0

    .line 1
    iget-object p0, p0, Lm/z1;->C:Lm/z;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final h(I)V
    .locals 0

    .line 1
    iput p1, p0, Lm/z1;->j:I

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Lm/z1;->l:Z

    .line 5
    .line 6
    return-void
.end method

.method public final k()I
    .locals 1

    .line 1
    iget-boolean v0, p0, Lm/z1;->l:Z

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
    iget p0, p0, Lm/z1;->j:I

    .line 8
    .line 9
    return p0
.end method

.method public l(Landroid/widget/ListAdapter;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lm/z1;->q:Lm/w1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lm/w1;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lm/w1;-><init>(Lm/z1;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lm/z1;->q:Lm/w1;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-object v1, p0, Lm/z1;->e:Landroid/widget/ListAdapter;

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v1, v0}, Landroid/widget/Adapter;->unregisterDataSetObserver(Landroid/database/DataSetObserver;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    :goto_0
    iput-object p1, p0, Lm/z1;->e:Landroid/widget/ListAdapter;

    .line 21
    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    iget-object v0, p0, Lm/z1;->q:Lm/w1;

    .line 25
    .line 26
    invoke-interface {p1, v0}, Landroid/widget/Adapter;->registerDataSetObserver(Landroid/database/DataSetObserver;)V

    .line 27
    .line 28
    .line 29
    :cond_2
    iget-object p1, p0, Lm/z1;->f:Lm/m1;

    .line 30
    .line 31
    if-eqz p1, :cond_3

    .line 32
    .line 33
    iget-object p0, p0, Lm/z1;->e:Landroid/widget/ListAdapter;

    .line 34
    .line 35
    invoke-virtual {p1, p0}, Landroid/widget/AbsListView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 36
    .line 37
    .line 38
    :cond_3
    return-void
.end method

.method public final n()Lm/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lm/z1;->f:Lm/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final o(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm/z1;->C:Lm/z;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/widget/PopupWindow;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public p(Landroid/content/Context;Z)Lm/m1;
    .locals 0

    .line 1
    new-instance p0, Lm/m1;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lm/m1;-><init>(Landroid/content/Context;Z)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final r(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lm/z1;->C:Lm/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lm/z1;->z:Landroid/graphics/Rect;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    .line 12
    .line 13
    .line 14
    iget v0, v1, Landroid/graphics/Rect;->left:I

    .line 15
    .line 16
    iget v1, v1, Landroid/graphics/Rect;->right:I

    .line 17
    .line 18
    add-int/2addr v0, v1

    .line 19
    add-int/2addr v0, p1

    .line 20
    iput v0, p0, Lm/z1;->h:I

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iput p1, p0, Lm/z1;->h:I

    .line 24
    .line 25
    return-void
.end method
