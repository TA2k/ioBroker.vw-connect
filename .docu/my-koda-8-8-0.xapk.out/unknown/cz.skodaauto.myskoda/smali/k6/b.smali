.class public abstract Lk6/b;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Landroid/graphics/Rect;

.field public static final o:Lgv/a;

.field public static final p:Lip/v;


# instance fields
.field public final d:Landroid/graphics/Rect;

.field public final e:Landroid/graphics/Rect;

.field public final f:Landroid/graphics/Rect;

.field public final g:[I

.field public final h:Landroid/view/accessibility/AccessibilityManager;

.field public final i:Lcom/google/android/material/chip/Chip;

.field public j:Lk6/a;

.field public k:I

.field public l:I

.field public m:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/Rect;

    .line 2
    .line 3
    const v1, 0x7fffffff

    .line 4
    .line 5
    .line 6
    const/high16 v2, -0x80000000

    .line 7
    .line 8
    invoke-direct {v0, v1, v1, v2, v2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lk6/b;->n:Landroid/graphics/Rect;

    .line 12
    .line 13
    new-instance v0, Lgv/a;

    .line 14
    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lk6/b;->o:Lgv/a;

    .line 21
    .line 22
    new-instance v0, Lip/v;

    .line 23
    .line 24
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lk6/b;->p:Lip/v;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/chip/Chip;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Rect;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lk6/b;->d:Landroid/graphics/Rect;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/Rect;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lk6/b;->e:Landroid/graphics/Rect;

    .line 17
    .line 18
    new-instance v0, Landroid/graphics/Rect;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lk6/b;->f:Landroid/graphics/Rect;

    .line 24
    .line 25
    const/4 v0, 0x2

    .line 26
    new-array v0, v0, [I

    .line 27
    .line 28
    iput-object v0, p0, Lk6/b;->g:[I

    .line 29
    .line 30
    const/high16 v0, -0x80000000

    .line 31
    .line 32
    iput v0, p0, Lk6/b;->k:I

    .line 33
    .line 34
    iput v0, p0, Lk6/b;->l:I

    .line 35
    .line 36
    iput v0, p0, Lk6/b;->m:I

    .line 37
    .line 38
    iput-object p1, p0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v1, "accessibility"

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Landroid/view/accessibility/AccessibilityManager;

    .line 51
    .line 52
    iput-object v0, p0, Lk6/b;->h:Landroid/view/accessibility/AccessibilityManager;

    .line 53
    .line 54
    const/4 p0, 0x1

    .line 55
    invoke-virtual {p1, p0}, Landroid/view/View;->setFocusable(Z)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/view/View;->getImportantForAccessibility()I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_0

    .line 65
    .line 66
    invoke-virtual {p1, p0}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 67
    .line 68
    .line 69
    :cond_0
    return-void
.end method


# virtual methods
.method public final b(Landroid/view/View;)Lbu/c;
    .locals 1

    .line 1
    iget-object p1, p0, Lk6/b;->j:Lk6/a;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    new-instance p1, Lk6/a;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-direct {p1, p0, v0}, Lk6/a;-><init>(Ld6/b;I)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lk6/b;->j:Lk6/a;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lk6/b;->j:Lk6/a;

    .line 14
    .line 15
    return-object p0
.end method

.method public final d(Landroid/view/View;Le6/d;)V
    .locals 2

    .line 1
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 2
    .line 3
    iget-object v1, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 4
    .line 5
    invoke-virtual {v1, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lmq/d;

    .line 9
    .line 10
    iget-object p0, p0, Lmq/d;->q:Lcom/google/android/material/chip/Chip;

    .line 11
    .line 12
    iget-object p1, p0, Lcom/google/android/material/chip/Chip;->h:Lmq/f;

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    iget-boolean p1, p1, Lmq/f;->Z:Z

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    :goto_0
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCheckable(Z)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/view/View;->isClickable()Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setClickable(Z)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/google/android/material/chip/Chip;->getAccessibilityClassName()Ljava/lang/CharSequence;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p2, p1}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p2, p0}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public final j(I)Z
    .locals 2

    .line 1
    iget v0, p0, Lk6/b;->l:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eq v0, p1, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    const/high16 v0, -0x80000000

    .line 8
    .line 9
    iput v0, p0, Lk6/b;->l:I

    .line 10
    .line 11
    invoke-virtual {p0, p1, v1}, Lk6/b;->p(IZ)V

    .line 12
    .line 13
    .line 14
    const/16 v0, 0x8

    .line 15
    .line 16
    invoke-virtual {p0, p1, v0}, Lk6/b;->r(II)V

    .line 17
    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0
.end method

.method public final k(I)Le6/d;
    .locals 11

    .line 1
    invoke-static {}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain()Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Le6/d;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setEnabled(Z)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setFocusable(Z)V

    .line 15
    .line 16
    .line 17
    const-string v3, "android.view.View"

    .line 18
    .line 19
    invoke-virtual {v1, v3}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 20
    .line 21
    .line 22
    sget-object v3, Lk6/b;->n:Landroid/graphics/Rect;

    .line 23
    .line 24
    invoke-virtual {v0, v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->setBoundsInParent(Landroid/graphics/Rect;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->setBoundsInScreen(Landroid/graphics/Rect;)V

    .line 28
    .line 29
    .line 30
    const/4 v4, -0x1

    .line 31
    iput v4, v1, Le6/d;->b:I

    .line 32
    .line 33
    iget-object v5, p0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 34
    .line 35
    invoke-virtual {v0, v5}, Landroid/view/accessibility/AccessibilityNodeInfo;->setParent(Landroid/view/View;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1, v1}, Lk6/b;->o(ILe6/d;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1}, Le6/d;->g()Ljava/lang/CharSequence;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    if-nez v6, :cond_1

    .line 46
    .line 47
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getContentDescription()Ljava/lang/CharSequence;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    if-eqz v6, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 55
    .line 56
    const-string p1, "Callbacks must add text or a content description in populateNodeForVirtualViewId()"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_1
    :goto_0
    iget-object v6, p0, Lk6/b;->e:Landroid/graphics/Rect;

    .line 63
    .line 64
    invoke-virtual {v1, v6}, Le6/d;->f(Landroid/graphics/Rect;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v6, v3}, Landroid/graphics/Rect;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v7

    .line 71
    if-nez v7, :cond_f

    .line 72
    .line 73
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getActions()I

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    and-int/lit8 v8, v7, 0x40

    .line 78
    .line 79
    if-nez v8, :cond_e

    .line 80
    .line 81
    const/16 v8, 0x80

    .line 82
    .line 83
    and-int/2addr v7, v8

    .line 84
    if-nez v7, :cond_d

    .line 85
    .line 86
    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    invoke-virtual {v0, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setPackageName(Ljava/lang/CharSequence;)V

    .line 95
    .line 96
    .line 97
    iput p1, v1, Le6/d;->c:I

    .line 98
    .line 99
    invoke-virtual {v0, v5, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setSource(Landroid/view/View;I)V

    .line 100
    .line 101
    .line 102
    iget v7, p0, Lk6/b;->k:I

    .line 103
    .line 104
    const/4 v9, 0x0

    .line 105
    if-ne v7, p1, :cond_2

    .line 106
    .line 107
    invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setAccessibilityFocused(Z)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v8}, Le6/d;->a(I)V

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_2
    invoke-virtual {v0, v9}, Landroid/view/accessibility/AccessibilityNodeInfo;->setAccessibilityFocused(Z)V

    .line 115
    .line 116
    .line 117
    const/16 v7, 0x40

    .line 118
    .line 119
    invoke-virtual {v1, v7}, Le6/d;->a(I)V

    .line 120
    .line 121
    .line 122
    :goto_1
    iget v7, p0, Lk6/b;->l:I

    .line 123
    .line 124
    if-ne v7, p1, :cond_3

    .line 125
    .line 126
    move p1, v2

    .line 127
    goto :goto_2

    .line 128
    :cond_3
    move p1, v9

    .line 129
    :goto_2
    if-eqz p1, :cond_4

    .line 130
    .line 131
    const/4 v7, 0x2

    .line 132
    invoke-virtual {v1, v7}, Le6/d;->a(I)V

    .line 133
    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_4
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->isFocusable()Z

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    if-eqz v7, :cond_5

    .line 141
    .line 142
    invoke-virtual {v1, v2}, Le6/d;->a(I)V

    .line 143
    .line 144
    .line 145
    :cond_5
    :goto_3
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setFocused(Z)V

    .line 146
    .line 147
    .line 148
    iget-object p1, p0, Lk6/b;->g:[I

    .line 149
    .line 150
    invoke-virtual {v5, p1}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 151
    .line 152
    .line 153
    iget-object v7, p0, Lk6/b;->d:Landroid/graphics/Rect;

    .line 154
    .line 155
    invoke-virtual {v0, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->getBoundsInScreen(Landroid/graphics/Rect;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v7, v3}, Landroid/graphics/Rect;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    if-eqz v0, :cond_7

    .line 163
    .line 164
    invoke-virtual {v1, v7}, Le6/d;->f(Landroid/graphics/Rect;)V

    .line 165
    .line 166
    .line 167
    iget v0, v1, Le6/d;->b:I

    .line 168
    .line 169
    if-eq v0, v4, :cond_6

    .line 170
    .line 171
    invoke-static {}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain()Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    new-instance v8, Le6/d;

    .line 176
    .line 177
    invoke-direct {v8, v0}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 178
    .line 179
    .line 180
    iget v0, v1, Le6/d;->b:I

    .line 181
    .line 182
    :goto_4
    if-eq v0, v4, :cond_6

    .line 183
    .line 184
    iput v4, v8, Le6/d;->b:I

    .line 185
    .line 186
    iget-object v10, v8, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 187
    .line 188
    invoke-virtual {v10, v5, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setParent(Landroid/view/View;I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v10, v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->setBoundsInParent(Landroid/graphics/Rect;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p0, v0, v8}, Lk6/b;->o(ILe6/d;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v8, v6}, Le6/d;->f(Landroid/graphics/Rect;)V

    .line 198
    .line 199
    .line 200
    iget v0, v6, Landroid/graphics/Rect;->left:I

    .line 201
    .line 202
    iget v10, v6, Landroid/graphics/Rect;->top:I

    .line 203
    .line 204
    invoke-virtual {v7, v0, v10}, Landroid/graphics/Rect;->offset(II)V

    .line 205
    .line 206
    .line 207
    iget v0, v8, Le6/d;->b:I

    .line 208
    .line 209
    goto :goto_4

    .line 210
    :cond_6
    aget v0, p1, v9

    .line 211
    .line 212
    invoke-virtual {v5}, Landroid/view/View;->getScrollX()I

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    sub-int/2addr v0, v3

    .line 217
    aget v3, p1, v2

    .line 218
    .line 219
    invoke-virtual {v5}, Landroid/view/View;->getScrollY()I

    .line 220
    .line 221
    .line 222
    move-result v4

    .line 223
    sub-int/2addr v3, v4

    .line 224
    invoke-virtual {v7, v0, v3}, Landroid/graphics/Rect;->offset(II)V

    .line 225
    .line 226
    .line 227
    :cond_7
    iget-object p0, p0, Lk6/b;->f:Landroid/graphics/Rect;

    .line 228
    .line 229
    invoke-virtual {v5, p0}, Landroid/view/View;->getLocalVisibleRect(Landroid/graphics/Rect;)Z

    .line 230
    .line 231
    .line 232
    move-result v0

    .line 233
    if-eqz v0, :cond_c

    .line 234
    .line 235
    aget v0, p1, v9

    .line 236
    .line 237
    invoke-virtual {v5}, Landroid/view/View;->getScrollX()I

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    sub-int/2addr v0, v3

    .line 242
    aget p1, p1, v2

    .line 243
    .line 244
    invoke-virtual {v5}, Landroid/view/View;->getScrollY()I

    .line 245
    .line 246
    .line 247
    move-result v3

    .line 248
    sub-int/2addr p1, v3

    .line 249
    invoke-virtual {p0, v0, p1}, Landroid/graphics/Rect;->offset(II)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v7, p0}, Landroid/graphics/Rect;->intersect(Landroid/graphics/Rect;)Z

    .line 253
    .line 254
    .line 255
    move-result p0

    .line 256
    if-eqz p0, :cond_c

    .line 257
    .line 258
    iget-object p0, v1, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 259
    .line 260
    invoke-virtual {p0, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setBoundsInScreen(Landroid/graphics/Rect;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v7}, Landroid/graphics/Rect;->isEmpty()Z

    .line 264
    .line 265
    .line 266
    move-result p1

    .line 267
    if-eqz p1, :cond_8

    .line 268
    .line 269
    goto :goto_6

    .line 270
    :cond_8
    invoke-virtual {v5}, Landroid/view/View;->getWindowVisibility()I

    .line 271
    .line 272
    .line 273
    move-result p1

    .line 274
    if-eqz p1, :cond_9

    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_9
    invoke-virtual {v5}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 278
    .line 279
    .line 280
    move-result-object p1

    .line 281
    :goto_5
    instance-of v0, p1, Landroid/view/View;

    .line 282
    .line 283
    if-eqz v0, :cond_b

    .line 284
    .line 285
    check-cast p1, Landroid/view/View;

    .line 286
    .line 287
    invoke-virtual {p1}, Landroid/view/View;->getAlpha()F

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    const/4 v3, 0x0

    .line 292
    cmpg-float v0, v0, v3

    .line 293
    .line 294
    if-lez v0, :cond_c

    .line 295
    .line 296
    invoke-virtual {p1}, Landroid/view/View;->getVisibility()I

    .line 297
    .line 298
    .line 299
    move-result v0

    .line 300
    if-eqz v0, :cond_a

    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_a
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 304
    .line 305
    .line 306
    move-result-object p1

    .line 307
    goto :goto_5

    .line 308
    :cond_b
    if-eqz p1, :cond_c

    .line 309
    .line 310
    invoke-virtual {p0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setVisibleToUser(Z)V

    .line 311
    .line 312
    .line 313
    :cond_c
    :goto_6
    return-object v1

    .line 314
    :cond_d
    new-instance p0, Ljava/lang/RuntimeException;

    .line 315
    .line 316
    const-string p1, "Callbacks must not add ACTION_CLEAR_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()"

    .line 317
    .line 318
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw p0

    .line 322
    :cond_e
    new-instance p0, Ljava/lang/RuntimeException;

    .line 323
    .line 324
    const-string p1, "Callbacks must not add ACTION_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()"

    .line 325
    .line 326
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    throw p0

    .line 330
    :cond_f
    new-instance p0, Ljava/lang/RuntimeException;

    .line 331
    .line 332
    const-string p1, "Callbacks must set parent bounds in populateNodeForVirtualViewId()"

    .line 333
    .line 334
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    throw p0
.end method

.method public abstract l(Ljava/util/ArrayList;)V
.end method

.method public final m(ILandroid/graphics/Rect;)Z
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    new-instance v3, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v3}, Lk6/b;->l(Ljava/util/ArrayList;)V

    .line 13
    .line 14
    .line 15
    new-instance v4, Landroidx/collection/b1;

    .line 16
    .line 17
    const/4 v5, 0x0

    .line 18
    invoke-direct {v4, v5}, Landroidx/collection/b1;-><init>(I)V

    .line 19
    .line 20
    .line 21
    move v6, v5

    .line 22
    :goto_0
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 23
    .line 24
    .line 25
    move-result v7

    .line 26
    if-ge v6, v7, :cond_0

    .line 27
    .line 28
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    check-cast v7, Ljava/lang/Integer;

    .line 33
    .line 34
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    invoke-virtual {v0, v7}, Lk6/b;->k(I)Le6/d;

    .line 39
    .line 40
    .line 41
    move-result-object v7

    .line 42
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v8

    .line 46
    check-cast v8, Ljava/lang/Integer;

    .line 47
    .line 48
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    invoke-virtual {v4, v8, v7}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    add-int/lit8 v6, v6, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    iget v3, v0, Lk6/b;->l:I

    .line 59
    .line 60
    const/high16 v7, -0x80000000

    .line 61
    .line 62
    if-ne v3, v7, :cond_1

    .line 63
    .line 64
    const/4 v3, 0x0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    invoke-virtual {v4, v3}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    check-cast v3, Le6/d;

    .line 71
    .line 72
    :goto_1
    sget-object v8, Lk6/b;->o:Lgv/a;

    .line 73
    .line 74
    sget-object v9, Lk6/b;->p:Lip/v;

    .line 75
    .line 76
    iget-object v10, v0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 77
    .line 78
    const/4 v11, 0x2

    .line 79
    const/4 v13, 0x1

    .line 80
    if-eq v1, v13, :cond_15

    .line 81
    .line 82
    if-eq v1, v11, :cond_15

    .line 83
    .line 84
    const/16 v11, 0x82

    .line 85
    .line 86
    const/16 v14, 0x42

    .line 87
    .line 88
    const/16 v15, 0x21

    .line 89
    .line 90
    const/16 v6, 0x11

    .line 91
    .line 92
    if-eq v1, v6, :cond_2

    .line 93
    .line 94
    if-eq v1, v15, :cond_2

    .line 95
    .line 96
    if-eq v1, v14, :cond_2

    .line 97
    .line 98
    if-ne v1, v11, :cond_3

    .line 99
    .line 100
    :cond_2
    move/from16 v17, v13

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 104
    .line 105
    const-string v1, "direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD, FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 106
    .line 107
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw v0

    .line 111
    :goto_2
    new-instance v13, Landroid/graphics/Rect;

    .line 112
    .line 113
    invoke-direct {v13}, Landroid/graphics/Rect;-><init>()V

    .line 114
    .line 115
    .line 116
    iget v5, v0, Lk6/b;->l:I

    .line 117
    .line 118
    const-string v12, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 119
    .line 120
    if-eq v5, v7, :cond_4

    .line 121
    .line 122
    invoke-virtual {v0, v5}, Lk6/b;->n(I)Le6/d;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-virtual {v2, v13}, Le6/d;->f(Landroid/graphics/Rect;)V

    .line 127
    .line 128
    .line 129
    :goto_3
    const/4 v10, -0x1

    .line 130
    goto :goto_4

    .line 131
    :cond_4
    if-eqz v2, :cond_5

    .line 132
    .line 133
    invoke-virtual {v13, v2}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 134
    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_5
    invoke-virtual {v10}, Landroid/view/View;->getWidth()I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    invoke-virtual {v10}, Landroid/view/View;->getHeight()I

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-eq v1, v6, :cond_9

    .line 146
    .line 147
    if-eq v1, v15, :cond_8

    .line 148
    .line 149
    if-eq v1, v14, :cond_7

    .line 150
    .line 151
    if-ne v1, v11, :cond_6

    .line 152
    .line 153
    const/4 v5, 0x0

    .line 154
    const/4 v10, -0x1

    .line 155
    invoke-virtual {v13, v5, v10, v2, v10}, Landroid/graphics/Rect;->set(IIII)V

    .line 156
    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 160
    .line 161
    invoke-direct {v0, v12}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw v0

    .line 165
    :cond_7
    const/4 v2, 0x0

    .line 166
    const/4 v10, -0x1

    .line 167
    invoke-virtual {v13, v10, v2, v10, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_8
    const/4 v7, 0x0

    .line 172
    const/4 v10, -0x1

    .line 173
    invoke-virtual {v13, v7, v5, v2, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 174
    .line 175
    .line 176
    goto :goto_4

    .line 177
    :cond_9
    const/4 v7, 0x0

    .line 178
    const/4 v10, -0x1

    .line 179
    invoke-virtual {v13, v2, v7, v2, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 180
    .line 181
    .line 182
    :goto_4
    new-instance v2, Landroid/graphics/Rect;

    .line 183
    .line 184
    invoke-direct {v2, v13}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 185
    .line 186
    .line 187
    if-eq v1, v6, :cond_d

    .line 188
    .line 189
    if-eq v1, v15, :cond_c

    .line 190
    .line 191
    if-eq v1, v14, :cond_b

    .line 192
    .line 193
    if-ne v1, v11, :cond_a

    .line 194
    .line 195
    invoke-virtual {v13}, Landroid/graphics/Rect;->height()I

    .line 196
    .line 197
    .line 198
    move-result v5

    .line 199
    add-int/lit8 v5, v5, 0x1

    .line 200
    .line 201
    neg-int v5, v5

    .line 202
    const/4 v7, 0x0

    .line 203
    invoke-virtual {v2, v7, v5}, Landroid/graphics/Rect;->offset(II)V

    .line 204
    .line 205
    .line 206
    goto :goto_5

    .line 207
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 208
    .line 209
    invoke-direct {v0, v12}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    throw v0

    .line 213
    :cond_b
    const/4 v7, 0x0

    .line 214
    invoke-virtual {v13}, Landroid/graphics/Rect;->width()I

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    add-int/lit8 v5, v5, 0x1

    .line 219
    .line 220
    neg-int v5, v5

    .line 221
    invoke-virtual {v2, v5, v7}, Landroid/graphics/Rect;->offset(II)V

    .line 222
    .line 223
    .line 224
    goto :goto_5

    .line 225
    :cond_c
    const/4 v7, 0x0

    .line 226
    invoke-virtual {v13}, Landroid/graphics/Rect;->height()I

    .line 227
    .line 228
    .line 229
    move-result v5

    .line 230
    add-int/lit8 v5, v5, 0x1

    .line 231
    .line 232
    invoke-virtual {v2, v7, v5}, Landroid/graphics/Rect;->offset(II)V

    .line 233
    .line 234
    .line 235
    goto :goto_5

    .line 236
    :cond_d
    const/4 v7, 0x0

    .line 237
    invoke-virtual {v13}, Landroid/graphics/Rect;->width()I

    .line 238
    .line 239
    .line 240
    move-result v5

    .line 241
    add-int/lit8 v5, v5, 0x1

    .line 242
    .line 243
    invoke-virtual {v2, v5, v7}, Landroid/graphics/Rect;->offset(II)V

    .line 244
    .line 245
    .line 246
    :goto_5
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 247
    .line 248
    .line 249
    invoke-virtual {v4}, Landroidx/collection/b1;->f()I

    .line 250
    .line 251
    .line 252
    move-result v5

    .line 253
    new-instance v6, Landroid/graphics/Rect;

    .line 254
    .line 255
    invoke-direct {v6}, Landroid/graphics/Rect;-><init>()V

    .line 256
    .line 257
    .line 258
    move v9, v7

    .line 259
    const/16 v16, 0x0

    .line 260
    .line 261
    :goto_6
    if-ge v9, v5, :cond_14

    .line 262
    .line 263
    invoke-virtual {v4, v9}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v11

    .line 267
    check-cast v11, Le6/d;

    .line 268
    .line 269
    if-ne v11, v3, :cond_e

    .line 270
    .line 271
    goto :goto_8

    .line 272
    :cond_e
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v11, v6}, Le6/d;->f(Landroid/graphics/Rect;)V

    .line 276
    .line 277
    .line 278
    invoke-static {v1, v13, v6}, Llp/bd;->g(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 279
    .line 280
    .line 281
    move-result v12

    .line 282
    if-nez v12, :cond_f

    .line 283
    .line 284
    goto :goto_8

    .line 285
    :cond_f
    invoke-static {v1, v13, v2}, Llp/bd;->g(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 286
    .line 287
    .line 288
    move-result v12

    .line 289
    if-nez v12, :cond_10

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_10
    invoke-static {v1, v13, v6, v2}, Llp/bd;->b(ILandroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 293
    .line 294
    .line 295
    move-result v12

    .line 296
    if-eqz v12, :cond_11

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_11
    invoke-static {v1, v13, v2, v6}, Llp/bd;->b(ILandroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 300
    .line 301
    .line 302
    move-result v12

    .line 303
    if-eqz v12, :cond_12

    .line 304
    .line 305
    goto :goto_8

    .line 306
    :cond_12
    invoke-static {v1, v13, v6}, Llp/bd;->h(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    .line 307
    .line 308
    .line 309
    move-result v12

    .line 310
    invoke-static {v1, v13, v6}, Llp/bd;->i(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    .line 311
    .line 312
    .line 313
    move-result v14

    .line 314
    mul-int/lit8 v15, v12, 0xd

    .line 315
    .line 316
    mul-int/2addr v15, v12

    .line 317
    mul-int/2addr v14, v14

    .line 318
    add-int/2addr v14, v15

    .line 319
    invoke-static {v1, v13, v2}, Llp/bd;->h(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    .line 320
    .line 321
    .line 322
    move-result v12

    .line 323
    invoke-static {v1, v13, v2}, Llp/bd;->i(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    .line 324
    .line 325
    .line 326
    move-result v15

    .line 327
    mul-int/lit8 v17, v12, 0xd

    .line 328
    .line 329
    mul-int v17, v17, v12

    .line 330
    .line 331
    mul-int/2addr v15, v15

    .line 332
    add-int v15, v15, v17

    .line 333
    .line 334
    if-ge v14, v15, :cond_13

    .line 335
    .line 336
    :goto_7
    invoke-virtual {v2, v6}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 337
    .line 338
    .line 339
    move-object/from16 v16, v11

    .line 340
    .line 341
    :cond_13
    :goto_8
    add-int/lit8 v9, v9, 0x1

    .line 342
    .line 343
    goto :goto_6

    .line 344
    :cond_14
    move v2, v10

    .line 345
    :goto_9
    move-object/from16 v1, v16

    .line 346
    .line 347
    goto/16 :goto_10

    .line 348
    .line 349
    :cond_15
    move v7, v5

    .line 350
    move/from16 v17, v13

    .line 351
    .line 352
    const/4 v2, -0x1

    .line 353
    sget-object v5, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 354
    .line 355
    invoke-virtual {v10}, Landroid/view/View;->getLayoutDirection()I

    .line 356
    .line 357
    .line 358
    move-result v5

    .line 359
    move/from16 v6, v17

    .line 360
    .line 361
    if-ne v5, v6, :cond_16

    .line 362
    .line 363
    const/4 v5, 0x1

    .line 364
    goto :goto_a

    .line 365
    :cond_16
    move v5, v7

    .line 366
    :goto_a
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 367
    .line 368
    .line 369
    invoke-virtual {v4}, Landroidx/collection/b1;->f()I

    .line 370
    .line 371
    .line 372
    move-result v6

    .line 373
    new-instance v9, Ljava/util/ArrayList;

    .line 374
    .line 375
    invoke-direct {v9, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 376
    .line 377
    .line 378
    move v10, v7

    .line 379
    :goto_b
    if-ge v10, v6, :cond_17

    .line 380
    .line 381
    invoke-virtual {v4, v10}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v12

    .line 385
    check-cast v12, Le6/d;

    .line 386
    .line 387
    invoke-virtual {v9, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 388
    .line 389
    .line 390
    add-int/lit8 v10, v10, 0x1

    .line 391
    .line 392
    goto :goto_b

    .line 393
    :cond_17
    new-instance v6, Lk6/c;

    .line 394
    .line 395
    invoke-direct {v6, v5, v8}, Lk6/c;-><init>(ZLgv/a;)V

    .line 396
    .line 397
    .line 398
    invoke-static {v9, v6}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 399
    .line 400
    .line 401
    const/4 v6, 0x1

    .line 402
    if-eq v1, v6, :cond_1b

    .line 403
    .line 404
    if-ne v1, v11, :cond_1a

    .line 405
    .line 406
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 407
    .line 408
    .line 409
    move-result v1

    .line 410
    if-nez v3, :cond_18

    .line 411
    .line 412
    move v10, v2

    .line 413
    goto :goto_c

    .line 414
    :cond_18
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->lastIndexOf(Ljava/lang/Object;)I

    .line 415
    .line 416
    .line 417
    move-result v10

    .line 418
    :goto_c
    add-int/2addr v10, v6

    .line 419
    if-ge v10, v1, :cond_19

    .line 420
    .line 421
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v6

    .line 425
    goto :goto_f

    .line 426
    :cond_19
    const/4 v6, 0x0

    .line 427
    goto :goto_f

    .line 428
    :cond_1a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 429
    .line 430
    const-string v1, "direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD}."

    .line 431
    .line 432
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    throw v0

    .line 436
    :cond_1b
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 437
    .line 438
    .line 439
    move-result v1

    .line 440
    if-nez v3, :cond_1c

    .line 441
    .line 442
    :goto_d
    const/16 v17, 0x1

    .line 443
    .line 444
    goto :goto_e

    .line 445
    :cond_1c
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 446
    .line 447
    .line 448
    move-result v1

    .line 449
    goto :goto_d

    .line 450
    :goto_e
    add-int/lit8 v1, v1, -0x1

    .line 451
    .line 452
    if-ltz v1, :cond_19

    .line 453
    .line 454
    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v6

    .line 458
    :goto_f
    move-object/from16 v16, v6

    .line 459
    .line 460
    check-cast v16, Le6/d;

    .line 461
    .line 462
    goto :goto_9

    .line 463
    :goto_10
    if-nez v1, :cond_1d

    .line 464
    .line 465
    const/high16 v7, -0x80000000

    .line 466
    .line 467
    goto :goto_13

    .line 468
    :cond_1d
    iget-boolean v3, v4, Landroidx/collection/b1;->d:Z

    .line 469
    .line 470
    if-eqz v3, :cond_1e

    .line 471
    .line 472
    invoke-static {v4}, Landroidx/collection/v;->a(Landroidx/collection/b1;)V

    .line 473
    .line 474
    .line 475
    :cond_1e
    iget v3, v4, Landroidx/collection/b1;->g:I

    .line 476
    .line 477
    move v5, v7

    .line 478
    :goto_11
    if-ge v5, v3, :cond_20

    .line 479
    .line 480
    iget-object v6, v4, Landroidx/collection/b1;->f:[Ljava/lang/Object;

    .line 481
    .line 482
    aget-object v6, v6, v5

    .line 483
    .line 484
    if-ne v6, v1, :cond_1f

    .line 485
    .line 486
    move v12, v5

    .line 487
    goto :goto_12

    .line 488
    :cond_1f
    add-int/lit8 v5, v5, 0x1

    .line 489
    .line 490
    goto :goto_11

    .line 491
    :cond_20
    move v12, v2

    .line 492
    :goto_12
    invoke-virtual {v4, v12}, Landroidx/collection/b1;->d(I)I

    .line 493
    .line 494
    .line 495
    move-result v7

    .line 496
    :goto_13
    invoke-virtual {v0, v7}, Lk6/b;->q(I)Z

    .line 497
    .line 498
    .line 499
    move-result v0

    .line 500
    return v0
.end method

.method public final n(I)Le6/d;
    .locals 5

    .line 1
    const/4 v0, -0x1

    .line 2
    if-ne p1, v0, :cond_3

    .line 3
    .line 4
    iget-object p1, p0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 5
    .line 6
    invoke-static {p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain(Landroid/view/View;)Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Le6/d;

    .line 11
    .line 12
    invoke-direct {v1, v0}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 13
    .line 14
    .line 15
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 16
    .line 17
    invoke-virtual {p1, v0}, Lcom/google/android/material/chip/Chip;->onInitializeAccessibilityNodeInfo(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 18
    .line 19
    .line 20
    new-instance v2, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v2}, Lk6/b;->l(Ljava/util/ArrayList;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getChildCount()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-lez p0, :cond_1

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-gtz p0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 42
    .line 43
    const-string p1, "Views cannot have both real and virtual children"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    :goto_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    const/4 v0, 0x0

    .line 54
    :goto_1
    if-ge v0, p0, :cond_2

    .line 55
    .line 56
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    iget-object v4, v1, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 67
    .line 68
    invoke-virtual {v4, p1, v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->addChild(Landroid/view/View;I)V

    .line 69
    .line 70
    .line 71
    add-int/lit8 v0, v0, 0x1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_2
    return-object v1

    .line 75
    :cond_3
    invoke-virtual {p0, p1}, Lk6/b;->k(I)Le6/d;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0
.end method

.method public abstract o(ILe6/d;)V
.end method

.method public abstract p(IZ)V
.end method

.method public final q(I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->isFocused()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/View;->requestFocus()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget v0, p0, Lk6/b;->l:I

    .line 17
    .line 18
    if-ne v0, p1, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    const/high16 v1, -0x80000000

    .line 22
    .line 23
    if-eq v0, v1, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lk6/b;->j(I)Z

    .line 26
    .line 27
    .line 28
    :cond_2
    if-ne p1, v1, :cond_3

    .line 29
    .line 30
    :goto_0
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_3
    iput p1, p0, Lk6/b;->l:I

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    invoke-virtual {p0, p1, v0}, Lk6/b;->p(IZ)V

    .line 36
    .line 37
    .line 38
    const/16 v1, 0x8

    .line 39
    .line 40
    invoke-virtual {p0, p1, v1}, Lk6/b;->r(II)V

    .line 41
    .line 42
    .line 43
    return v0
.end method

.method public final r(II)V
    .locals 4

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    if-eq p1, v0, :cond_5

    .line 4
    .line 5
    iget-object v0, p0, Lk6/b;->h:Landroid/view/accessibility/AccessibilityManager;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto/16 :goto_2

    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    goto :goto_2

    .line 24
    :cond_1
    const/4 v2, -0x1

    .line 25
    if-eq p1, v2, :cond_4

    .line 26
    .line 27
    invoke-static {p2}, Landroid/view/accessibility/AccessibilityEvent;->obtain(I)Landroid/view/accessibility/AccessibilityEvent;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-virtual {p0, p1}, Lk6/b;->n(I)Le6/d;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p2}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {p0}, Le6/d;->g()Ljava/lang/CharSequence;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 47
    .line 48
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getContentDescription()Ljava/lang/CharSequence;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p2, v2}, Landroid/view/accessibility/AccessibilityRecord;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->isScrollable()Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    invoke-virtual {p2, v2}, Landroid/view/accessibility/AccessibilityRecord;->setScrollable(Z)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->isPassword()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    invoke-virtual {p2, v2}, Landroid/view/accessibility/AccessibilityRecord;->setPassword(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->isEnabled()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-virtual {p2, v2}, Landroid/view/accessibility/AccessibilityRecord;->setEnabled(Z)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->isChecked()Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    invoke-virtual {p2, v2}, Landroid/view/accessibility/AccessibilityRecord;->setChecked(Z)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2}, Landroid/view/accessibility/AccessibilityRecord;->getText()Ljava/util/List;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    if-eqz v2, :cond_3

    .line 92
    .line 93
    invoke-virtual {p2}, Landroid/view/accessibility/AccessibilityRecord;->getContentDescription()Ljava/lang/CharSequence;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    if-eqz v2, :cond_2

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_2
    new-instance p0, Ljava/lang/RuntimeException;

    .line 101
    .line 102
    const-string p1, "Callbacks must add text or a content description in populateEventForVirtualViewId()"

    .line 103
    .line 104
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :cond_3
    :goto_0
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getClassName()Ljava/lang/CharSequence;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setClassName(Ljava/lang/CharSequence;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p2, v0, p1}, Landroid/view/accessibility/AccessibilityRecord;->setSource(Landroid/view/View;I)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityEvent;->setPackageName(Ljava/lang/CharSequence;)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_4
    invoke-static {p2}, Landroid/view/accessibility/AccessibilityEvent;->obtain(I)Landroid/view/accessibility/AccessibilityEvent;

    .line 131
    .line 132
    .line 133
    move-result-object p2

    .line 134
    invoke-virtual {v0, p2}, Landroid/view/View;->onInitializeAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V

    .line 135
    .line 136
    .line 137
    :goto_1
    invoke-interface {v1, v0, p2}, Landroid/view/ViewParent;->requestSendAccessibilityEvent(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 138
    .line 139
    .line 140
    :cond_5
    :goto_2
    return-void
.end method
