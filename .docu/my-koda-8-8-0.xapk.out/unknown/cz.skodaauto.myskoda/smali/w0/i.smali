.class public final Lw0/i;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lw0/f;

.field public e:Landroidx/core/app/a0;

.field public final f:Lw0/m;

.field public final g:Lw0/d;

.field public h:Z

.field public final i:Landroidx/lifecycle/i0;

.field public final j:Ljava/util/concurrent/atomic/AtomicReference;

.field public final k:Lw0/j;

.field public l:Lh0/z;

.field public final m:Lw0/e;

.field public final n:Lkq/a;

.field public final o:Lt1/j0;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 9

    .line 1
    const/4 v3, 0x0

    .line 2
    const/4 v5, 0x0

    .line 3
    const/4 v6, 0x0

    .line 4
    invoke-direct {p0, p1, v3, v5, v6}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 5
    .line 6
    .line 7
    sget-object v0, Lw0/f;->e:Lw0/f;

    .line 8
    .line 9
    iput-object v0, p0, Lw0/i;->d:Lw0/f;

    .line 10
    .line 11
    new-instance v7, Lw0/d;

    .line 12
    .line 13
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    sget-object v0, Lw0/g;->e:Lw0/g;

    .line 17
    .line 18
    iput-object v0, v7, Lw0/d;->h:Lw0/g;

    .line 19
    .line 20
    iput-object v7, p0, Lw0/i;->g:Lw0/d;

    .line 21
    .line 22
    const/4 v8, 0x1

    .line 23
    iput-boolean v8, p0, Lw0/i;->h:Z

    .line 24
    .line 25
    new-instance v0, Landroidx/lifecycle/i0;

    .line 26
    .line 27
    sget-object v1, Lw0/h;->d:Lw0/h;

    .line 28
    .line 29
    invoke-direct {v0, v1}, Landroidx/lifecycle/g0;-><init>(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lw0/i;->i:Landroidx/lifecycle/i0;

    .line 33
    .line 34
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lw0/i;->j:Ljava/util/concurrent/atomic/AtomicReference;

    .line 40
    .line 41
    new-instance v0, Lw0/j;

    .line 42
    .line 43
    invoke-direct {v0, v7}, Lw0/j;-><init>(Lw0/d;)V

    .line 44
    .line 45
    .line 46
    iput-object v0, p0, Lw0/i;->k:Lw0/j;

    .line 47
    .line 48
    new-instance v0, Lw0/e;

    .line 49
    .line 50
    invoke-direct {v0, p0}, Lw0/e;-><init>(Lw0/i;)V

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Lw0/i;->m:Lw0/e;

    .line 54
    .line 55
    new-instance v0, Lkq/a;

    .line 56
    .line 57
    const/4 v1, 0x2

    .line 58
    invoke-direct {v0, p0, v1}, Lkq/a;-><init>(Ljava/lang/Object;I)V

    .line 59
    .line 60
    .line 61
    iput-object v0, p0, Lw0/i;->n:Lkq/a;

    .line 62
    .line 63
    new-instance v0, Lt1/j0;

    .line 64
    .line 65
    const/16 v1, 0xe

    .line 66
    .line 67
    invoke-direct {v0, p0, v1}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p0, Lw0/i;->o:Lt1/j0;

    .line 71
    .line 72
    invoke-static {}, Llp/k1;->a()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    sget-object v2, Lw0/k;->a:[I

    .line 80
    .line 81
    invoke-virtual {v0, v3, v2, v5, v6}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 86
    .line 87
    move-object v0, p0

    .line 88
    move-object v1, p1

    .line 89
    invoke-static/range {v0 .. v6}, Ld6/o0;->b(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    .line 90
    .line 91
    .line 92
    :try_start_0
    iget-object p0, v7, Lw0/d;->h:Lw0/g;

    .line 93
    .line 94
    iget p0, p0, Lw0/g;->d:I

    .line 95
    .line 96
    invoke-virtual {v4, v8, p0}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    invoke-static {}, Lw0/g;->values()[Lw0/g;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    array-length v2, p1

    .line 105
    const/4 v3, 0x0

    .line 106
    move v5, v3

    .line 107
    :goto_0
    if-ge v5, v2, :cond_4

    .line 108
    .line 109
    aget-object v6, p1, v5

    .line 110
    .line 111
    iget v7, v6, Lw0/g;->d:I

    .line 112
    .line 113
    if-ne v7, p0, :cond_3

    .line 114
    .line 115
    invoke-virtual {v0, v6}, Lw0/i;->setScaleType(Lw0/g;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v3, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    invoke-static {}, Lw0/f;->values()[Lw0/f;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    array-length v2, p1

    .line 127
    move v5, v3

    .line 128
    :goto_1
    if-ge v5, v2, :cond_2

    .line 129
    .line 130
    aget-object v6, p1, v5

    .line 131
    .line 132
    iget v7, v6, Lw0/f;->d:I

    .line 133
    .line 134
    if-ne v7, p0, :cond_1

    .line 135
    .line 136
    invoke-virtual {v0, v6}, Lw0/i;->setImplementationMode(Lw0/f;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 137
    .line 138
    .line 139
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 140
    .line 141
    .line 142
    new-instance p0, Lwq/f;

    .line 143
    .line 144
    new-instance p1, Lt0/c;

    .line 145
    .line 146
    const/16 v2, 0x10

    .line 147
    .line 148
    invoke-direct {p1, v2}, Lt0/c;-><init>(I)V

    .line 149
    .line 150
    .line 151
    invoke-direct {p0, v1, p1}, Lwq/f;-><init>(Landroid/content/Context;Lt0/c;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0}, Landroid/view/View;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    if-nez p0, :cond_0

    .line 159
    .line 160
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    const p1, 0x106000c

    .line 165
    .line 166
    .line 167
    invoke-virtual {p0, p1}, Landroid/content/Context;->getColor(I)I

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    invoke-virtual {v0, p0}, Landroid/view/View;->setBackgroundColor(I)V

    .line 172
    .line 173
    .line 174
    :cond_0
    new-instance p0, Lw0/m;

    .line 175
    .line 176
    const/4 p1, 0x0

    .line 177
    invoke-direct {p0, v1, p1, v3, v3}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 178
    .line 179
    .line 180
    const/4 p1, -0x1

    .line 181
    invoke-virtual {p0, p1}, Landroid/view/View;->setBackgroundColor(I)V

    .line 182
    .line 183
    .line 184
    const/4 v1, 0x0

    .line 185
    invoke-virtual {p0, v1}, Landroid/view/View;->setAlpha(F)V

    .line 186
    .line 187
    .line 188
    const v1, 0x7f7fffff    # Float.MAX_VALUE

    .line 189
    .line 190
    .line 191
    invoke-virtual {p0, v1}, Landroid/view/View;->setElevation(F)V

    .line 192
    .line 193
    .line 194
    iput-object p0, v0, Lw0/i;->f:Lw0/m;

    .line 195
    .line 196
    new-instance v0, Landroid/widget/LinearLayout$LayoutParams;

    .line 197
    .line 198
    invoke-direct {v0, p1, p1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {p0, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 202
    .line 203
    .line 204
    return-void

    .line 205
    :catchall_0
    move-exception v0

    .line 206
    move-object p0, v0

    .line 207
    goto :goto_2

    .line 208
    :cond_1
    add-int/lit8 v5, v5, 0x1

    .line 209
    .line 210
    goto :goto_1

    .line 211
    :cond_2
    :try_start_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 212
    .line 213
    new-instance v0, Ljava/lang/StringBuilder;

    .line 214
    .line 215
    const-string v1, "Unknown implementation mode id "

    .line 216
    .line 217
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw p1

    .line 231
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 232
    .line 233
    goto :goto_0

    .line 234
    :cond_4
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 235
    .line 236
    new-instance v0, Ljava/lang/StringBuilder;

    .line 237
    .line 238
    const-string v1, "Unknown scale type id "

    .line 239
    .line 240
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 254
    :goto_2
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 255
    .line 256
    .line 257
    throw p0
.end method

.method public static b(Lb0/x1;Lw0/f;)Z
    .locals 4

    .line 1
    iget-object p0, p0, Lb0/x1;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->l()Lh0/z;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lh0/z;->q()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "androidx.camera.camera2.legacy"

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    const-class v0, Landroidx/camera/view/internal/compat/quirk/SurfaceViewStretchedQuirk;

    .line 18
    .line 19
    sget-object v1, Ly0/a;->a:Ld01/x;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    const/4 v1, 0x0

    .line 26
    const/4 v2, 0x1

    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    const-class v0, Landroidx/camera/view/internal/compat/quirk/SurfaceViewNotCroppedByParentQuirk;

    .line 30
    .line 31
    sget-object v3, Ly0/a;->a:Ld01/x;

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move v0, v1

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    :goto_0
    move v0, v2

    .line 43
    :goto_1
    if-nez p0, :cond_5

    .line 44
    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_4

    .line 53
    .line 54
    if-ne p0, v2, :cond_3

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 58
    .line 59
    new-instance v0, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string v1, "Invalid implementation mode: "

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    return v1

    .line 78
    :cond_5
    :goto_2
    return v2
.end method

.method private getDisplayManager()Landroid/hardware/display/DisplayManager;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    const-string v0, "display"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Landroid/hardware/display/DisplayManager;

    .line 16
    .line 17
    return-object p0
.end method

.method private getScreenFlashInternal()Lb0/s0;
    .locals 0

    .line 1
    iget-object p0, p0, Lw0/i;->f:Lw0/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Lw0/m;->getScreenFlash()Lb0/s0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private getViewPortScaleType()I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lw0/i;->getScaleType()Lw0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    if-eq v0, v1, :cond_1

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    if-eq v0, v2, :cond_1

    .line 22
    .line 23
    const/4 v2, 0x5

    .line 24
    if-ne v0, v2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    new-instance v1, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v2, "Unexpected scale type: "

    .line 32
    .line 33
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lw0/i;->getScaleType()Lw0/g;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw v0

    .line 51
    :cond_1
    :goto_0
    return v1

    .line 52
    :cond_2
    const/4 p0, 0x0

    .line 53
    return p0
.end method

.method private setScreenFlashUiInfo(Lb0/s0;)V
    .locals 0

    .line 1
    const-string p0, "PreviewView"

    .line 2
    .line 3
    const-string p1, "setScreenFlashUiInfo: mCameraController is null!"

    .line 4
    .line 5
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 5
    .line 6
    if-eqz v0, :cond_2

    .line 7
    .line 8
    iget-boolean v0, p0, Lw0/i;->h:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0}, Lw0/i;->getDefaultDisplay()Landroid/view/Display;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-object v1, p0, Lw0/i;->l:Lh0/z;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-object v2, p0, Lw0/i;->g:Lw0/d;

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/view/Display;->getRotation()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-interface {v1, v3}, Lh0/z;->r(I)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-virtual {v0}, Landroid/view/Display;->getRotation()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-boolean v3, v2, Lw0/d;->g:Z

    .line 37
    .line 38
    if-nez v3, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    iput v1, v2, Lw0/d;->c:I

    .line 42
    .line 43
    iput v0, v2, Lw0/d;->e:I

    .line 44
    .line 45
    :cond_1
    :goto_0
    iget-object v0, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 46
    .line 47
    invoke-virtual {v0}, Landroidx/core/app/a0;->h()V

    .line 48
    .line 49
    .line 50
    :cond_2
    iget-object v0, p0, Lw0/i;->k:Lw0/j;

    .line 51
    .line 52
    new-instance v1, Landroid/util/Size;

    .line 53
    .line 54
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    invoke-direct {v1, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    invoke-static {}, Llp/k1;->a()V

    .line 73
    .line 74
    .line 75
    monitor-enter v0

    .line 76
    :try_start_0
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_4

    .line 81
    .line 82
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_4

    .line 87
    .line 88
    iget-object v2, v0, Lw0/j;->b:Landroid/graphics/Rect;

    .line 89
    .line 90
    if-nez v2, :cond_3

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    iget-object v3, v0, Lw0/j;->a:Lw0/d;

    .line 94
    .line 95
    invoke-virtual {v3, v1, p0, v2}, Lw0/d;->a(Landroid/util/Size;ILandroid/graphics/Rect;)V

    .line 96
    .line 97
    .line 98
    monitor-exit v0

    .line 99
    return-void

    .line 100
    :catchall_0
    move-exception p0

    .line 101
    goto :goto_2

    .line 102
    :cond_4
    :goto_1
    monitor-exit v0

    .line 103
    return-void

    .line 104
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    throw p0
.end method

.method public getBitmap()Landroid/graphics/Bitmap;
    .locals 7

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object v0, p0, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Landroid/widget/FrameLayout;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/core/app/a0;->d()Landroid/graphics/Bitmap;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    :goto_0
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_1
    iget-object p0, p0, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lw0/d;

    .line 24
    .line 25
    new-instance v2, Landroid/util/Size;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    invoke-direct {v2, v3, v4}, Landroid/util/Size;-><init>(II)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-nez v3, :cond_2

    .line 47
    .line 48
    return-object v1

    .line 49
    :cond_2
    invoke-virtual {p0}, Lw0/d;->d()Landroid/graphics/Matrix;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-virtual {p0, v2, v0}, Lw0/d;->e(Landroid/util/Size;I)Landroid/graphics/RectF;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-static {v4, v2, v5}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    new-instance v4, Landroid/graphics/Canvas;

    .line 74
    .line 75
    invoke-direct {v4, v2}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 76
    .line 77
    .line 78
    new-instance v5, Landroid/graphics/Matrix;

    .line 79
    .line 80
    invoke-direct {v5}, Landroid/graphics/Matrix;-><init>()V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v5, v3}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    iget-object v6, p0, Lw0/d;->a:Landroid/util/Size;

    .line 91
    .line 92
    invoke-virtual {v6}, Landroid/util/Size;->getWidth()I

    .line 93
    .line 94
    .line 95
    move-result v6

    .line 96
    int-to-float v6, v6

    .line 97
    div-float/2addr v3, v6

    .line 98
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 99
    .line 100
    .line 101
    move-result v6

    .line 102
    iget-object p0, p0, Lw0/d;->a:Landroid/util/Size;

    .line 103
    .line 104
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    int-to-float p0, p0

    .line 109
    div-float/2addr v6, p0

    .line 110
    invoke-virtual {v5, v3, v6}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 111
    .line 112
    .line 113
    iget p0, v0, Landroid/graphics/RectF;->left:F

    .line 114
    .line 115
    iget v0, v0, Landroid/graphics/RectF;->top:F

    .line 116
    .line 117
    invoke-virtual {v5, p0, v0}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 118
    .line 119
    .line 120
    new-instance p0, Landroid/graphics/Paint;

    .line 121
    .line 122
    const/4 v0, 0x7

    .line 123
    invoke-direct {p0, v0}, Landroid/graphics/Paint;-><init>(I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v4, v1, v5, p0}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Matrix;Landroid/graphics/Paint;)V

    .line 127
    .line 128
    .line 129
    return-object v2
.end method

.method public getController()Lw0/a;
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return-object p0
.end method

.method public getDefaultDisplay()Landroid/view/Display;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getDisplay()Landroid/view/Display;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-direct {p0}, Lw0/i;->getDisplayManager()Landroid/hardware/display/DisplayManager;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-virtual {v0, v1}, Landroid/hardware/display/DisplayManager;->getDisplay(I)Landroid/view/Display;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getDisplay()Landroid/view/Display;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public getImplementationMode()Lw0/f;
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw0/i;->d:Lw0/f;

    .line 5
    .line 6
    return-object p0
.end method

.method public getMeteringPointFactory()Lb0/g1;
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw0/i;->k:Lw0/j;

    .line 5
    .line 6
    return-object p0
.end method

.method public getOutputTransform()Lz0/a;
    .locals 7

    .line 1
    iget-object v0, p0, Lw0/i;->g:Lw0/d;

    .line 2
    .line 3
    invoke-static {}, Llp/k1;->a()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :try_start_0
    new-instance v2, Landroid/util/Size;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-direct {v2, v3, v4}, Landroid/util/Size;-><init>(II)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    invoke-virtual {v0, v2, v3}, Lw0/d;->c(Landroid/util/Size;I)Landroid/graphics/Matrix;

    .line 25
    .line 26
    .line 27
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-object v2, v1

    .line 30
    :goto_0
    iget-object v0, v0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 31
    .line 32
    const-string v3, "PreviewView"

    .line 33
    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_0
    sget-object v1, Li0/f;->a:Landroid/graphics/RectF;

    .line 40
    .line 41
    new-instance v1, Landroid/graphics/RectF;

    .line 42
    .line 43
    invoke-direct {v1, v0}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 44
    .line 45
    .line 46
    new-instance v4, Landroid/graphics/Matrix;

    .line 47
    .line 48
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 49
    .line 50
    .line 51
    sget-object v5, Li0/f;->a:Landroid/graphics/RectF;

    .line 52
    .line 53
    sget-object v6, Landroid/graphics/Matrix$ScaleToFit;->FILL:Landroid/graphics/Matrix$ScaleToFit;

    .line 54
    .line 55
    invoke-virtual {v4, v5, v1, v6}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2, v4}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 62
    .line 63
    instance-of v1, v1, Lw0/r;

    .line 64
    .line 65
    if-eqz v1, :cond_1

    .line 66
    .line 67
    invoke-virtual {p0}, Landroid/view/View;->getMatrix()Landroid/graphics/Matrix;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v2, p0}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getMatrix()Landroid/graphics/Matrix;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p0}, Landroid/graphics/Matrix;->isIdentity()Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-nez p0, :cond_2

    .line 84
    .line 85
    const-string p0, "PreviewView needs to be in COMPATIBLE mode for the transform to work correctly."

    .line 86
    .line 87
    invoke-static {v3, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    :cond_2
    :goto_1
    new-instance p0, Lz0/a;

    .line 91
    .line 92
    new-instance v1, Landroid/util/Size;

    .line 93
    .line 94
    invoke-virtual {v0}, Landroid/graphics/Rect;->width()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    invoke-direct {v1, v2, v0}, Landroid/util/Size;-><init>(II)V

    .line 103
    .line 104
    .line 105
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    return-object p0

    .line 109
    :cond_3
    :goto_2
    const-string p0, "Transform info is not ready"

    .line 110
    .line 111
    invoke-static {v3, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    return-object v1
.end method

.method public getPreviewStreamState()Landroidx/lifecycle/g0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/lifecycle/g0;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw0/i;->i:Landroidx/lifecycle/i0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScaleType()Lw0/g;
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw0/i;->g:Lw0/d;

    .line 5
    .line 6
    iget-object p0, p0, Lw0/d;->h:Lw0/g;

    .line 7
    .line 8
    return-object p0
.end method

.method public getScreenFlash()Lb0/s0;
    .locals 0

    .line 1
    invoke-direct {p0}, Lw0/i;->getScreenFlashInternal()Lb0/s0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getSensorToViewTransform()Landroid/graphics/Matrix;
    .locals 4

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance v0, Landroid/util/Size;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-direct {v0, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    iget-object p0, p0, Lw0/i;->g:Lw0/d;

    .line 36
    .line 37
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-nez v3, :cond_1

    .line 42
    .line 43
    return-object v1

    .line 44
    :cond_1
    new-instance v1, Landroid/graphics/Matrix;

    .line 45
    .line 46
    iget-object v3, p0, Lw0/d;->d:Landroid/graphics/Matrix;

    .line 47
    .line 48
    invoke-direct {v1, v3}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v0, v2}, Lw0/d;->c(Landroid/util/Size;I)Landroid/graphics/Matrix;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {v1, p0}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 56
    .line 57
    .line 58
    :cond_2
    :goto_0
    return-object v1
.end method

.method public getSurfaceProvider()Lb0/j1;
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lw0/i;->o:Lt1/j0;

    .line 5
    .line 6
    return-object p0
.end method

.method public getViewPort()Lb0/a2;
    .locals 3

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lw0/i;->getDefaultDisplay()Landroid/view/Display;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const/4 v1, 0x0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    return-object v1

    .line 12
    :cond_0
    invoke-virtual {v0}, Landroid/view/Display;->getRotation()I

    .line 13
    .line 14
    .line 15
    invoke-static {}, Llp/k1;->a()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    new-instance v0, Landroid/util/Rational;

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-direct {v0, v1, v2}, Landroid/util/Rational;-><init>(II)V

    .line 42
    .line 43
    .line 44
    invoke-direct {p0}, Lw0/i;->getViewPortScaleType()I

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 48
    .line 49
    .line 50
    new-instance p0, Lb0/a2;

    .line 51
    .line 52
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :cond_2
    :goto_0
    return-object v1
.end method

.method public final onAttachedToWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/View;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    invoke-direct {p0}, Lw0/i;->getDisplayManager()Landroid/hardware/display/DisplayManager;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance v1, Landroid/os/Handler;

    .line 18
    .line 19
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 24
    .line 25
    .line 26
    iget-object v2, p0, Lw0/i;->m:Lw0/e;

    .line 27
    .line 28
    invoke-virtual {v0, v2, v1}, Landroid/hardware/display/DisplayManager;->registerDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;Landroid/os/Handler;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    :goto_0
    iget-object v0, p0, Lw0/i;->n:Lkq/a;

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Landroid/view/View;->addOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Landroidx/core/app/a0;->e()V

    .line 41
    .line 42
    .line 43
    :cond_2
    invoke-static {}, Llp/k1;->a()V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Lw0/i;->getViewPort()Lb0/a2;

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/view/View;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw0/i;->n:Lkq/a;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, Landroid/view/View;->removeOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Landroidx/core/app/a0;->f()V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    invoke-direct {p0}, Lw0/i;->getDisplayManager()Landroid/hardware/display/DisplayManager;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iget-object p0, p0, Lw0/i;->m:Lw0/e;

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Landroid/hardware/display/DisplayManager;->unregisterDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;)V

    .line 32
    .line 33
    .line 34
    :cond_2
    :goto_0
    return-void
.end method

.method public setController(Lw0/a;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Llp/k1;->a()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lw0/i;->getViewPort()Lb0/a2;

    .line 8
    .line 9
    .line 10
    invoke-direct {p0}, Lw0/i;->getScreenFlashInternal()Lb0/s0;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-direct {p0, p1}, Lw0/i;->setScreenFlashUiInfo(Lb0/s0;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setImplementationMode(Lw0/f;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw0/i;->d:Lw0/f;

    .line 5
    .line 6
    return-void
.end method

.method public setScaleType(Lw0/g;)V
    .locals 1

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw0/i;->g:Lw0/d;

    .line 5
    .line 6
    iput-object p1, v0, Lw0/d;->h:Lw0/g;

    .line 7
    .line 8
    invoke-virtual {p0}, Lw0/i;->a()V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Llp/k1;->a()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lw0/i;->getViewPort()Lb0/a2;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setScreenFlashOverlayColor(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw0/i;->f:Lw0/m;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/view/View;->setBackgroundColor(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setScreenFlashWindow(Landroid/view/Window;)V
    .locals 1

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw0/i;->f:Lw0/m;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lw0/m;->setScreenFlashWindow(Landroid/view/Window;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Lw0/i;->getScreenFlashInternal()Lb0/s0;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-direct {p0, p1}, Lw0/i;->setScreenFlashUiInfo(Lb0/s0;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
