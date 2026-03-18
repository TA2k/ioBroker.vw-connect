.class public Lsu/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsu/a;


# static fields
.field public static final r:[I

.field public static final s:Landroid/view/animation/DecelerateInterpolator;


# instance fields
.field public final a:Lqp/g;

.field public final b:Lcom/google/firebase/messaging/w;

.field public final c:Lqu/c;

.field public d:Z

.field public final e:J

.field public final f:Ljava/util/concurrent/ExecutorService;

.field public final g:Landroid/graphics/drawable/ShapeDrawable;

.field public h:Ljava/util/Set;

.field public final i:Landroid/util/SparseArray;

.field public final j:Lb81/c;

.field public final k:I

.field public l:Ljava/util/Set;

.field public final m:Lb81/c;

.field public n:F

.field public final o:Lsu/h;

.field public p:Lnd0/c;

.field public q:Lnd0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x7

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    sput-object v0, Lsu/i;->r:[I

    .line 8
    .line 9
    new-instance v0, Landroid/view/animation/DecelerateInterpolator;

    .line 10
    .line 11
    invoke-direct {v0}, Landroid/view/animation/DecelerateInterpolator;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lsu/i;->s:Landroid/view/animation/DecelerateInterpolator;

    .line 15
    .line 16
    return-void

    .line 17
    :array_0
    .array-data 4
        0xa
        0x14
        0x32
        0x64
        0xc8
        0x1f4
        0x3e8
    .end array-data
.end method

.method public constructor <init>(Landroid/content/Context;Lqp/g;Lqu/c;)V
    .locals 11

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lsu/i;->f:Ljava/util/concurrent/ExecutorService;

    .line 9
    .line 10
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-static {v0}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Lsu/i;->h:Ljava/util/Set;

    .line 20
    .line 21
    new-instance v0, Landroid/util/SparseArray;

    .line 22
    .line 23
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lsu/i;->i:Landroid/util/SparseArray;

    .line 27
    .line 28
    new-instance v0, Lb81/c;

    .line 29
    .line 30
    const/16 v1, 0x17

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lb81/c;-><init>(I)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lsu/i;->j:Lb81/c;

    .line 36
    .line 37
    const/4 v0, 0x4

    .line 38
    iput v0, p0, Lsu/i;->k:I

    .line 39
    .line 40
    new-instance v0, Lb81/c;

    .line 41
    .line 42
    invoke-direct {v0, v1}, Lb81/c;-><init>(I)V

    .line 43
    .line 44
    .line 45
    iput-object v0, p0, Lsu/i;->m:Lb81/c;

    .line 46
    .line 47
    new-instance v0, Lsu/h;

    .line 48
    .line 49
    invoke-direct {v0, p0}, Lsu/h;-><init>(Lsu/i;)V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Lsu/i;->o:Lsu/h;

    .line 53
    .line 54
    iput-object p2, p0, Lsu/i;->a:Lqp/g;

    .line 55
    .line 56
    const/4 p2, 0x1

    .line 57
    iput-boolean p2, p0, Lsu/i;->d:Z

    .line 58
    .line 59
    const-wide/16 v0, 0x12c

    .line 60
    .line 61
    iput-wide v0, p0, Lsu/i;->e:J

    .line 62
    .line 63
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    iget v0, v0, Landroid/util/DisplayMetrics;->density:F

    .line 72
    .line 73
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 74
    .line 75
    invoke-direct {v1, p1}, Lcom/google/firebase/messaging/w;-><init>(Landroid/content/Context;)V

    .line 76
    .line 77
    .line 78
    iput-object v1, p0, Lsu/i;->b:Lcom/google/firebase/messaging/w;

    .line 79
    .line 80
    new-instance v2, Lav/b;

    .line 81
    .line 82
    invoke-direct {v2, p1}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V

    .line 83
    .line 84
    .line 85
    const/4 v3, 0x0

    .line 86
    iput v3, v2, Lav/b;->d:I

    .line 87
    .line 88
    iput v3, v2, Lav/b;->e:I

    .line 89
    .line 90
    new-instance v4, Landroid/view/ViewGroup$LayoutParams;

    .line 91
    .line 92
    const/4 v5, -0x2

    .line 93
    invoke-direct {v4, v5, v5}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2, v4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 97
    .line 98
    .line 99
    const v4, 0x7f0a004f

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2, v4}, Landroid/view/View;->setId(I)V

    .line 103
    .line 104
    .line 105
    const/high16 v5, 0x41400000    # 12.0f

    .line 106
    .line 107
    mul-float/2addr v5, v0

    .line 108
    float-to-int v5, v5

    .line 109
    invoke-virtual {v2, v5, v5, v5, v5}, Landroid/view/View;->setPadding(IIII)V

    .line 110
    .line 111
    .line 112
    iget-object v5, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v5, Lcom/google/maps/android/ui/RotationLayout;

    .line 115
    .line 116
    invoke-virtual {v5}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v5, v2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v5, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    instance-of v4, v2, Landroid/widget/TextView;

    .line 127
    .line 128
    if-eqz v4, :cond_0

    .line 129
    .line 130
    check-cast v2, Landroid/widget/TextView;

    .line 131
    .line 132
    goto :goto_0

    .line 133
    :cond_0
    const/4 v2, 0x0

    .line 134
    :goto_0
    iput-object v2, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 135
    .line 136
    if-eqz v2, :cond_1

    .line 137
    .line 138
    const v4, 0x7f130576

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2, p1, v4}, Landroid/widget/TextView;->setTextAppearance(Landroid/content/Context;I)V

    .line 142
    .line 143
    .line 144
    :cond_1
    new-instance p1, Landroid/graphics/drawable/ShapeDrawable;

    .line 145
    .line 146
    new-instance v2, Landroid/graphics/drawable/shapes/OvalShape;

    .line 147
    .line 148
    invoke-direct {v2}, Landroid/graphics/drawable/shapes/OvalShape;-><init>()V

    .line 149
    .line 150
    .line 151
    invoke-direct {p1, v2}, Landroid/graphics/drawable/ShapeDrawable;-><init>(Landroid/graphics/drawable/shapes/Shape;)V

    .line 152
    .line 153
    .line 154
    iput-object p1, p0, Lsu/i;->g:Landroid/graphics/drawable/ShapeDrawable;

    .line 155
    .line 156
    new-instance p1, Landroid/graphics/drawable/ShapeDrawable;

    .line 157
    .line 158
    new-instance v2, Landroid/graphics/drawable/shapes/OvalShape;

    .line 159
    .line 160
    invoke-direct {v2}, Landroid/graphics/drawable/shapes/OvalShape;-><init>()V

    .line 161
    .line 162
    .line 163
    invoke-direct {p1, v2}, Landroid/graphics/drawable/ShapeDrawable;-><init>(Landroid/graphics/drawable/shapes/Shape;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p1}, Landroid/graphics/drawable/ShapeDrawable;->getPaint()Landroid/graphics/Paint;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    const v4, -0x7f000001

    .line 171
    .line 172
    .line 173
    invoke-virtual {v2, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 174
    .line 175
    .line 176
    new-instance v5, Landroid/graphics/drawable/LayerDrawable;

    .line 177
    .line 178
    iget-object v2, p0, Lsu/i;->g:Landroid/graphics/drawable/ShapeDrawable;

    .line 179
    .line 180
    const/4 v4, 0x2

    .line 181
    new-array v4, v4, [Landroid/graphics/drawable/Drawable;

    .line 182
    .line 183
    aput-object p1, v4, v3

    .line 184
    .line 185
    aput-object v2, v4, p2

    .line 186
    .line 187
    invoke-direct {v5, v4}, Landroid/graphics/drawable/LayerDrawable;-><init>([Landroid/graphics/drawable/Drawable;)V

    .line 188
    .line 189
    .line 190
    const/high16 p1, 0x40400000    # 3.0f

    .line 191
    .line 192
    mul-float/2addr v0, p1

    .line 193
    float-to-int v7, v0

    .line 194
    const/4 v6, 0x1

    .line 195
    move v8, v7

    .line 196
    move v9, v7

    .line 197
    move v10, v7

    .line 198
    invoke-virtual/range {v5 .. v10}, Landroid/graphics/drawable/LayerDrawable;->setLayerInset(IIIII)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v1, v5}, Lcom/google/firebase/messaging/w;->r(Landroid/graphics/drawable/Drawable;)V

    .line 202
    .line 203
    .line 204
    iput-object p3, p0, Lsu/i;->c:Lqu/c;

    .line 205
    .line 206
    return-void
.end method

.method public static b(Lsu/i;Ljava/util/ArrayList;Lyu/a;)Lyu/a;
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_2

    .line 3
    .line 4
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_0
    iget-object p0, p0, Lsu/i;->c:Lqu/c;

    .line 12
    .line 13
    iget-object p0, p0, Lqu/c;->g:Lap0/o;

    .line 14
    .line 15
    invoke-interface {p0}, Lru/a;->o()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    mul-int/2addr p0, p0

    .line 20
    int-to-double v1, p0

    .line 21
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_2

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Lyu/a;

    .line 36
    .line 37
    iget-wide v3, p1, Lyu/a;->a:D

    .line 38
    .line 39
    iget-wide v5, p2, Lyu/a;->a:D

    .line 40
    .line 41
    sub-double/2addr v3, v5

    .line 42
    mul-double/2addr v3, v3

    .line 43
    iget-wide v5, p1, Lyu/a;->b:D

    .line 44
    .line 45
    iget-wide v7, p2, Lyu/a;->b:D

    .line 46
    .line 47
    sub-double/2addr v5, v7

    .line 48
    mul-double/2addr v5, v5

    .line 49
    add-double/2addr v5, v3

    .line 50
    cmpg-double v3, v5, v1

    .line 51
    .line 52
    if-gez v3, :cond_1

    .line 53
    .line 54
    move-object v0, p1

    .line 55
    move-wide v1, v5

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    :goto_1
    return-object v0
.end method


# virtual methods
.method public a(Ljava/util/Set;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lsu/i;->o:Lsu/h;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    new-instance v0, Lsu/g;

    .line 5
    .line 6
    iget-object v1, p0, Lsu/h;->c:Lsu/i;

    .line 7
    .line 8
    invoke-direct {v0, v1, p1}, Lsu/g;-><init>(Lsu/i;Ljava/util/Set;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lsu/h;->b:Lsu/g;

    .line 12
    .line 13
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    const/4 p1, 0x0

    .line 15
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p1

    .line 20
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    throw p1
.end method

.method public c(Lqu/a;)Lsp/b;
    .locals 7

    .line 1
    invoke-interface {p1}, Lqu/a;->a()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    sget-object v0, Lsu/i;->r:[I

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aget v2, v0, v1

    .line 9
    .line 10
    if-gt p1, v2, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    move v2, v1

    .line 14
    :goto_0
    const/4 v3, 0x6

    .line 15
    if-ge v2, v3, :cond_2

    .line 16
    .line 17
    add-int/lit8 v3, v2, 0x1

    .line 18
    .line 19
    aget v4, v0, v3

    .line 20
    .line 21
    if-ge p1, v4, :cond_1

    .line 22
    .line 23
    aget p1, v0, v2

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move v2, v3

    .line 27
    goto :goto_0

    .line 28
    :cond_2
    aget p1, v0, v3

    .line 29
    .line 30
    :goto_1
    iget-object v2, p0, Lsu/i;->i:Landroid/util/SparseArray;

    .line 31
    .line 32
    invoke-virtual {v2, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    check-cast v3, Lsp/b;

    .line 37
    .line 38
    if-nez v3, :cond_6

    .line 39
    .line 40
    iget-object v3, p0, Lsu/i;->g:Landroid/graphics/drawable/ShapeDrawable;

    .line 41
    .line 42
    invoke-virtual {v3}, Landroid/graphics/drawable/ShapeDrawable;->getPaint()Landroid/graphics/Paint;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    int-to-float v4, p1

    .line 47
    const/high16 v5, 0x43960000    # 300.0f

    .line 48
    .line 49
    invoke-static {v4, v5}, Ljava/lang/Math;->min(FF)F

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    sub-float/2addr v5, v4

    .line 54
    mul-float/2addr v5, v5

    .line 55
    const v4, 0x47afc800    # 90000.0f

    .line 56
    .line 57
    .line 58
    div-float/2addr v5, v4

    .line 59
    const/high16 v4, 0x435c0000    # 220.0f

    .line 60
    .line 61
    mul-float/2addr v5, v4

    .line 62
    const/4 v4, 0x3

    .line 63
    new-array v4, v4, [F

    .line 64
    .line 65
    aput v5, v4, v1

    .line 66
    .line 67
    const/high16 v5, 0x3f800000    # 1.0f

    .line 68
    .line 69
    const/4 v6, 0x1

    .line 70
    aput v5, v4, v6

    .line 71
    .line 72
    const v5, 0x3f19999a    # 0.6f

    .line 73
    .line 74
    .line 75
    const/4 v6, 0x2

    .line 76
    aput v5, v4, v6

    .line 77
    .line 78
    invoke-static {v4}, Landroid/graphics/Color;->HSVToColor([F)I

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 83
    .line 84
    .line 85
    iget-object p0, p0, Lsu/i;->b:Lcom/google/firebase/messaging/w;

    .line 86
    .line 87
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v3, Landroid/content/Context;

    .line 90
    .line 91
    iget-object v4, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v4, Landroid/widget/TextView;

    .line 94
    .line 95
    if-eqz v4, :cond_3

    .line 96
    .line 97
    const v5, 0x7f130576

    .line 98
    .line 99
    .line 100
    invoke-virtual {v4, v3, v5}, Landroid/widget/TextView;->setTextAppearance(Landroid/content/Context;I)V

    .line 101
    .line 102
    .line 103
    :cond_3
    aget v0, v0, v1

    .line 104
    .line 105
    if-ge p1, v0, :cond_4

    .line 106
    .line 107
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    goto :goto_2

    .line 112
    :cond_4
    const-string v0, "+"

    .line 113
    .line 114
    invoke-static {p1, v0}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    :goto_2
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v3, Landroid/widget/TextView;

    .line 121
    .line 122
    if-eqz v3, :cond_5

    .line 123
    .line 124
    invoke-virtual {v3, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 125
    .line 126
    .line 127
    :cond_5
    invoke-static {v1, v1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast p0, Landroid/view/ViewGroup;

    .line 134
    .line 135
    invoke-virtual {p0, v0, v0}, Landroid/view/View;->measure(II)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredWidth()I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 143
    .line 144
    .line 145
    move-result v3

    .line 146
    invoke-virtual {p0, v1, v1, v0, v3}, Landroid/view/ViewGroup;->layout(IIII)V

    .line 147
    .line 148
    .line 149
    sget-object v4, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 150
    .line 151
    invoke-static {v0, v3, v4}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-virtual {v0, v1}, Landroid/graphics/Bitmap;->eraseColor(I)V

    .line 156
    .line 157
    .line 158
    new-instance v1, Landroid/graphics/Canvas;

    .line 159
    .line 160
    invoke-direct {v1, v0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0, v1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v0}, Lkp/m8;->b(Landroid/graphics/Bitmap;)Lsp/b;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    invoke-virtual {v2, p1, p0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    return-object p0

    .line 174
    :cond_6
    return-object v3
.end method

.method public final d()V
    .locals 4

    .line 1
    iget-object v0, p0, Lsu/i;->c:Lqu/c;

    .line 2
    .line 3
    iget-object v1, v0, Lqu/c;->e:Ltu/a;

    .line 4
    .line 5
    new-instance v2, Lsu/b;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v2, p0, v3}, Lsu/b;-><init>(Lsu/i;I)V

    .line 9
    .line 10
    .line 11
    iput-object v2, v1, Ltu/a;->e:Lqp/e;

    .line 12
    .line 13
    new-instance v2, Lsu/b;

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v2, p0, v3}, Lsu/b;-><init>(Lsu/i;I)V

    .line 17
    .line 18
    .line 19
    iput-object v2, v1, Ltu/a;->c:Lqp/c;

    .line 20
    .line 21
    new-instance v2, Lsu/b;

    .line 22
    .line 23
    const/4 v3, 0x2

    .line 24
    invoke-direct {v2, p0, v3}, Lsu/b;-><init>(Lsu/i;I)V

    .line 25
    .line 26
    .line 27
    iput-object v2, v1, Ltu/a;->d:Lqp/d;

    .line 28
    .line 29
    iget-object v0, v0, Lqu/c;->f:Ltu/a;

    .line 30
    .line 31
    new-instance v1, Lsu/b;

    .line 32
    .line 33
    const/4 v2, 0x3

    .line 34
    invoke-direct {v1, p0, v2}, Lsu/b;-><init>(Lsu/i;I)V

    .line 35
    .line 36
    .line 37
    iput-object v1, v0, Ltu/a;->e:Lqp/e;

    .line 38
    .line 39
    new-instance v1, Lsu/b;

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    invoke-direct {v1, p0, v2}, Lsu/b;-><init>(Lsu/i;I)V

    .line 43
    .line 44
    .line 45
    iput-object v1, v0, Ltu/a;->c:Lqp/c;

    .line 46
    .line 47
    new-instance v1, Lsu/b;

    .line 48
    .line 49
    const/4 v2, 0x2

    .line 50
    invoke-direct {v1, p0, v2}, Lsu/b;-><init>(Lsu/i;I)V

    .line 51
    .line 52
    .line 53
    iput-object v1, v0, Ltu/a;->d:Lqp/d;

    .line 54
    .line 55
    return-void
.end method

.method public e(Lzj0/c;Lsp/l;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    return-void
.end method
