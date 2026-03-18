.class public abstract Lgn/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroid/graphics/Matrix;

.field public static final b:Ley0/b;

.field public static final c:Ley0/b;

.field public static final d:Ley0/b;

.field public static final e:Ley0/b;

.field public static final f:F


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 7
    .line 8
    new-instance v0, Ley0/b;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lgn/h;->b:Ley0/b;

    .line 15
    .line 16
    new-instance v0, Ley0/b;

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lgn/h;->c:Ley0/b;

    .line 23
    .line 24
    new-instance v0, Ley0/b;

    .line 25
    .line 26
    const/4 v1, 0x3

    .line 27
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lgn/h;->d:Ley0/b;

    .line 31
    .line 32
    new-instance v0, Ley0/b;

    .line 33
    .line 34
    const/4 v1, 0x4

    .line 35
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Lgn/h;->e:Ley0/b;

    .line 39
    .line 40
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 41
    .line 42
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 43
    .line 44
    .line 45
    move-result-wide v2

    .line 46
    div-double/2addr v2, v0

    .line 47
    double-to-float v0, v2

    .line 48
    sput v0, Lgn/h;->f:F

    .line 49
    .line 50
    return-void
.end method

.method public static a(Landroid/graphics/Path;FFF)V
    .locals 9

    .line 1
    sget-object v0, Lgn/h;->b:Ley0/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/graphics/PathMeasure;

    .line 8
    .line 9
    sget-object v1, Lgn/h;->c:Ley0/b;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Landroid/graphics/Path;

    .line 16
    .line 17
    sget-object v2, Lgn/h;->d:Ley0/b;

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Landroid/graphics/Path;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-virtual {v0, p0, v3}, Landroid/graphics/PathMeasure;->setPath(Landroid/graphics/Path;Z)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Landroid/graphics/PathMeasure;->getLength()F

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    const/high16 v4, 0x3f800000    # 1.0f

    .line 34
    .line 35
    cmpl-float v5, p1, v4

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    if-nez v5, :cond_0

    .line 39
    .line 40
    cmpl-float v5, p2, v6

    .line 41
    .line 42
    if-nez v5, :cond_0

    .line 43
    .line 44
    goto/16 :goto_1

    .line 45
    .line 46
    :cond_0
    cmpg-float v5, v3, v4

    .line 47
    .line 48
    if-ltz v5, :cond_9

    .line 49
    .line 50
    sub-float v5, p2, p1

    .line 51
    .line 52
    sub-float/2addr v5, v4

    .line 53
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    float-to-double v4, v4

    .line 58
    const-wide v7, 0x3f847ae147ae147bL    # 0.01

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    cmpg-double v4, v4, v7

    .line 64
    .line 65
    if-gez v4, :cond_1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    mul-float/2addr p1, v3

    .line 69
    mul-float/2addr p2, v3

    .line 70
    invoke-static {p1, p2}, Ljava/lang/Math;->min(FF)F

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    invoke-static {p1, p2}, Ljava/lang/Math;->max(FF)F

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    mul-float/2addr p3, v3

    .line 79
    add-float/2addr v4, p3

    .line 80
    add-float/2addr p1, p3

    .line 81
    cmpl-float p2, v4, v3

    .line 82
    .line 83
    if-ltz p2, :cond_2

    .line 84
    .line 85
    cmpl-float p2, p1, v3

    .line 86
    .line 87
    if-ltz p2, :cond_2

    .line 88
    .line 89
    invoke-static {v4, v3}, Lgn/f;->d(FF)I

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    int-to-float v4, p2

    .line 94
    invoke-static {p1, v3}, Lgn/f;->d(FF)I

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    int-to-float p1, p1

    .line 99
    :cond_2
    cmpg-float p2, v4, v6

    .line 100
    .line 101
    if-gez p2, :cond_3

    .line 102
    .line 103
    invoke-static {v4, v3}, Lgn/f;->d(FF)I

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    int-to-float v4, p2

    .line 108
    :cond_3
    cmpg-float p2, p1, v6

    .line 109
    .line 110
    if-gez p2, :cond_4

    .line 111
    .line 112
    invoke-static {p1, v3}, Lgn/f;->d(FF)I

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    int-to-float p1, p1

    .line 117
    :cond_4
    cmpl-float p2, v4, p1

    .line 118
    .line 119
    if-nez p2, :cond_5

    .line 120
    .line 121
    invoke-virtual {p0}, Landroid/graphics/Path;->reset()V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_5
    if-ltz p2, :cond_6

    .line 126
    .line 127
    sub-float/2addr v4, v3

    .line 128
    :cond_6
    invoke-virtual {v1}, Landroid/graphics/Path;->reset()V

    .line 129
    .line 130
    .line 131
    const/4 p2, 0x1

    .line 132
    invoke-virtual {v0, v4, p1, v1, p2}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 133
    .line 134
    .line 135
    cmpl-float p3, p1, v3

    .line 136
    .line 137
    if-lez p3, :cond_7

    .line 138
    .line 139
    invoke-virtual {v2}, Landroid/graphics/Path;->reset()V

    .line 140
    .line 141
    .line 142
    rem-float/2addr p1, v3

    .line 143
    invoke-virtual {v0, v6, p1, v2, p2}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v2}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;)V

    .line 147
    .line 148
    .line 149
    goto :goto_0

    .line 150
    :cond_7
    cmpg-float p1, v4, v6

    .line 151
    .line 152
    if-gez p1, :cond_8

    .line 153
    .line 154
    invoke-virtual {v2}, Landroid/graphics/Path;->reset()V

    .line 155
    .line 156
    .line 157
    add-float/2addr v4, v3

    .line 158
    invoke-virtual {v0, v4, v3, v2, p2}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1, v2}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;)V

    .line 162
    .line 163
    .line 164
    :cond_8
    :goto_0
    invoke-virtual {p0, v1}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 165
    .line 166
    .line 167
    :cond_9
    :goto_1
    return-void
.end method

.method public static b(Ljava/io/Closeable;)V
    .locals 0

    .line 1
    :try_start_0
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    :catch_0
    return-void

    .line 5
    :catch_1
    move-exception p0

    .line 6
    throw p0
.end method

.method public static c()F
    .locals 1

    .line 1
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget v0, v0, Landroid/util/DisplayMetrics;->density:F

    .line 10
    .line 11
    return v0
.end method

.method public static d(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ne v0, p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-ne v0, p2, :cond_0

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 v0, 0x1

    .line 15
    invoke-static {p0, p1, p2, v0}, Landroid/graphics/Bitmap;->createScaledBitmap(Landroid/graphics/Bitmap;IIZ)Landroid/graphics/Bitmap;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->recycle()V

    .line 20
    .line 21
    .line 22
    return-object p1
.end method
