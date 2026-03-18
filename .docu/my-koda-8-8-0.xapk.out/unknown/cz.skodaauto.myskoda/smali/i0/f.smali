.class public abstract Li0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/RectF;

    .line 2
    .line 3
    const/high16 v1, -0x40800000    # -1.0f

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    invoke-direct {v0, v1, v1, v2, v2}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Li0/f;->a:Landroid/graphics/RectF;

    .line 11
    .line 12
    return-void
.end method

.method public static a(Landroid/graphics/RectF;Landroid/graphics/RectF;IZ)Landroid/graphics/Matrix;
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Landroid/graphics/Matrix$ScaleToFit;->FILL:Landroid/graphics/Matrix$ScaleToFit;

    .line 7
    .line 8
    sget-object v2, Li0/f;->a:Landroid/graphics/RectF;

    .line 9
    .line 10
    invoke-virtual {v0, p0, v2, v1}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 11
    .line 12
    .line 13
    int-to-float p0, p2

    .line 14
    invoke-virtual {v0, p0}, Landroid/graphics/Matrix;->postRotate(F)Z

    .line 15
    .line 16
    .line 17
    if-eqz p3, :cond_0

    .line 18
    .line 19
    const/high16 p0, -0x40800000    # -1.0f

    .line 20
    .line 21
    const/high16 p2, 0x3f800000    # 1.0f

    .line 22
    .line 23
    invoke-virtual {v0, p0, p2}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    new-instance p0, Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-direct {p0}, Landroid/graphics/Matrix;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v2, p1, v1}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, p0}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

.method public static b(Landroid/graphics/Matrix;)I
    .locals 4

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    new-array v0, v0, [F

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/graphics/Matrix;->getValues([F)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    aget p0, v0, p0

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    aget v0, v0, v1

    .line 13
    .line 14
    float-to-double v0, v0

    .line 15
    float-to-double v2, p0

    .line 16
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->atan2(DD)D

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    const-wide v2, 0x404ca5dc1a63c1f8L    # 57.29577951308232

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    mul-double/2addr v0, v2

    .line 26
    invoke-static {v0, v1}, Ljava/lang/Math;->round(D)J

    .line 27
    .line 28
    .line 29
    move-result-wide v0

    .line 30
    long-to-int p0, v0

    .line 31
    invoke-static {p0}, Li0/f;->i(I)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public static c(I)Z
    .locals 2

    .line 1
    const/16 v0, 0x5a

    .line 2
    .line 3
    if-eq p0, v0, :cond_3

    .line 4
    .line 5
    const/16 v0, 0x10e

    .line 6
    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/16 v0, 0xb4

    .line 13
    .line 14
    if-ne p0, v0, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string v1, "Invalid rotation degrees: "

    .line 20
    .line 21
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 32
    return p0
.end method

.method public static d(Landroid/util/Size;ZLandroid/util/Size;)Z
    .locals 3

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    int-to-float p1, p1

    .line 10
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    int-to-float p0, p0

    .line 15
    div-float/2addr p1, p0

    .line 16
    move p0, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    int-to-float p1, p1

    .line 23
    add-float/2addr p1, v0

    .line 24
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    int-to-float v1, v1

    .line 29
    sub-float/2addr v1, v0

    .line 30
    div-float/2addr p1, v1

    .line 31
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    int-to-float v1, v1

    .line 36
    sub-float/2addr v1, v0

    .line 37
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    int-to-float p0, p0

    .line 42
    add-float/2addr p0, v0

    .line 43
    div-float p0, v1, p0

    .line 44
    .line 45
    :goto_0
    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    int-to-float v1, v1

    .line 50
    add-float/2addr v1, v0

    .line 51
    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    int-to-float v2, v2

    .line 56
    sub-float/2addr v2, v0

    .line 57
    div-float/2addr v1, v2

    .line 58
    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    int-to-float v2, v2

    .line 63
    sub-float/2addr v2, v0

    .line 64
    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    int-to-float p2, p2

    .line 69
    add-float/2addr p2, v0

    .line 70
    div-float/2addr v2, p2

    .line 71
    cmpl-float p1, p1, v2

    .line 72
    .line 73
    if-ltz p1, :cond_1

    .line 74
    .line 75
    cmpl-float p0, v1, p0

    .line 76
    .line 77
    if-ltz p0, :cond_1

    .line 78
    .line 79
    const/4 p0, 0x1

    .line 80
    return p0

    .line 81
    :cond_1
    const/4 p0, 0x0

    .line 82
    return p0
.end method

.method public static e(Landroid/graphics/Matrix;)Z
    .locals 9

    .line 1
    const/4 v0, 0x4

    .line 2
    new-array v0, v0, [F

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/graphics/Matrix;->mapVectors([F)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    aget v1, v0, p0

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    aget v3, v0, v2

    .line 15
    .line 16
    const/4 v4, 0x2

    .line 17
    aget v4, v0, v4

    .line 18
    .line 19
    const/4 v5, 0x3

    .line 20
    aget v0, v0, v5

    .line 21
    .line 22
    mul-float v5, v1, v4

    .line 23
    .line 24
    mul-float v6, v3, v0

    .line 25
    .line 26
    add-float/2addr v6, v5

    .line 27
    mul-float v5, v1, v0

    .line 28
    .line 29
    mul-float v7, v3, v4

    .line 30
    .line 31
    sub-float/2addr v5, v7

    .line 32
    mul-float/2addr v1, v1

    .line 33
    mul-float/2addr v3, v3

    .line 34
    add-float/2addr v3, v1

    .line 35
    float-to-double v7, v3

    .line 36
    invoke-static {v7, v8}, Ljava/lang/Math;->sqrt(D)D

    .line 37
    .line 38
    .line 39
    move-result-wide v7

    .line 40
    mul-float/2addr v4, v4

    .line 41
    mul-float/2addr v0, v0

    .line 42
    add-float/2addr v0, v4

    .line 43
    float-to-double v0, v0

    .line 44
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 45
    .line 46
    .line 47
    move-result-wide v0

    .line 48
    float-to-double v3, v6

    .line 49
    mul-double/2addr v7, v0

    .line 50
    div-double/2addr v3, v7

    .line 51
    float-to-double v0, v5

    .line 52
    div-double/2addr v0, v7

    .line 53
    invoke-static {v0, v1, v3, v4}, Ljava/lang/Math;->atan2(DD)D

    .line 54
    .line 55
    .line 56
    move-result-wide v0

    .line 57
    invoke-static {v0, v1}, Ljava/lang/Math;->toDegrees(D)D

    .line 58
    .line 59
    .line 60
    move-result-wide v0

    .line 61
    double-to-float v0, v0

    .line 62
    const/4 v1, 0x0

    .line 63
    cmpl-float v0, v0, v1

    .line 64
    .line 65
    if-lez v0, :cond_0

    .line 66
    .line 67
    return v2

    .line 68
    :cond_0
    return p0

    .line 69
    :array_0
    .array-data 4
        0x0
        0x3f800000    # 1.0f
        0x3f800000    # 1.0f
        0x0
    .end array-data
.end method

.method public static f(Landroid/graphics/Rect;)Landroid/util/Size;
    .locals 2

    .line 1
    new-instance v0, Landroid/util/Size;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-direct {v0, v1, p0}, Landroid/util/Size;-><init>(II)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static g(Landroid/util/Size;I)Landroid/util/Size;
    .locals 3

    .line 1
    rem-int/lit8 v0, p1, 0x5a

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Invalid rotation degrees: "

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-static {v0, v1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Li0/f;->i(I)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    invoke-static {p1}, Li0/f;->c(I)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    new-instance p1, Landroid/util/Size;

    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    invoke-direct {p1, v0, p0}, Landroid/util/Size;-><init>(II)V

    .line 46
    .line 47
    .line 48
    return-object p1

    .line 49
    :cond_1
    return-object p0
.end method

.method public static h(Landroid/util/Size;)Landroid/graphics/RectF;
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/RectF;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    int-to-float v1, v1

    .line 5
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    int-to-float v2, v2

    .line 10
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    int-to-float p0, p0

    .line 15
    invoke-direct {v0, v1, v1, v2, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static i(I)I
    .locals 0

    .line 1
    rem-int/lit16 p0, p0, 0x168

    .line 2
    .line 3
    add-int/lit16 p0, p0, 0x168

    .line 4
    .line 5
    rem-int/lit16 p0, p0, 0x168

    .line 6
    .line 7
    return p0
.end method
