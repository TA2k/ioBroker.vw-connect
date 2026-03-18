.class public abstract Lpv/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:La5/f;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, La5/f;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, La5/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lpv/b;->a:La5/f;

    .line 9
    .line 10
    return-void
.end method

.method public static a(Ljava/util/List;)Landroid/graphics/Rect;
    .locals 6

    .line 1
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    const v1, 0x7fffffff

    .line 8
    .line 9
    .line 10
    move v2, v1

    .line 11
    move v3, v2

    .line 12
    move v1, v0

    .line 13
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    check-cast v4, Landroid/graphics/Point;

    .line 24
    .line 25
    iget v5, v4, Landroid/graphics/Point;->x:I

    .line 26
    .line 27
    invoke-static {v2, v5}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    iget v5, v4, Landroid/graphics/Point;->x:I

    .line 32
    .line 33
    invoke-static {v0, v5}, Ljava/lang/Math;->max(II)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget v5, v4, Landroid/graphics/Point;->y:I

    .line 38
    .line 39
    invoke-static {v3, v5}, Ljava/lang/Math;->min(II)I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    iget v4, v4, Landroid/graphics/Point;->y:I

    .line 44
    .line 45
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance p0, Landroid/graphics/Rect;

    .line 51
    .line 52
    invoke-direct {p0, v2, v3, v0, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 53
    .line 54
    .line 55
    return-object p0
.end method

.method public static b(Llp/y1;)Ljava/util/List;
    .locals 15

    .line 1
    const/4 v0, 0x4

    .line 2
    new-array v0, v0, [Landroid/graphics/Point;

    .line 3
    .line 4
    iget v1, p0, Llp/y1;->h:F

    .line 5
    .line 6
    float-to-double v1, v1

    .line 7
    invoke-static {v1, v2}, Ljava/lang/Math;->toRadians(D)D

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 12
    .line 13
    .line 14
    move-result-wide v1

    .line 15
    iget v3, p0, Llp/y1;->h:F

    .line 16
    .line 17
    float-to-double v3, v3

    .line 18
    invoke-static {v3, v4}, Ljava/lang/Math;->toRadians(D)D

    .line 19
    .line 20
    .line 21
    move-result-wide v3

    .line 22
    invoke-static {v3, v4}, Ljava/lang/Math;->cos(D)D

    .line 23
    .line 24
    .line 25
    move-result-wide v3

    .line 26
    new-instance v5, Landroid/graphics/Point;

    .line 27
    .line 28
    iget v6, p0, Llp/y1;->d:I

    .line 29
    .line 30
    iget v7, p0, Llp/y1;->e:I

    .line 31
    .line 32
    invoke-direct {v5, v6, v7}, Landroid/graphics/Point;-><init>(II)V

    .line 33
    .line 34
    .line 35
    const/4 v8, 0x0

    .line 36
    aput-object v5, v0, v8

    .line 37
    .line 38
    new-instance v5, Landroid/graphics/Point;

    .line 39
    .line 40
    int-to-double v9, v6

    .line 41
    iget v6, p0, Llp/y1;->f:I

    .line 42
    .line 43
    int-to-double v11, v6

    .line 44
    mul-double v13, v11, v3

    .line 45
    .line 46
    int-to-double v6, v7

    .line 47
    mul-double/2addr v11, v1

    .line 48
    add-double/2addr v11, v6

    .line 49
    add-double/2addr v9, v13

    .line 50
    double-to-int v6, v9

    .line 51
    double-to-int v7, v11

    .line 52
    invoke-direct {v5, v6, v7}, Landroid/graphics/Point;-><init>(II)V

    .line 53
    .line 54
    .line 55
    const/4 v6, 0x1

    .line 56
    aput-object v5, v0, v6

    .line 57
    .line 58
    new-instance v7, Landroid/graphics/Point;

    .line 59
    .line 60
    iget v5, v5, Landroid/graphics/Point;->x:I

    .line 61
    .line 62
    int-to-double v9, v5

    .line 63
    iget p0, p0, Llp/y1;->g:I

    .line 64
    .line 65
    int-to-double v11, p0

    .line 66
    mul-double/2addr v11, v1

    .line 67
    aget-object v1, v0, v6

    .line 68
    .line 69
    iget v1, v1, Landroid/graphics/Point;->y:I

    .line 70
    .line 71
    int-to-double v1, v1

    .line 72
    int-to-double v13, p0

    .line 73
    mul-double/2addr v13, v3

    .line 74
    add-double/2addr v13, v1

    .line 75
    sub-double/2addr v9, v11

    .line 76
    double-to-int p0, v9

    .line 77
    double-to-int v1, v13

    .line 78
    invoke-direct {v7, p0, v1}, Landroid/graphics/Point;-><init>(II)V

    .line 79
    .line 80
    .line 81
    const/4 p0, 0x2

    .line 82
    aput-object v7, v0, p0

    .line 83
    .line 84
    new-instance v1, Landroid/graphics/Point;

    .line 85
    .line 86
    aget-object v2, v0, v8

    .line 87
    .line 88
    iget v3, v2, Landroid/graphics/Point;->x:I

    .line 89
    .line 90
    aget-object p0, v0, p0

    .line 91
    .line 92
    iget v4, p0, Landroid/graphics/Point;->x:I

    .line 93
    .line 94
    aget-object v5, v0, v6

    .line 95
    .line 96
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 97
    .line 98
    sub-int/2addr v4, v6

    .line 99
    add-int/2addr v4, v3

    .line 100
    iget v2, v2, Landroid/graphics/Point;->y:I

    .line 101
    .line 102
    iget p0, p0, Landroid/graphics/Point;->y:I

    .line 103
    .line 104
    iget v3, v5, Landroid/graphics/Point;->y:I

    .line 105
    .line 106
    sub-int/2addr p0, v3

    .line 107
    add-int/2addr p0, v2

    .line 108
    invoke-direct {v1, v4, p0}, Landroid/graphics/Point;-><init>(II)V

    .line 109
    .line 110
    .line 111
    const/4 p0, 0x3

    .line 112
    aput-object v1, v0, p0

    .line 113
    .line 114
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0
.end method
