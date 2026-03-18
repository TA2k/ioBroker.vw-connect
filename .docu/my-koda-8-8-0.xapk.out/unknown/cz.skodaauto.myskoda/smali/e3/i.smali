.class public final Le3/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/graphics/Path;

.field public b:Landroid/graphics/RectF;

.field public c:[F

.field public d:Landroid/graphics/Matrix;


# direct methods
.method public constructor <init>(Landroid/graphics/Path;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 5
    .line 6
    return-void
.end method

.method public static a(Le3/i;Le3/i;)V
    .locals 3

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    instance-of v0, p1, Le3/i;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p1, p1, Le3/i;->a:Landroid/graphics/Path;

    .line 8
    .line 9
    const-wide/16 v0, 0x0

    .line 10
    .line 11
    long-to-int v2, v0

    .line 12
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    long-to-int v0, v0

    .line 17
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0, p1, v2, v0}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;FF)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 26
    .line 27
    const-string p1, "Unable to obtain android.graphics.Path"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public static b(Le3/i;Ld3/c;)V
    .locals 4

    .line 1
    sget-object v0, Le3/h0;->d:[Le3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget v0, p1, Ld3/c;->a:F

    .line 7
    .line 8
    iget v1, p1, Ld3/c;->d:F

    .line 9
    .line 10
    iget v2, p1, Ld3/c;->c:F

    .line 11
    .line 12
    iget p1, p1, Ld3/c;->b:F

    .line 13
    .line 14
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-nez v3, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-nez v3, :cond_0

    .line 25
    .line 26
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    :cond_0
    const-string v3, "Invalid rectangle, make sure no value is NaN"

    .line 39
    .line 40
    invoke-static {v3}, Le3/l;->b(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    :cond_1
    iget-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    new-instance v3, Landroid/graphics/RectF;

    .line 48
    .line 49
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 53
    .line 54
    :cond_2
    iget-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 55
    .line 56
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v0, p1, v2, v1}, Landroid/graphics/RectF;->set(FFFF)V

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 63
    .line 64
    iget-object p0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 65
    .line 66
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Landroid/graphics/Path$Direction;->CCW:Landroid/graphics/Path$Direction;

    .line 70
    .line 71
    invoke-virtual {p1, p0, v0}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public static c(Le3/i;Ld3/d;)V
    .locals 12

    .line 1
    sget-object v0, Le3/h0;->d:[Le3/h0;

    .line 2
    .line 3
    iget-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Landroid/graphics/RectF;

    .line 8
    .line 9
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 13
    .line 14
    :cond_0
    iget-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 15
    .line 16
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iget v1, p1, Ld3/d;->a:F

    .line 20
    .line 21
    iget-wide v2, p1, Ld3/d;->h:J

    .line 22
    .line 23
    iget-wide v4, p1, Ld3/d;->g:J

    .line 24
    .line 25
    iget-wide v6, p1, Ld3/d;->f:J

    .line 26
    .line 27
    iget-wide v8, p1, Ld3/d;->e:J

    .line 28
    .line 29
    iget v10, p1, Ld3/d;->b:F

    .line 30
    .line 31
    iget v11, p1, Ld3/d;->c:F

    .line 32
    .line 33
    iget p1, p1, Ld3/d;->d:F

    .line 34
    .line 35
    invoke-virtual {v0, v1, v10, v11, p1}, Landroid/graphics/RectF;->set(FFFF)V

    .line 36
    .line 37
    .line 38
    iget-object p1, p0, Le3/i;->c:[F

    .line 39
    .line 40
    if-nez p1, :cond_1

    .line 41
    .line 42
    const/16 p1, 0x8

    .line 43
    .line 44
    new-array p1, p1, [F

    .line 45
    .line 46
    iput-object p1, p0, Le3/i;->c:[F

    .line 47
    .line 48
    :cond_1
    iget-object p1, p0, Le3/i;->c:[F

    .line 49
    .line 50
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    const/16 v0, 0x20

    .line 54
    .line 55
    shr-long v10, v8, v0

    .line 56
    .line 57
    long-to-int v1, v10

    .line 58
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    const/4 v10, 0x0

    .line 63
    aput v1, p1, v10

    .line 64
    .line 65
    const-wide v10, 0xffffffffL

    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    and-long/2addr v8, v10

    .line 71
    long-to-int v1, v8

    .line 72
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    const/4 v8, 0x1

    .line 77
    aput v1, p1, v8

    .line 78
    .line 79
    shr-long v8, v6, v0

    .line 80
    .line 81
    long-to-int v1, v8

    .line 82
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    const/4 v8, 0x2

    .line 87
    aput v1, p1, v8

    .line 88
    .line 89
    and-long/2addr v6, v10

    .line 90
    long-to-int v1, v6

    .line 91
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    const/4 v6, 0x3

    .line 96
    aput v1, p1, v6

    .line 97
    .line 98
    shr-long v6, v4, v0

    .line 99
    .line 100
    long-to-int v1, v6

    .line 101
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    const/4 v6, 0x4

    .line 106
    aput v1, p1, v6

    .line 107
    .line 108
    and-long/2addr v4, v10

    .line 109
    long-to-int v1, v4

    .line 110
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    const/4 v4, 0x5

    .line 115
    aput v1, p1, v4

    .line 116
    .line 117
    shr-long v0, v2, v0

    .line 118
    .line 119
    long-to-int v0, v0

    .line 120
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    const/4 v1, 0x6

    .line 125
    aput v0, p1, v1

    .line 126
    .line 127
    and-long v0, v2, v10

    .line 128
    .line 129
    long-to-int v0, v0

    .line 130
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    const/4 v1, 0x7

    .line 135
    aput v0, p1, v1

    .line 136
    .line 137
    iget-object p1, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 138
    .line 139
    iget-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 140
    .line 141
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iget-object p0, p0, Le3/i;->c:[F

    .line 145
    .line 146
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    sget-object v1, Landroid/graphics/Path$Direction;->CCW:Landroid/graphics/Path$Direction;

    .line 150
    .line 151
    invoke-virtual {p1, v0, p0, v1}, Landroid/graphics/Path;->addRoundRect(Landroid/graphics/RectF;[FLandroid/graphics/Path$Direction;)V

    .line 152
    .line 153
    .line 154
    return-void
.end method


# virtual methods
.method public final d(Ld3/c;FF)V
    .locals 4

    .line 1
    iget v0, p1, Ld3/c;->a:F

    .line 2
    .line 3
    iget v1, p1, Ld3/c;->b:F

    .line 4
    .line 5
    iget v2, p1, Ld3/c;->c:F

    .line 6
    .line 7
    iget p1, p1, Ld3/c;->d:F

    .line 8
    .line 9
    iget-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 10
    .line 11
    if-nez v3, :cond_0

    .line 12
    .line 13
    new-instance v3, Landroid/graphics/RectF;

    .line 14
    .line 15
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 19
    .line 20
    :cond_0
    iget-object v3, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 21
    .line 22
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v3, v0, v1, v2, p1}, Landroid/graphics/RectF;->set(FFFF)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 29
    .line 30
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    invoke-virtual {p0, p1, p2, p3, v0}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FFZ)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final e()V
    .locals 0

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/graphics/Path;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final f()Ld3/c;
    .locals 4

    .line 1
    iget-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/graphics/RectF;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Le3/i;->b:Landroid/graphics/RectF;

    .line 13
    .line 14
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-virtual {p0, v0, v1}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Ld3/c;

    .line 24
    .line 25
    iget v1, v0, Landroid/graphics/RectF;->left:F

    .line 26
    .line 27
    iget v2, v0, Landroid/graphics/RectF;->top:F

    .line 28
    .line 29
    iget v3, v0, Landroid/graphics/RectF;->right:F

    .line 30
    .line 31
    iget v0, v0, Landroid/graphics/RectF;->bottom:F

    .line 32
    .line 33
    invoke-direct {p0, v1, v2, v3, v0}, Ld3/c;-><init>(FFFF)V

    .line 34
    .line 35
    .line 36
    return-object p0
.end method

.method public final g(FF)V
    .locals 0

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final h(FF)V
    .locals 0

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Landroid/graphics/Path;->moveTo(FF)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final i(Le3/i;Le3/i;I)Z
    .locals 2

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    sget-object p3, Landroid/graphics/Path$Op;->DIFFERENCE:Landroid/graphics/Path$Op;

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    if-ne p3, v0, :cond_1

    .line 8
    .line 9
    sget-object p3, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v0, 0x4

    .line 13
    if-ne p3, v0, :cond_2

    .line 14
    .line 15
    sget-object p3, Landroid/graphics/Path$Op;->REVERSE_DIFFERENCE:Landroid/graphics/Path$Op;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    const/4 v0, 0x2

    .line 19
    if-ne p3, v0, :cond_3

    .line 20
    .line 21
    sget-object p3, Landroid/graphics/Path$Op;->UNION:Landroid/graphics/Path$Op;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_3
    sget-object p3, Landroid/graphics/Path$Op;->XOR:Landroid/graphics/Path$Op;

    .line 25
    .line 26
    :goto_0
    instance-of v0, p1, Le3/i;

    .line 27
    .line 28
    const-string v1, "Unable to obtain android.graphics.Path"

    .line 29
    .line 30
    if-eqz v0, :cond_5

    .line 31
    .line 32
    iget-object p1, p1, Le3/i;->a:Landroid/graphics/Path;

    .line 33
    .line 34
    instance-of v0, p2, Le3/i;

    .line 35
    .line 36
    if-eqz v0, :cond_4

    .line 37
    .line 38
    iget-object p2, p2, Le3/i;->a:Landroid/graphics/Path;

    .line 39
    .line 40
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2, p3}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0

    .line 47
    :cond_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 48
    .line 49
    invoke-direct {p0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_5
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 54
    .line 55
    invoke-direct {p0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0
.end method

.method public final j()V
    .locals 0

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/graphics/Path;->reset()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final k()V
    .locals 0

    .line 1
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/graphics/Path;->rewind()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final l(I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    sget-object p1, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    sget-object p1, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 8
    .line 9
    :goto_0
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final m(J)V
    .locals 4

    .line 1
    iget-object v0, p0, Le3/i;->d:Landroid/graphics/Matrix;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/graphics/Matrix;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Le3/i;->d:Landroid/graphics/Matrix;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/graphics/Matrix;->reset()V

    .line 17
    .line 18
    .line 19
    :goto_0
    iget-object v0, p0, Le3/i;->d:Landroid/graphics/Matrix;

    .line 20
    .line 21
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    shr-long v1, p1, v1

    .line 27
    .line 28
    long-to-int v1, v1

    .line 29
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    const-wide v2, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr p1, v2

    .line 39
    long-to-int p1, p1

    .line 40
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    invoke-virtual {v0, v1, p1}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Le3/i;->d:Landroid/graphics/Matrix;

    .line 48
    .line 49
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Le3/i;->a:Landroid/graphics/Path;

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method
