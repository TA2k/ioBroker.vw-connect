.class public final Lin/w1;
.super Llp/pa;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:F

.field public final c:F

.field public final synthetic d:Lin/z1;

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lin/z1;FF)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lin/w1;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lin/w1;->d:Lin/z1;

    .line 3
    new-instance p1, Landroid/graphics/RectF;

    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    iput-object p1, p0, Lin/w1;->e:Ljava/lang/Object;

    .line 4
    iput p2, p0, Lin/w1;->b:F

    .line 5
    iput p3, p0, Lin/w1;->c:F

    return-void
.end method

.method public constructor <init>(Lin/z1;FFLandroid/graphics/Path;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lin/w1;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lin/w1;->d:Lin/z1;

    .line 8
    iput p2, p0, Lin/w1;->b:F

    .line 9
    iput p3, p0, Lin/w1;->c:F

    .line 10
    iput-object p4, p0, Lin/w1;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Lin/l1;)Z
    .locals 4

    .line 1
    iget v0, p0, Lin/w1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lin/m1;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    move-object v0, p1

    .line 12
    check-cast v0, Lin/m1;

    .line 13
    .line 14
    iget-object p1, p1, Lin/a1;->a:Lil/g;

    .line 15
    .line 16
    iget-object v2, v0, Lin/m1;->n:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p1, v2}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const/4 v2, 0x0

    .line 23
    if-nez p1, :cond_0

    .line 24
    .line 25
    iget-object p0, v0, Lin/m1;->n:Ljava/lang/String;

    .line 26
    .line 27
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    const-string p1, "TextPath path reference \'%s\' not found"

    .line 32
    .line 33
    invoke-static {p1, p0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :goto_0
    move v1, v2

    .line 37
    goto :goto_1

    .line 38
    :cond_0
    check-cast p1, Lin/k0;

    .line 39
    .line 40
    new-instance v0, Lin/t1;

    .line 41
    .line 42
    iget-object v3, p1, Lin/k0;->o:Li4/c;

    .line 43
    .line 44
    invoke-direct {v0, v3}, Lin/t1;-><init>(Li4/c;)V

    .line 45
    .line 46
    .line 47
    iget-object v0, v0, Lin/t1;->c:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Landroid/graphics/Path;

    .line 50
    .line 51
    iget-object p1, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 52
    .line 53
    if-eqz p1, :cond_1

    .line 54
    .line 55
    invoke-virtual {v0, p1}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    new-instance p1, Landroid/graphics/RectF;

    .line 59
    .line 60
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, p1, v1}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lin/w1;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Landroid/graphics/RectF;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    :goto_1
    return v1

    .line 75
    :pswitch_0
    instance-of p0, p1, Lin/m1;

    .line 76
    .line 77
    if-eqz p0, :cond_3

    .line 78
    .line 79
    const-string p0, "SVGAndroidRenderer"

    .line 80
    .line 81
    const-string p1, "Using <textPath> elements in a clip path is not supported."

    .line 82
    .line 83
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 84
    .line 85
    .line 86
    const/4 p0, 0x0

    .line 87
    goto :goto_2

    .line 88
    :cond_3
    const/4 p0, 0x1

    .line 89
    :goto_2
    return p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/String;)V
    .locals 9

    .line 1
    iget v0, p0, Lin/w1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lin/w1;->d:Lin/z1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lin/z1;->m0()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    new-instance v1, Landroid/graphics/Rect;

    .line 15
    .line 16
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 17
    .line 18
    .line 19
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Lin/x1;

    .line 22
    .line 23
    iget-object v2, v2, Lin/x1;->d:Landroid/graphics/Paint;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    invoke-virtual {v2, p1, v3, v4, v1}, Landroid/graphics/Paint;->getTextBounds(Ljava/lang/String;IILandroid/graphics/Rect;)V

    .line 31
    .line 32
    .line 33
    new-instance v2, Landroid/graphics/RectF;

    .line 34
    .line 35
    invoke-direct {v2, v1}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lin/w1;->b:F

    .line 39
    .line 40
    iget v3, p0, Lin/w1;->c:F

    .line 41
    .line 42
    invoke-virtual {v2, v1, v3}, Landroid/graphics/RectF;->offset(FF)V

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lin/w1;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v1, Landroid/graphics/RectF;

    .line 48
    .line 49
    invoke-virtual {v1, v2}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 50
    .line 51
    .line 52
    :cond_0
    iget v1, p0, Lin/w1;->b:F

    .line 53
    .line 54
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Lin/x1;

    .line 57
    .line 58
    iget-object v0, v0, Lin/x1;->d:Landroid/graphics/Paint;

    .line 59
    .line 60
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    add-float/2addr p1, v1

    .line 65
    iput p1, p0, Lin/w1;->b:F

    .line 66
    .line 67
    return-void

    .line 68
    :pswitch_0
    iget-object v0, p0, Lin/w1;->d:Lin/z1;

    .line 69
    .line 70
    invoke-virtual {v0}, Lin/z1;->m0()Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-eqz v1, :cond_1

    .line 75
    .line 76
    new-instance v8, Landroid/graphics/Path;

    .line 77
    .line 78
    invoke-direct {v8}, Landroid/graphics/Path;-><init>()V

    .line 79
    .line 80
    .line 81
    iget-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v1, Lin/x1;

    .line 84
    .line 85
    iget-object v2, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 86
    .line 87
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    iget v6, p0, Lin/w1;->b:F

    .line 92
    .line 93
    iget v7, p0, Lin/w1;->c:F

    .line 94
    .line 95
    const/4 v4, 0x0

    .line 96
    move-object v3, p1

    .line 97
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Paint;->getTextPath(Ljava/lang/String;IIFFLandroid/graphics/Path;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, p0, Lin/w1;->e:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p1, Landroid/graphics/Path;

    .line 103
    .line 104
    invoke-virtual {p1, v8}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_1
    move-object v3, p1

    .line 109
    :goto_0
    iget p1, p0, Lin/w1;->b:F

    .line 110
    .line 111
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Lin/x1;

    .line 114
    .line 115
    iget-object v0, v0, Lin/x1;->d:Landroid/graphics/Paint;

    .line 116
    .line 117
    invoke-virtual {v0, v3}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    add-float/2addr v0, p1

    .line 122
    iput v0, p0, Lin/w1;->b:F

    .line 123
    .line 124
    return-void

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
