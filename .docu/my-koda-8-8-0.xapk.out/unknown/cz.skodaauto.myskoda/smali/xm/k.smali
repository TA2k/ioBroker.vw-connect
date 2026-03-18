.class public final Lxm/k;
.super Lxm/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Landroid/graphics/PointF;

.field public final i:[F

.field public final j:[F

.field public final k:Landroid/graphics/PathMeasure;

.field public l:Lxm/j;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Landroid/graphics/PointF;

    .line 5
    .line 6
    invoke-direct {p1}, Landroid/graphics/PointF;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lxm/k;->h:Landroid/graphics/PointF;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    new-array v0, p1, [F

    .line 13
    .line 14
    iput-object v0, p0, Lxm/k;->i:[F

    .line 15
    .line 16
    new-array p1, p1, [F

    .line 17
    .line 18
    iput-object p1, p0, Lxm/k;->j:[F

    .line 19
    .line 20
    new-instance p1, Landroid/graphics/PathMeasure;

    .line 21
    .line 22
    invoke-direct {p1}, Landroid/graphics/PathMeasure;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lxm/k;->k:Landroid/graphics/PathMeasure;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final e(Lhn/a;F)Ljava/lang/Object;
    .locals 5

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lxm/j;

    .line 3
    .line 4
    iget-object v1, v0, Lxm/j;->q:Landroid/graphics/Path;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    iget-object p0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Landroid/graphics/PointF;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    iget-object p1, p0, Lxm/k;->l:Lxm/j;

    .line 14
    .line 15
    iget-object v2, p0, Lxm/k;->k:Landroid/graphics/PathMeasure;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    if-eq p1, v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v2, v1, v3}, Landroid/graphics/PathMeasure;->setPath(Landroid/graphics/Path;Z)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lxm/k;->l:Lxm/j;

    .line 24
    .line 25
    :cond_1
    invoke-virtual {v2}, Landroid/graphics/PathMeasure;->getLength()F

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    mul-float/2addr p2, p1

    .line 30
    iget-object v0, p0, Lxm/k;->i:[F

    .line 31
    .line 32
    iget-object v1, p0, Lxm/k;->j:[F

    .line 33
    .line 34
    invoke-virtual {v2, p2, v0, v1}, Landroid/graphics/PathMeasure;->getPosTan(F[F[F)Z

    .line 35
    .line 36
    .line 37
    aget v2, v0, v3

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    aget v0, v0, v4

    .line 41
    .line 42
    iget-object p0, p0, Lxm/k;->h:Landroid/graphics/PointF;

    .line 43
    .line 44
    invoke-virtual {p0, v2, v0}, Landroid/graphics/PointF;->set(FF)V

    .line 45
    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    cmpg-float v0, p2, v0

    .line 49
    .line 50
    if-gez v0, :cond_2

    .line 51
    .line 52
    aget p1, v1, v3

    .line 53
    .line 54
    mul-float/2addr p1, p2

    .line 55
    aget v0, v1, v4

    .line 56
    .line 57
    mul-float/2addr v0, p2

    .line 58
    invoke-virtual {p0, p1, v0}, Landroid/graphics/PointF;->offset(FF)V

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    :cond_2
    cmpl-float v0, p2, p1

    .line 63
    .line 64
    if-lez v0, :cond_3

    .line 65
    .line 66
    aget v0, v1, v3

    .line 67
    .line 68
    sub-float/2addr p2, p1

    .line 69
    mul-float/2addr v0, p2

    .line 70
    aget p1, v1, v4

    .line 71
    .line 72
    mul-float/2addr p1, p2

    .line 73
    invoke-virtual {p0, v0, p1}, Landroid/graphics/PointF;->offset(FF)V

    .line 74
    .line 75
    .line 76
    :cond_3
    return-object p0
.end method
