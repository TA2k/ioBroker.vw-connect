.class public abstract Ll7/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/animation/Interpolator;


# instance fields
.field public final a:[F

.field public final b:F


# direct methods
.method public constructor <init>([F)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll7/b;->a:[F

    .line 5
    .line 6
    array-length p1, p1

    .line 7
    add-int/lit8 p1, p1, -0x1

    .line 8
    .line 9
    int-to-float p1, p1

    .line 10
    const/high16 v0, 0x3f800000    # 1.0f

    .line 11
    .line 12
    div-float/2addr v0, p1

    .line 13
    iput v0, p0, Ll7/b;->b:F

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final getInterpolation(F)F
    .locals 3

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    cmpl-float v1, p1, v0

    .line 4
    .line 5
    if-ltz v1, :cond_0

    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    cmpg-float v1, p1, v0

    .line 10
    .line 11
    if-gtz v1, :cond_1

    .line 12
    .line 13
    return v0

    .line 14
    :cond_1
    iget-object v0, p0, Ll7/b;->a:[F

    .line 15
    .line 16
    array-length v1, v0

    .line 17
    add-int/lit8 v1, v1, -0x1

    .line 18
    .line 19
    int-to-float v1, v1

    .line 20
    mul-float/2addr v1, p1

    .line 21
    float-to-int v1, v1

    .line 22
    array-length v2, v0

    .line 23
    add-int/lit8 v2, v2, -0x2

    .line 24
    .line 25
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    int-to-float v2, v1

    .line 30
    iget p0, p0, Ll7/b;->b:F

    .line 31
    .line 32
    mul-float/2addr v2, p0

    .line 33
    sub-float/2addr p1, v2

    .line 34
    div-float/2addr p1, p0

    .line 35
    aget p0, v0, v1

    .line 36
    .line 37
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    aget v0, v0, v1

    .line 40
    .line 41
    invoke-static {v0, p0, p1, p0}, La7/g0;->b(FFFF)F

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0
.end method
