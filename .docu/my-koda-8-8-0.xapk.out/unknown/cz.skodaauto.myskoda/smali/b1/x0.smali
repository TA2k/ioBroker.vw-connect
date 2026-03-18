.class public final Lb1/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/c0;


# instance fields
.field public d:F

.field public e:F


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(FF)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Lb1/x0;->d:F

    .line 4
    iput p2, p0, Lb1/x0;->e:F

    return-void
.end method


# virtual methods
.method public C()F
    .locals 0

    .line 1
    iget p0, p0, Lb1/x0;->d:F

    .line 2
    .line 3
    return p0
.end method

.method public K(F)J
    .locals 2

    .line 1
    iget v0, p0, Lb1/x0;->d:F

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    div-float/2addr v0, p1

    .line 8
    float-to-double v0, v0

    .line 9
    invoke-static {v0, v1}, Ljava/lang/Math;->log(D)D

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    double-to-float p1, v0

    .line 14
    const/high16 v0, 0x447a0000    # 1000.0f

    .line 15
    .line 16
    mul-float/2addr p1, v0

    .line 17
    iget p0, p0, Lb1/x0;->e:F

    .line 18
    .line 19
    div-float/2addr p1, p0

    .line 20
    float-to-long p0, p1

    .line 21
    const-wide/32 v0, 0xf4240

    .line 22
    .line 23
    .line 24
    mul-long/2addr p0, v0

    .line 25
    return-wide p0
.end method

.method public M(FF)F
    .locals 4

    .line 1
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lb1/x0;->d:F

    .line 6
    .line 7
    cmpg-float v0, v0, v1

    .line 8
    .line 9
    if-gtz v0, :cond_0

    .line 10
    .line 11
    return p1

    .line 12
    :cond_0
    div-float/2addr v1, p2

    .line 13
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    float-to-double v0, v0

    .line 18
    invoke-static {v0, v1}, Ljava/lang/Math;->log(D)D

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    iget p0, p0, Lb1/x0;->e:F

    .line 23
    .line 24
    float-to-double v2, p0

    .line 25
    div-double/2addr v0, v2

    .line 26
    const/16 v2, 0x3e8

    .line 27
    .line 28
    int-to-double v2, v2

    .line 29
    mul-double/2addr v0, v2

    .line 30
    div-float v2, p2, p0

    .line 31
    .line 32
    sub-float/2addr p1, v2

    .line 33
    div-float/2addr p2, p0

    .line 34
    float-to-double v2, p0

    .line 35
    mul-double/2addr v2, v0

    .line 36
    const/high16 p0, 0x447a0000    # 1000.0f

    .line 37
    .line 38
    float-to-double v0, p0

    .line 39
    div-double/2addr v2, v0

    .line 40
    invoke-static {v2, v3}, Ljava/lang/Math;->exp(D)D

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    double-to-float p0, v0

    .line 45
    mul-float/2addr p2, p0

    .line 46
    add-float/2addr p2, p1

    .line 47
    return p2
.end method

.method public O(JF)F
    .locals 2

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    long-to-float p1, p1

    .line 6
    const/high16 p2, 0x447a0000    # 1000.0f

    .line 7
    .line 8
    div-float/2addr p1, p2

    .line 9
    iget p0, p0, Lb1/x0;->e:F

    .line 10
    .line 11
    mul-float/2addr p1, p0

    .line 12
    float-to-double p0, p1

    .line 13
    invoke-static {p0, p1}, Ljava/lang/Math;->exp(D)D

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    double-to-float p0, p0

    .line 18
    mul-float/2addr p3, p0

    .line 19
    return p3
.end method

.method public S(JFF)F
    .locals 2

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    iget p0, p0, Lb1/x0;->e:F

    .line 6
    .line 7
    div-float v0, p4, p0

    .line 8
    .line 9
    sub-float/2addr p3, v0

    .line 10
    div-float/2addr p4, p0

    .line 11
    long-to-float p1, p1

    .line 12
    mul-float/2addr p0, p1

    .line 13
    const/high16 p1, 0x447a0000    # 1000.0f

    .line 14
    .line 15
    div-float/2addr p0, p1

    .line 16
    float-to-double p0, p0

    .line 17
    invoke-static {p0, p1}, Ljava/lang/Math;->exp(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    double-to-float p0, p0

    .line 22
    mul-float/2addr p4, p0

    .line 23
    add-float/2addr p4, p3

    .line 24
    return p4
.end method

.method public a(F)Lb1/w0;
    .locals 9

    .line 1
    invoke-virtual {p0, p1}, Lb1/x0;->b(F)D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sget v2, Lb1/y0;->a:F

    .line 6
    .line 7
    float-to-double v2, v2

    .line 8
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 9
    .line 10
    sub-double v4, v2, v4

    .line 11
    .line 12
    new-instance v6, Lb1/w0;

    .line 13
    .line 14
    iget v7, p0, Lb1/x0;->d:F

    .line 15
    .line 16
    iget p0, p0, Lb1/x0;->e:F

    .line 17
    .line 18
    mul-float/2addr v7, p0

    .line 19
    float-to-double v7, v7

    .line 20
    div-double/2addr v2, v4

    .line 21
    mul-double/2addr v2, v0

    .line 22
    invoke-static {v2, v3}, Ljava/lang/Math;->exp(D)D

    .line 23
    .line 24
    .line 25
    move-result-wide v2

    .line 26
    mul-double/2addr v2, v7

    .line 27
    double-to-float p0, v2

    .line 28
    div-double/2addr v0, v4

    .line 29
    invoke-static {v0, v1}, Ljava/lang/Math;->exp(D)D

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    const-wide v2, 0x408f400000000000L    # 1000.0

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    mul-double/2addr v0, v2

    .line 39
    double-to-long v0, v0

    .line 40
    invoke-direct {v6, v0, v1, p1, p0}, Lb1/w0;-><init>(JFF)V

    .line 41
    .line 42
    .line 43
    return-object v6
.end method

.method public b(F)D
    .locals 2

    .line 1
    sget-object v0, Lb1/b;->a:[F

    .line 2
    .line 3
    iget v0, p0, Lb1/x0;->d:F

    .line 4
    .line 5
    iget p0, p0, Lb1/x0;->e:F

    .line 6
    .line 7
    mul-float/2addr v0, p0

    .line 8
    const p0, 0x3eb33333    # 0.35f

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    mul-float/2addr p1, p0

    .line 16
    float-to-double p0, p1

    .line 17
    float-to-double v0, v0

    .line 18
    div-double/2addr p0, v0

    .line 19
    invoke-static {p0, p1}, Ljava/lang/Math;->log(D)D

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0
.end method
