.class public final Lwq/e;
.super Llp/nd;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Lwq/u;FF)V
    .locals 2

    .line 1
    mul-float/2addr p3, p2

    .line 2
    const/high16 p0, 0x43340000    # 180.0f

    .line 3
    .line 4
    const/high16 p2, 0x42b40000    # 90.0f

    .line 5
    .line 6
    invoke-virtual {p1, p3, p0, p2}, Lwq/u;->d(FFF)V

    .line 7
    .line 8
    .line 9
    float-to-double v0, p2

    .line 10
    invoke-static {v0, v1}, Ljava/lang/Math;->toRadians(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    float-to-double p2, p3

    .line 19
    mul-double/2addr v0, p2

    .line 20
    double-to-float p0, v0

    .line 21
    const/4 v0, 0x0

    .line 22
    float-to-double v0, v0

    .line 23
    invoke-static {v0, v1}, Ljava/lang/Math;->toRadians(D)D

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    mul-double/2addr v0, p2

    .line 32
    double-to-float p2, v0

    .line 33
    invoke-virtual {p1, p0, p2}, Lwq/u;->c(FF)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
