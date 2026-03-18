.class public final Lin/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public c:F

.field public d:F

.field public e:Z


# direct methods
.method public constructor <init>(FFFF)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lin/s1;->c:F

    .line 6
    .line 7
    iput v0, p0, Lin/s1;->d:F

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p0, Lin/s1;->e:Z

    .line 11
    .line 12
    iput p1, p0, Lin/s1;->a:F

    .line 13
    .line 14
    iput p2, p0, Lin/s1;->b:F

    .line 15
    .line 16
    mul-float p1, p3, p3

    .line 17
    .line 18
    mul-float p2, p4, p4

    .line 19
    .line 20
    add-float/2addr p2, p1

    .line 21
    float-to-double p1, p2

    .line 22
    invoke-static {p1, p2}, Ljava/lang/Math;->sqrt(D)D

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    const-wide/16 v0, 0x0

    .line 27
    .line 28
    cmpl-double v0, p1, v0

    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    float-to-double v0, p3

    .line 33
    div-double/2addr v0, p1

    .line 34
    double-to-float p3, v0

    .line 35
    iput p3, p0, Lin/s1;->c:F

    .line 36
    .line 37
    float-to-double p3, p4

    .line 38
    div-double/2addr p3, p1

    .line 39
    double-to-float p1, p3

    .line 40
    iput p1, p0, Lin/s1;->d:F

    .line 41
    .line 42
    :cond_0
    return-void
.end method


# virtual methods
.method public final a(FF)V
    .locals 4

    .line 1
    iget v0, p0, Lin/s1;->a:F

    .line 2
    .line 3
    sub-float/2addr p1, v0

    .line 4
    iget v0, p0, Lin/s1;->b:F

    .line 5
    .line 6
    sub-float/2addr p2, v0

    .line 7
    mul-float v0, p1, p1

    .line 8
    .line 9
    mul-float v1, p2, p2

    .line 10
    .line 11
    add-float/2addr v1, v0

    .line 12
    float-to-double v0, v1

    .line 13
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    const-wide/16 v2, 0x0

    .line 18
    .line 19
    cmpl-double v2, v0, v2

    .line 20
    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    float-to-double v2, p1

    .line 24
    div-double/2addr v2, v0

    .line 25
    double-to-float p1, v2

    .line 26
    float-to-double v2, p2

    .line 27
    div-double/2addr v2, v0

    .line 28
    double-to-float p2, v2

    .line 29
    :cond_0
    iget v0, p0, Lin/s1;->c:F

    .line 30
    .line 31
    neg-float v1, v0

    .line 32
    cmpl-float v1, p1, v1

    .line 33
    .line 34
    if-nez v1, :cond_1

    .line 35
    .line 36
    iget v1, p0, Lin/s1;->d:F

    .line 37
    .line 38
    neg-float v1, v1

    .line 39
    cmpl-float v1, p2, v1

    .line 40
    .line 41
    if-nez v1, :cond_1

    .line 42
    .line 43
    const/4 v0, 0x1

    .line 44
    iput-boolean v0, p0, Lin/s1;->e:Z

    .line 45
    .line 46
    neg-float p2, p2

    .line 47
    iput p2, p0, Lin/s1;->c:F

    .line 48
    .line 49
    iput p1, p0, Lin/s1;->d:F

    .line 50
    .line 51
    return-void

    .line 52
    :cond_1
    add-float/2addr v0, p1

    .line 53
    iput v0, p0, Lin/s1;->c:F

    .line 54
    .line 55
    iget p1, p0, Lin/s1;->d:F

    .line 56
    .line 57
    add-float/2addr p1, p2

    .line 58
    iput p1, p0, Lin/s1;->d:F

    .line 59
    .line 60
    return-void
.end method

.method public final b(Lin/s1;)V
    .locals 4

    .line 1
    iget v0, p1, Lin/s1;->c:F

    .line 2
    .line 3
    iget v1, p0, Lin/s1;->c:F

    .line 4
    .line 5
    neg-float v2, v1

    .line 6
    cmpl-float v2, v0, v2

    .line 7
    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    iget v2, p1, Lin/s1;->d:F

    .line 11
    .line 12
    iget v3, p0, Lin/s1;->d:F

    .line 13
    .line 14
    neg-float v3, v3

    .line 15
    cmpl-float v3, v2, v3

    .line 16
    .line 17
    if-nez v3, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lin/s1;->e:Z

    .line 21
    .line 22
    neg-float v0, v2

    .line 23
    iput v0, p0, Lin/s1;->c:F

    .line 24
    .line 25
    iget p1, p1, Lin/s1;->c:F

    .line 26
    .line 27
    iput p1, p0, Lin/s1;->d:F

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    add-float/2addr v1, v0

    .line 31
    iput v1, p0, Lin/s1;->c:F

    .line 32
    .line 33
    iget v0, p0, Lin/s1;->d:F

    .line 34
    .line 35
    iget p1, p1, Lin/s1;->d:F

    .line 36
    .line 37
    add-float/2addr v0, p1

    .line 38
    iput v0, p0, Lin/s1;->d:F

    .line 39
    .line 40
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lin/s1;->a:F

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ","

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v2, p0, Lin/s1;->b:F

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v2, " "

    .line 24
    .line 25
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v2, p0, Lin/s1;->c:F

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget p0, p0, Lin/s1;->d:F

    .line 37
    .line 38
    const-string v1, ")"

    .line 39
    .line 40
    invoke-static {p0, v1, v0}, Lkx/a;->g(FLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
