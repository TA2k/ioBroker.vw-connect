.class public final Lxf0/j3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:D

.field public final b:D

.field public final c:J

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;


# direct methods
.method public constructor <init>(DDJZLjava/lang/String;Ljava/lang/String;I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p10, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-wide/high16 p3, 0x4059000000000000L    # 100.0

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p10, 0x10

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move-object p8, v1

    .line 13
    :cond_1
    and-int/lit8 p10, p10, 0x20

    .line 14
    .line 15
    if-eqz p10, :cond_2

    .line 16
    .line 17
    move-object p9, v1

    .line 18
    :cond_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-wide p1, p0, Lxf0/j3;->a:D

    .line 22
    .line 23
    iput-wide p3, p0, Lxf0/j3;->b:D

    .line 24
    .line 25
    iput-wide p5, p0, Lxf0/j3;->c:J

    .line 26
    .line 27
    iput-boolean p7, p0, Lxf0/j3;->d:Z

    .line 28
    .line 29
    iput-object p8, p0, Lxf0/j3;->e:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p9, p0, Lxf0/j3;->f:Ljava/lang/String;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lxf0/j3;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lxf0/j3;

    .line 12
    .line 13
    iget-wide v3, p0, Lxf0/j3;->a:D

    .line 14
    .line 15
    iget-wide v5, p1, Lxf0/j3;->a:D

    .line 16
    .line 17
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-wide v3, p0, Lxf0/j3;->b:D

    .line 25
    .line 26
    iget-wide v5, p1, Lxf0/j3;->b:D

    .line 27
    .line 28
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-wide v3, p0, Lxf0/j3;->c:J

    .line 36
    .line 37
    iget-wide v5, p1, Lxf0/j3;->c:J

    .line 38
    .line 39
    invoke-static {v3, v4, v5, v6}, Le3/s;->c(JJ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-boolean v1, p0, Lxf0/j3;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Lxf0/j3;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lxf0/j3;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lxf0/j3;->e:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object p0, p0, Lxf0/j3;->f:Ljava/lang/String;

    .line 65
    .line 66
    iget-object p1, p1, Lxf0/j3;->f:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-nez p0, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-wide v0, p0, Lxf0/j3;->a:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-wide v2, p0, Lxf0/j3;->b:D

    .line 11
    .line 12
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sget v2, Le3/s;->j:I

    .line 17
    .line 18
    iget-wide v2, p0, Lxf0/j3;->c:J

    .line 19
    .line 20
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean v2, p0, Lxf0/j3;->d:Z

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    iget-object v3, p0, Lxf0/j3;->e:Ljava/lang/String;

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    move v3, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_0
    add-int/2addr v0, v3

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-object p0, p0, Lxf0/j3;->f:Ljava/lang/String;

    .line 44
    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    :goto_1
    add-int/2addr v0, v2

    .line 53
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Lxf0/j3;->c:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Le3/s;->i(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "SimpleGaugeData(value="

    .line 8
    .line 9
    const-string v2, ", maxValue="

    .line 10
    .line 11
    iget-wide v3, p0, Lxf0/j3;->a:D

    .line 12
    .line 13
    invoke-static {v1, v2, v3, v4}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-wide v2, p0, Lxf0/j3;->b:D

    .line 18
    .line 19
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v2, ", gaugeColor="

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ", isSkeletonLoading="

    .line 31
    .line 32
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-boolean v0, p0, Lxf0/j3;->d:Z

    .line 36
    .line 37
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v0, ", infoLinePrimary="

    .line 41
    .line 42
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v0, p0, Lxf0/j3;->e:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v0, ", infoLineSecondary="

    .line 51
    .line 52
    const-string v2, ")"

    .line 53
    .line 54
    iget-object p0, p0, Lxf0/j3;->f:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v1, v0, p0, v2}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method
