.class public final Lfp0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lfp0/a;

.field public final b:Lqr0/d;

.field public final c:Lfp0/b;

.field public final d:Lfp0/b;

.field public final e:Lqr0/d;

.field public final f:Ljava/time/OffsetDateTime;

.field public final g:Z

.field public final h:Z


# direct methods
.method public constructor <init>(Lfp0/a;Lqr0/d;Lfp0/b;Lfp0/b;Lqr0/d;Ljava/time/OffsetDateTime;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfp0/e;->a:Lfp0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lfp0/e;->b:Lqr0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lfp0/e;->c:Lfp0/b;

    .line 9
    .line 10
    iput-object p4, p0, Lfp0/e;->d:Lfp0/b;

    .line 11
    .line 12
    iput-object p5, p0, Lfp0/e;->e:Lqr0/d;

    .line 13
    .line 14
    iput-object p6, p0, Lfp0/e;->f:Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    const-wide p3, 0x408f400000000000L    # 1000.0

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    const/4 p5, 0x0

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    iget-wide v0, p2, Lqr0/d;->a:D

    .line 26
    .line 27
    div-double/2addr v0, p3

    .line 28
    const-wide v2, 0x40a2c00000000000L    # 2400.0

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmpg-double p6, v0, v2

    .line 34
    .line 35
    if-gez p6, :cond_0

    .line 36
    .line 37
    move p6, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move p6, p5

    .line 40
    :goto_0
    iput-boolean p6, p0, Lfp0/e;->g:Z

    .line 41
    .line 42
    if-eqz p2, :cond_2

    .line 43
    .line 44
    iget-wide v0, p2, Lqr0/d;->a:D

    .line 45
    .line 46
    div-double/2addr v0, p3

    .line 47
    const-wide/high16 p2, 0x3ff0000000000000L    # 1.0

    .line 48
    .line 49
    cmpg-double p2, v0, p2

    .line 50
    .line 51
    if-gez p2, :cond_1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move p1, p5

    .line 55
    :goto_1
    move p5, p1

    .line 56
    :cond_2
    iput-boolean p5, p0, Lfp0/e;->h:Z

    .line 57
    .line 58
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lfp0/e;

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
    check-cast p1, Lfp0/e;

    .line 12
    .line 13
    iget-object v1, p0, Lfp0/e;->a:Lfp0/a;

    .line 14
    .line 15
    iget-object v3, p1, Lfp0/e;->a:Lfp0/a;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lfp0/e;->b:Lqr0/d;

    .line 21
    .line 22
    iget-object v3, p1, Lfp0/e;->b:Lqr0/d;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lfp0/e;->c:Lfp0/b;

    .line 32
    .line 33
    iget-object v3, p1, Lfp0/e;->c:Lfp0/b;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lfp0/e;->d:Lfp0/b;

    .line 43
    .line 44
    iget-object v3, p1, Lfp0/e;->d:Lfp0/b;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lfp0/e;->e:Lqr0/d;

    .line 54
    .line 55
    iget-object v3, p1, Lfp0/e;->e:Lqr0/d;

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
    iget-object p0, p0, Lfp0/e;->f:Ljava/time/OffsetDateTime;

    .line 65
    .line 66
    iget-object p1, p1, Lfp0/e;->f:Ljava/time/OffsetDateTime;

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
    .locals 5

    .line 1
    iget-object v0, p0, Lfp0/e;->a:Lfp0/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iget-object v2, p0, Lfp0/e;->b:Lqr0/d;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    move v2, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-wide v2, v2, Lqr0/d;->a:D

    .line 17
    .line 18
    invoke-static {v2, v3}, Ljava/lang/Double;->hashCode(D)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    :goto_0
    add-int/2addr v0, v2

    .line 23
    mul-int/lit8 v0, v0, 0x1f

    .line 24
    .line 25
    iget-object v2, p0, Lfp0/e;->c:Lfp0/b;

    .line 26
    .line 27
    invoke-virtual {v2}, Lfp0/b;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    add-int/2addr v2, v0

    .line 32
    mul-int/lit8 v2, v2, 0x1f

    .line 33
    .line 34
    iget-object v0, p0, Lfp0/e;->d:Lfp0/b;

    .line 35
    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    move v0, v1

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    invoke-virtual {v0}, Lfp0/b;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    :goto_1
    add-int/2addr v2, v0

    .line 45
    mul-int/lit8 v2, v2, 0x1f

    .line 46
    .line 47
    iget-object v0, p0, Lfp0/e;->e:Lqr0/d;

    .line 48
    .line 49
    if-nez v0, :cond_2

    .line 50
    .line 51
    move v0, v1

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    iget-wide v3, v0, Lqr0/d;->a:D

    .line 54
    .line 55
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    :goto_2
    add-int/2addr v2, v0

    .line 60
    mul-int/lit8 v2, v2, 0x1f

    .line 61
    .line 62
    iget-object p0, p0, Lfp0/e;->f:Ljava/time/OffsetDateTime;

    .line 63
    .line 64
    if-nez p0, :cond_3

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    :goto_3
    add-int/2addr v2, v1

    .line 72
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RangeIceStatus(carType="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lfp0/e;->a:Lfp0/a;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", adBlueRange="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lfp0/e;->b:Lqr0/d;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", primaryEngine="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lfp0/e;->c:Lfp0/b;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", secondaryEngine="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lfp0/e;->d:Lfp0/b;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", totalRange="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lfp0/e;->e:Lqr0/d;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", carCapturedTimestamp="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lfp0/e;->f:Ljava/time/OffsetDateTime;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ")"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
