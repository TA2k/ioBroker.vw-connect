.class public final Lg1/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:J

.field public final c:Z


# direct methods
.method public constructor <init>(JJZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lg1/r1;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lg1/r1;->b:J

    .line 7
    .line 8
    iput-boolean p5, p0, Lg1/r1;->c:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lg1/r1;)Lg1/r1;
    .locals 7

    .line 1
    new-instance v0, Lg1/r1;

    .line 2
    .line 3
    iget-wide v1, p0, Lg1/r1;->a:J

    .line 4
    .line 5
    iget-wide v3, p1, Lg1/r1;->a:J

    .line 6
    .line 7
    invoke-static {v1, v2, v3, v4}, Ld3/b;->h(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    iget-wide v3, p0, Lg1/r1;->b:J

    .line 12
    .line 13
    iget-wide v5, p1, Lg1/r1;->b:J

    .line 14
    .line 15
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->max(JJ)J

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    iget-boolean v5, p0, Lg1/r1;->c:Z

    .line 20
    .line 21
    invoke-direct/range {v0 .. v5}, Lg1/r1;-><init>(JJZ)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lg1/r1;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lg1/r1;

    .line 10
    .line 11
    iget-wide v0, p0, Lg1/r1;->a:J

    .line 12
    .line 13
    iget-wide v2, p1, Lg1/r1;->a:J

    .line 14
    .line 15
    invoke-static {v0, v1, v2, v3}, Ld3/b;->c(JJ)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-wide v0, p0, Lg1/r1;->b:J

    .line 23
    .line 24
    iget-wide v2, p1, Lg1/r1;->b:J

    .line 25
    .line 26
    cmp-long v0, v0, v2

    .line 27
    .line 28
    if-eqz v0, :cond_3

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_3
    iget-boolean p0, p0, Lg1/r1;->c:Z

    .line 32
    .line 33
    iget-boolean p1, p1, Lg1/r1;->c:Z

    .line 34
    .line 35
    if-eq p0, p1, :cond_4

    .line 36
    .line 37
    :goto_0
    const/4 p0, 0x0

    .line 38
    return p0

    .line 39
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 40
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-wide v0, p0, Lg1/r1;->a:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

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
    iget-wide v2, p0, Lg1/r1;->b:J

    .line 11
    .line 12
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean p0, p0, Lg1/r1;->c:Z

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MouseWheelScrollDelta(value="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lg1/r1;->a:J

    .line 9
    .line 10
    invoke-static {v1, v2}, Ld3/b;->j(J)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", timeMillis="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-wide v1, p0, Lg1/r1;->b:J

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", shouldApplyImmediately="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-boolean p0, p0, Lg1/r1;->c:Z

    .line 33
    .line 34
    const/16 v1, 0x29

    .line 35
    .line 36
    invoke-static {v0, p0, v1}, Lf2/m0;->l(Ljava/lang/StringBuilder;ZC)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
