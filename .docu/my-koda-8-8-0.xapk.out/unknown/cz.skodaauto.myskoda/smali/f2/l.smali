.class public final Lf2/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:J

.field public final c:J

.field public final d:J


# direct methods
.method public constructor <init>(JJJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lf2/l;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lf2/l;->b:J

    .line 7
    .line 8
    iput-wide p5, p0, Lf2/l;->c:J

    .line 9
    .line 10
    iput-wide p7, p0, Lf2/l;->d:J

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_6

    .line 7
    .line 8
    const-class v2, Lf2/l;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    if-eq v2, v3, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    check-cast p1, Lf2/l;

    .line 18
    .line 19
    iget-wide v2, p0, Lf2/l;->a:J

    .line 20
    .line 21
    iget-wide v4, p1, Lf2/l;->a:J

    .line 22
    .line 23
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-nez v2, :cond_2

    .line 28
    .line 29
    return v1

    .line 30
    :cond_2
    iget-wide v2, p0, Lf2/l;->b:J

    .line 31
    .line 32
    iget-wide v4, p1, Lf2/l;->b:J

    .line 33
    .line 34
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-nez v2, :cond_3

    .line 39
    .line 40
    return v1

    .line 41
    :cond_3
    iget-wide v2, p0, Lf2/l;->c:J

    .line 42
    .line 43
    iget-wide v4, p1, Lf2/l;->c:J

    .line 44
    .line 45
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-nez v2, :cond_4

    .line 50
    .line 51
    return v1

    .line 52
    :cond_4
    iget-wide v2, p0, Lf2/l;->d:J

    .line 53
    .line 54
    iget-wide p0, p1, Lf2/l;->d:J

    .line 55
    .line 56
    invoke-static {v2, v3, p0, p1}, Le3/s;->c(JJ)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_5

    .line 61
    .line 62
    return v1

    .line 63
    :cond_5
    return v0

    .line 64
    :cond_6
    :goto_0
    return v1
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    sget v0, Le3/s;->j:I

    .line 2
    .line 3
    iget-wide v0, p0, Lf2/l;->a:J

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-wide v2, p0, Lf2/l;->b:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-wide v2, p0, Lf2/l;->c:J

    .line 19
    .line 20
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-wide v1, p0, Lf2/l;->d:J

    .line 25
    .line 26
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    add-int/2addr p0, v0

    .line 31
    return p0
.end method
