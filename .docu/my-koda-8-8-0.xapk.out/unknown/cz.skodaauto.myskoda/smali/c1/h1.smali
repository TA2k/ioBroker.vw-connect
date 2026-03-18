.class public final Lc1/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/d2;


# instance fields
.field public final d:Lc1/d2;

.field public final e:J


# direct methods
.method public constructor <init>(Lc1/d2;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/h1;->d:Lc1/d2;

    .line 5
    .line 6
    iput-wide p2, p0, Lc1/h1;->e:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 3

    .line 1
    iget-wide v0, p0, Lc1/h1;->e:J

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-gez v2, :cond_0

    .line 6
    .line 7
    return-object p5

    .line 8
    :cond_0
    iget-object p0, p0, Lc1/h1;->d:Lc1/d2;

    .line 9
    .line 10
    sub-long/2addr p1, v0

    .line 11
    invoke-interface/range {p0 .. p5}, Lc1/d2;->D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/h1;->d:Lc1/d2;

    .line 2
    .line 3
    invoke-interface {p0}, Lc1/d2;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    instance-of v0, p1, Lc1/h1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lc1/h1;

    .line 8
    .line 9
    iget-wide v2, p1, Lc1/h1;->e:J

    .line 10
    .line 11
    iget-wide v4, p0, Lc1/h1;->e:J

    .line 12
    .line 13
    cmp-long v0, v2, v4

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-object p1, p1, Lc1/h1;->d:Lc1/d2;

    .line 18
    .line 19
    iget-object p0, p0, Lc1/h1;->d:Lc1/d2;

    .line 20
    .line 21
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_1
    return v1
.end method

.method public final h(Lc1/p;Lc1/p;Lc1/p;)J
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/h1;->d:Lc1/d2;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2, p3}, Lc1/d2;->h(Lc1/p;Lc1/p;Lc1/p;)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-wide v0, p0, Lc1/h1;->e:J

    .line 8
    .line 9
    add-long/2addr p1, v0

    .line 10
    return-wide p1
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lc1/h1;->d:Lc1/d2;

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
    iget-wide v1, p0, Lc1/h1;->e:J

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 3

    .line 1
    iget-wide v0, p0, Lc1/h1;->e:J

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-gez v2, :cond_0

    .line 6
    .line 7
    return-object p3

    .line 8
    :cond_0
    iget-object p0, p0, Lc1/h1;->d:Lc1/d2;

    .line 9
    .line 10
    sub-long/2addr p1, v0

    .line 11
    invoke-interface/range {p0 .. p5}, Lc1/d2;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
