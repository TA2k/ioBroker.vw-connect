.class public final Ley0/d;
.super Ley0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# virtual methods
.method public final a(I)I
    .locals 0

    .line 1
    sget-object p0, Ley0/e;->e:Ley0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ley0/a;->a(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()I
    .locals 0

    .line 1
    sget-object p0, Ley0/e;->e:Ley0/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ley0/a;->b()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c()J
    .locals 2

    .line 1
    sget-object p0, Ley0/e;->e:Ley0/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ley0/a;->c()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final d(JJ)J
    .locals 0

    .line 1
    const-wide/16 p0, 0x3e8

    .line 2
    .line 3
    sget-object p2, Ley0/e;->e:Ley0/a;

    .line 4
    .line 5
    const-wide/16 p3, 0x0

    .line 6
    .line 7
    invoke-virtual {p2, p3, p4, p0, p1}, Ley0/e;->d(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    return-wide p0
.end method

.method public final e()J
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method
