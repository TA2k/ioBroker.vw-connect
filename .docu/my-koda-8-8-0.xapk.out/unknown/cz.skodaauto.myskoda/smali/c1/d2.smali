.class public interface abstract Lc1/d2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
.end method

.method public P(Lc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 6

    .line 1
    invoke-interface {p0, p1, p2, p3}, Lc1/d2;->h(Lc1/p;Lc1/p;Lc1/p;)J

    .line 2
    .line 3
    .line 4
    move-result-wide v1

    .line 5
    move-object v0, p0

    .line 6
    move-object v3, p1

    .line 7
    move-object v4, p2

    .line 8
    move-object v5, p3

    .line 9
    invoke-interface/range {v0 .. v5}, Lc1/d2;->D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public abstract a()Z
.end method

.method public abstract h(Lc1/p;Lc1/p;Lc1/p;)J
.end method

.method public abstract t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
.end method
