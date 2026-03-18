.class public interface abstract Lc1/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/g2;


# virtual methods
.method public h(Lc1/p;Lc1/p;Lc1/p;)J
    .locals 0

    .line 1
    invoke-interface {p0}, Lc1/f2;->u()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-interface {p0}, Lc1/f2;->y()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    add-int/2addr p0, p1

    .line 10
    int-to-long p0, p0

    .line 11
    const-wide/32 p2, 0xf4240

    .line 12
    .line 13
    .line 14
    mul-long/2addr p0, p2

    .line 15
    return-wide p0
.end method

.method public abstract u()I
.end method

.method public abstract y()I
.end method
