.class public interface abstract Lc1/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/j;


# virtual methods
.method public a(Lc1/b2;)Lc1/d2;
    .locals 0

    .line 1
    new-instance p1, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    invoke-direct {p1, p0}, Lcom/google/firebase/messaging/w;-><init>(Lc1/b0;)V

    .line 4
    .line 5
    .line 6
    return-object p1
.end method

.method public b(FFF)F
    .locals 6

    .line 1
    invoke-interface {p0, p1, p2, p3}, Lc1/b0;->e(FFF)J

    .line 2
    .line 3
    .line 4
    move-result-wide v1

    .line 5
    move-object v0, p0

    .line 6
    move v3, p1

    .line 7
    move v4, p2

    .line 8
    move v5, p3

    .line 9
    invoke-interface/range {v0 .. v5}, Lc1/b0;->d(JFFF)F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public abstract c(JFFF)F
.end method

.method public abstract d(JFFF)F
.end method

.method public abstract e(FFF)J
.end method
