.class public final Lk1/w0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:F

.field public s:F

.field public t:Z


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 2

    .line 1
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget p3, p2, Lt3/e1;->d:I

    .line 6
    .line 7
    iget p4, p2, Lt3/e1;->e:I

    .line 8
    .line 9
    new-instance v0, Li40/j0;

    .line 10
    .line 11
    const/16 v1, 0x16

    .line 12
    .line 13
    invoke-direct {v0, v1, p0, p2}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 17
    .line 18
    invoke-interface {p1, p3, p4, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
