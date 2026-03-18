.class public final Lt3/a1;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/x;


# instance fields
.field public r:Lay0/k;

.field public s:J


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final h(J)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lt3/a1;->s:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lt4/l;->a(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lt3/a1;->r:Lay0/k;

    .line 10
    .line 11
    new-instance v1, Lt4/l;

    .line 12
    .line 13
    invoke-direct {v1, p1, p2}, Lt4/l;-><init>(J)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    iput-wide p1, p0, Lt3/a1;->s:J

    .line 20
    .line 21
    :cond_0
    return-void
.end method
