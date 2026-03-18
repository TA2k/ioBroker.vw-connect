.class public final Lc3/c;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc3/e;


# instance fields
.field public r:Lay0/k;

.field public s:Lc3/u;


# virtual methods
.method public final F(Lc3/u;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lc3/c;->s:Lc3/u;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Lc3/c;->s:Lc3/u;

    .line 10
    .line 11
    iget-object p0, p0, Lc3/c;->r:Lay0/k;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method
