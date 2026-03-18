.class public final Li2/y0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/c2;
.implements Lv3/x1;


# instance fields
.field public r:Laa/o;

.field public s:Z


# virtual methods
.method public final J0()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final a0(Ld4/l;)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Li2/y0;->s:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Li2/y0;->r:Laa/o;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Laa/o;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Li2/z0;->a:Li2/z0;

    .line 2
    .line 3
    return-object p0
.end method
