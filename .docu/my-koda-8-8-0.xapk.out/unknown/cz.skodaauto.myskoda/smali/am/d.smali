.class public final Lam/d;
.super Lam/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final x:Lzl/h;


# direct methods
.method public constructor <init>(Lzl/h;Lx2/e;Lt3/k;Le3/m;Lzl/n;)V
    .locals 7

    .line 1
    const/high16 v3, 0x3f800000    # 1.0f

    .line 2
    .line 3
    const/4 v5, 0x1

    .line 4
    move-object v0, p0

    .line 5
    move-object v1, p2

    .line 6
    move-object v2, p3

    .line 7
    move-object v4, p4

    .line 8
    move-object v6, p5

    .line 9
    invoke-direct/range {v0 .. v6}, Lam/b;-><init>(Lx2/e;Lt3/k;FLe3/m;ZLzl/n;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lam/d;->x:Lzl/h;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final P0()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lam/d;->x:Lzl/h;

    .line 6
    .line 7
    iput-object v0, p0, Lzl/h;->o:Lvy0/b0;

    .line 8
    .line 9
    invoke-virtual {p0}, Lzl/h;->c()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final Q0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lam/d;->x:Lzl/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lzl/h;->h()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final R0()V
    .locals 1

    .line 1
    iget-object p0, p0, Lam/d;->x:Lzl/h;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Lzl/h;->m(Lzl/b;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final Y0()Li3/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lam/d;->x:Lzl/h;

    .line 2
    .line 3
    return-object p0
.end method
