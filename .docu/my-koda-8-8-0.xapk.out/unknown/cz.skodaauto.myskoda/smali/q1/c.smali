.class public final Lq1/c;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public r:Lq1/b;


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final P0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lq1/c;->r:Lq1/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, v0, Lq1/b;->a:Ln2/b;

    .line 6
    .line 7
    invoke-virtual {v1, p0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v1, v0, Lq1/b;->a:Ln2/b;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    iput-object v0, p0, Lq1/c;->r:Lq1/b;

    .line 18
    .line 19
    return-void
.end method

.method public final Q0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lq1/c;->r:Lq1/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v1, "null cannot be cast to non-null type androidx.compose.foundation.relocation.BringIntoViewRequesterImpl"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, v0, Lq1/b;->a:Ln2/b;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
