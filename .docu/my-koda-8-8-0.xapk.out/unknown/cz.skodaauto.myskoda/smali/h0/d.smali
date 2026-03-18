.class public final Lh0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/b0;


# instance fields
.field public final d:Lh0/b0;

.field public final e:Lh0/c;

.field public final f:Lh0/b;


# direct methods
.method public constructor <init>(Lh0/b0;Lh0/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/d;->d:Lh0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lh0/d;->e:Lh0/c;

    .line 7
    .line 8
    iget-object p2, p2, Lh0/c;->c:Lh0/t;

    .line 9
    .line 10
    new-instance v0, Lh0/b;

    .line 11
    .line 12
    invoke-interface {p1}, Lh0/b0;->g()Lh0/y;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p2}, Lh0/t;->r()V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, p1}, Lh0/b;-><init>(Lh0/y;)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lh0/d;->f:Lh0/b;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->e:Lh0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->b()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final c()Lh0/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->c()Lh0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final e(Lb0/z1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lb0/y1;->e(Lb0/z1;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final f(Lb0/z1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lb0/y1;->f(Lb0/z1;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final g()Lh0/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->f:Lh0/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Lh0/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->h()Lh0/t;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final i(Lh0/t;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh0/b0;->i(Lh0/t;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final j(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh0/b0;->j(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final k(Ljava/util/Collection;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh0/b0;->k(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final l()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->e:Lh0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(Lb0/z1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lb0/y1;->m(Lb0/z1;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final n()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->n()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o(Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh0/b0;->o(Ljava/util/ArrayList;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final p()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->p()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final q(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lh0/b0;->q(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final r(Lb0/z1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/d;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lb0/y1;->r(Lb0/z1;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
