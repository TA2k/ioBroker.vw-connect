.class public final Lhz0/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/i;
.implements Lhz0/i1;
.implements Llz0/c;


# instance fields
.field public final a:Lhz0/h0;

.field public final b:Lhz0/j0;


# direct methods
.method public constructor <init>(Lhz0/h0;Lhz0/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 5
    .line 6
    iput-object p2, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 4
    .line 5
    iput-object p1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 6
    .line 7
    return-void
.end method

.method public final C()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 4
    .line 5
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 6
    .line 7
    return-object p0
.end method

.method public final D(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final E()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final copy()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lhz0/i0;

    .line 2
    .line 3
    iget-object v1, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 4
    .line 5
    invoke-virtual {v1}, Lhz0/h0;->a()Lhz0/h0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 10
    .line 11
    invoke-virtual {p0}, Lhz0/j0;->a()Lhz0/j0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-direct {v0, v1, p0}, Lhz0/i0;-><init>(Lhz0/h0;Lhz0/j0;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final d()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final e()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final f()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final g(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final i(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final j(Lhz0/h;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->c:Lhz0/h;

    .line 4
    .line 5
    return-void
.end method

.method public final k()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final l(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final m(Liz0/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lhz0/i1;->m(Liz0/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final n(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final o()Lhz0/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->c:Lhz0/h;

    .line 4
    .line 5
    return-object p0
.end method

.method public final q(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final r(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final s(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 4
    .line 5
    iput-object p1, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 6
    .line 7
    return-void
.end method

.method public final t()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final u(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final v()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 4
    .line 5
    iget-object p0, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 6
    .line 7
    return-object p0
.end method

.method public final w()Liz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->b:Lhz0/j0;

    .line 2
    .line 3
    invoke-interface {p0}, Lhz0/i1;->w()Liz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final y()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final z()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/i0;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method
