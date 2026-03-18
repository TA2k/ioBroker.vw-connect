.class public final Lhz0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/i;
.implements Lhz0/i1;
.implements Lhz0/q1;
.implements Llz0/c;


# instance fields
.field public final a:Lhz0/h0;

.field public final b:Lhz0/j0;

.field public final c:Lhz0/k0;

.field public d:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lhz0/h0;Lhz0/j0;Lhz0/k0;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/q;->a:Lhz0/h0;

    .line 5
    .line 6
    iput-object p2, p0, Lhz0/q;->b:Lhz0/j0;

    .line 7
    .line 8
    iput-object p3, p0, Lhz0/q;->c:Lhz0/k0;

    .line 9
    .line 10
    iput-object p4, p0, Lhz0/q;->d:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final A(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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

.method public final B()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/k0;->c:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final C()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final F()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/k0;->a:Ljava/lang/Boolean;

    .line 4
    .line 5
    return-object p0
.end method

.method public final a()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/k0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final b(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/k0;->c:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final c(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/k0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final copy()Ljava/lang/Object;
    .locals 8

    .line 1
    new-instance v0, Lhz0/q;

    .line 2
    .line 3
    iget-object v1, p0, Lhz0/q;->a:Lhz0/h0;

    .line 4
    .line 5
    invoke-virtual {v1}, Lhz0/h0;->a()Lhz0/h0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v2, p0, Lhz0/q;->b:Lhz0/j0;

    .line 10
    .line 11
    invoke-virtual {v2}, Lhz0/j0;->a()Lhz0/j0;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    new-instance v3, Lhz0/k0;

    .line 16
    .line 17
    iget-object v4, p0, Lhz0/q;->c:Lhz0/k0;

    .line 18
    .line 19
    iget-object v5, v4, Lhz0/k0;->a:Ljava/lang/Boolean;

    .line 20
    .line 21
    iget-object v6, v4, Lhz0/k0;->b:Ljava/lang/Integer;

    .line 22
    .line 23
    iget-object v7, v4, Lhz0/k0;->c:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-object v4, v4, Lhz0/k0;->d:Ljava/lang/Integer;

    .line 26
    .line 27
    invoke-direct {v3, v5, v6, v7, v4}, Lhz0/k0;-><init>(Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lhz0/q;->d:Ljava/lang/String;

    .line 31
    .line 32
    invoke-direct {v0, v1, v2, v3, p0}, Lhz0/q;-><init>(Lhz0/h0;Lhz0/j0;Lhz0/k0;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method

.method public final d()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lhz0/q;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lhz0/q;

    .line 6
    .line 7
    iget-object v0, p1, Lhz0/q;->a:Lhz0/h0;

    .line 8
    .line 9
    iget-object v1, p0, Lhz0/q;->a:Lhz0/h0;

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p1, Lhz0/q;->b:Lhz0/j0;

    .line 18
    .line 19
    iget-object v1, p0, Lhz0/q;->b:Lhz0/j0;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget-object v0, p1, Lhz0/q;->c:Lhz0/k0;

    .line 28
    .line 29
    iget-object v1, p0, Lhz0/q;->c:Lhz0/k0;

    .line 30
    .line 31
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-object p1, p1, Lhz0/q;->d:Ljava/lang/String;

    .line 38
    .line 39
    iget-object p0, p0, Lhz0/q;->d:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_0

    .line 46
    .line 47
    const/4 p0, 0x1

    .line 48
    return p0

    .line 49
    :cond_0
    const/4 p0, 0x0

    .line 50
    return p0
.end method

.method public final f()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final h()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/k0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lhz0/q;->a:Lhz0/h0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lhz0/h0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lhz0/q;->b:Lhz0/j0;

    .line 8
    .line 9
    invoke-virtual {v1}, Lhz0/j0;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    xor-int/2addr v0, v1

    .line 14
    iget-object v1, p0, Lhz0/q;->c:Lhz0/k0;

    .line 15
    .line 16
    invoke-virtual {v1}, Lhz0/k0;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    xor-int/2addr v0, v1

    .line 21
    iget-object p0, p0, Lhz0/q;->d:Ljava/lang/String;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    :goto_0
    xor-int/2addr p0, v0

    .line 32
    return p0
.end method

.method public final i(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/j0;->c:Lhz0/h;

    .line 4
    .line 5
    return-object p0
.end method

.method public final p(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/k0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final q(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->b:Lhz0/j0;

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

.method public final x(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->c:Lhz0/k0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/k0;->a:Ljava/lang/Boolean;

    .line 4
    .line 5
    return-void
.end method

.method public final y()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

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
    iget-object p0, p0, Lhz0/q;->a:Lhz0/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method
