.class public final Ll2/r;
.super Ll2/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:Z

.field public final c:Z

.field public d:Ljava/util/HashSet;

.field public final e:Ljava/util/LinkedHashSet;

.field public final f:Ll2/j1;

.field public final synthetic g:Ll2/t;


# direct methods
.method public constructor <init>(Ll2/t;JZZLh6/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/r;->g:Ll2/t;

    .line 5
    .line 6
    iput-wide p2, p0, Ll2/r;->a:J

    .line 7
    .line 8
    iput-boolean p4, p0, Ll2/r;->b:Z

    .line 9
    .line 10
    iput-boolean p5, p0, Ll2/r;->c:Z

    .line 11
    .line 12
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 13
    .line 14
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Ll2/r;->e:Ljava/util/LinkedHashSet;

    .line 18
    .line 19
    sget-object p1, Lt2/g;->g:Lt2/g;

    .line 20
    .line 21
    sget-object p2, Ll2/x0;->g:Ll2/x0;

    .line 22
    .line 23
    new-instance p3, Ll2/j1;

    .line 24
    .line 25
    invoke-direct {p3, p1, p2}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 26
    .line 27
    .line 28
    iput-object p3, p0, Ll2/r;->f:Ll2/j1;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a(Ll2/a0;Lay0/n;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ll2/x;->a(Ll2/a0;Lay0/n;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final b(Ll2/a0;Lt0/c;Lay0/n;)Landroidx/collection/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Ll2/x;->b(Ll2/a0;Lt0/c;Lay0/n;)Landroidx/collection/r0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final c()V
    .locals 1

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget v0, p0, Ll2/t;->A:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, -0x1

    .line 6
    .line 7
    iput v0, p0, Ll2/t;->A:I

    .line 8
    .line 9
    return-void
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/x;->d()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ll2/r;->b:Z

    .line 2
    .line 3
    return p0
.end method

.method public final f()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ll2/r;->c:Z

    .line 2
    .line 3
    return p0
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ll2/r;->a:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final h()Ll2/w;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->h:Ll2/a0;

    .line 4
    .line 5
    return-object p0
.end method

.method public final i()Ll2/p1;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ll2/p1;

    .line 8
    .line 9
    return-object p0
.end method

.method public final j()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/x;->j()Lpx0/g;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final k(Ll2/a0;)V
    .locals 2

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object v0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    iget-object v1, p0, Ll2/t;->h:Ll2/a0;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/x;->k(Ll2/a0;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ll2/x;->k(Ll2/a0;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final l(Ll2/a1;)Ll2/z0;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ll2/x;->l(Ll2/a1;)Ll2/z0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final m(Ll2/a0;Lt0/c;Landroidx/collection/r0;)Landroidx/collection/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Ll2/x;->m(Ll2/a0;Lt0/c;Landroidx/collection/r0;)Landroidx/collection/r0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final n(Ljava/util/Set;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ll2/r;->d:Ljava/util/HashSet;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/util/HashSet;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ll2/r;->d:Ljava/util/HashSet;

    .line 11
    .line 12
    :cond_0
    invoke-interface {v0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final o(Ll2/t;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->e:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final p(Ll2/u1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ll2/x;->p(Ll2/u1;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final q(Ll2/a0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ll2/x;->q(Ll2/a0;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final r()V
    .locals 1

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget v0, p0, Ll2/t;->A:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    iput v0, p0, Ll2/t;->A:I

    .line 8
    .line 9
    return-void
.end method

.method public final s(Ll2/o;)V
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/r;->d:Ljava/util/HashSet;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Ljava/util/Set;

    .line 20
    .line 21
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.ComposerImpl"

    .line 22
    .line 23
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    move-object v2, p1

    .line 27
    check-cast v2, Ll2/t;

    .line 28
    .line 29
    iget-object v2, v2, Ll2/t;->c:Ll2/f2;

    .line 30
    .line 31
    invoke-interface {v1, v2}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    iget-object p0, p0, Ll2/r;->e:Ljava/util/LinkedHashSet;

    .line 36
    .line 37
    invoke-static {p0}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0, p1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final t(Ll2/a0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r;->g:Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->b:Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ll2/x;->t(Ll2/a0;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final u()V
    .locals 6

    .line 1
    iget-object v0, p0, Ll2/r;->e:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_2

    .line 8
    .line 9
    iget-object p0, p0, Ll2/r;->d:Ljava/util/HashSet;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-eqz v4, :cond_0

    .line 38
    .line 39
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Ljava/util/Set;

    .line 44
    .line 45
    iget-object v5, v2, Ll2/t;->c:Ll2/f2;

    .line 46
    .line 47
    invoke-interface {v4, v5}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    invoke-interface {v0}, Ljava/util/Set;->clear()V

    .line 52
    .line 53
    .line 54
    :cond_2
    return-void
.end method
