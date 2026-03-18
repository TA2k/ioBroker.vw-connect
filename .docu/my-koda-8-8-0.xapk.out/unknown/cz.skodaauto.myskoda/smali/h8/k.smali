.class public abstract Lh8/k;
.super Lh8/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ljava/util/HashMap;

.field public i:Landroid/os/Handler;

.field public j:Ly7/z;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lh8/a;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 2

    .line 1
    iget-object p0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lh8/j;

    .line 22
    .line 23
    iget-object v1, v0, Lh8/j;->a:Lh8/a;

    .line 24
    .line 25
    iget-object v0, v0, Lh8/j;->b:Lh8/h;

    .line 26
    .line 27
    invoke-virtual {v1, v0}, Lh8/a;->b(Lh8/c0;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object p0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lh8/j;

    .line 22
    .line 23
    iget-object v1, v0, Lh8/j;->a:Lh8/a;

    .line 24
    .line 25
    iget-object v0, v0, Lh8/j;->b:Lh8/h;

    .line 26
    .line 27
    invoke-virtual {v1, v0}, Lh8/a;->d(Lh8/c0;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void
.end method

.method public i()V
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lh8/j;

    .line 22
    .line 23
    iget-object v0, v0, Lh8/j;->a:Lh8/a;

    .line 24
    .line 25
    invoke-virtual {v0}, Lh8/a;->i()V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    return-void
.end method

.method public o()V
    .locals 4

    .line 1
    iget-object p0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lh8/j;

    .line 22
    .line 23
    iget-object v2, v1, Lh8/j;->a:Lh8/a;

    .line 24
    .line 25
    iget-object v3, v1, Lh8/j;->c:Lh8/i;

    .line 26
    .line 27
    iget-object v1, v1, Lh8/j;->b:Lh8/h;

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Lh8/a;->n(Lh8/c0;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v2, v3}, Lh8/a;->q(Lh8/h0;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2, v3}, Lh8/a;->p(Ld8/g;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {p0}, Ljava/util/HashMap;->clear()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public abstract s(Ljava/lang/Object;Lh8/b0;)Lh8/b0;
.end method

.method public t(JLjava/lang/Object;)J
    .locals 0

    .line 1
    return-wide p1
.end method

.method public u(ILjava/lang/Object;)I
    .locals 0

    .line 1
    return p1
.end method

.method public abstract v(Ljava/lang/Object;Lh8/a;Lt7/p0;)V
.end method

.method public final w(Ljava/lang/Object;Lh8/a;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lh8/k;->h:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    xor-int/lit8 v1, v1, 0x1

    .line 8
    .line 9
    invoke-static {v1}, Lw7/a;->c(Z)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lh8/h;

    .line 13
    .line 14
    invoke-direct {v1, p0, p1}, Lh8/h;-><init>(Lh8/k;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lh8/i;

    .line 18
    .line 19
    invoke-direct {v2, p0, p1}, Lh8/i;-><init>(Lh8/k;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance v3, Lh8/j;

    .line 23
    .line 24
    invoke-direct {v3, p2, v1, v2}, Lh8/j;-><init>(Lh8/a;Lh8/h;Lh8/i;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lh8/k;->i:Landroid/os/Handler;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    iget-object v0, p2, Lh8/a;->c:Ld8/f;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    iget-object v0, v0, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 44
    .line 45
    new-instance v3, Lh8/g0;

    .line 46
    .line 47
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object p1, v3, Lh8/g0;->a:Landroid/os/Handler;

    .line 51
    .line 52
    iput-object v2, v3, Lh8/g0;->b:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v0, v3}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    iget-object p1, p0, Lh8/k;->i:Landroid/os/Handler;

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    iget-object p1, p2, Lh8/a;->d:Ld8/f;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    iget-object p1, p1, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 68
    .line 69
    new-instance v0, Ld8/e;

    .line 70
    .line 71
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 72
    .line 73
    .line 74
    iput-object v2, v0, Ld8/e;->a:Ljava/lang/Object;

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    iget-object p1, p0, Lh8/k;->j:Ly7/z;

    .line 80
    .line 81
    iget-object v0, p0, Lh8/a;->g:Lb8/k;

    .line 82
    .line 83
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, v1, p1, v0}, Lh8/a;->j(Lh8/c0;Ly7/z;Lb8/k;)V

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Lh8/a;->b:Ljava/util/HashSet;

    .line 90
    .line 91
    invoke-virtual {p0}, Ljava/util/HashSet;->isEmpty()Z

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    if-eqz p0, :cond_0

    .line 96
    .line 97
    invoke-virtual {p2, v1}, Lh8/a;->b(Lh8/c0;)V

    .line 98
    .line 99
    .line 100
    :cond_0
    return-void
.end method
