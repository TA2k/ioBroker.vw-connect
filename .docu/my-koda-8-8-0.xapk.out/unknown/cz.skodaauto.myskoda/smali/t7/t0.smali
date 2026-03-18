.class public Lt7/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:I

.field public d:I

.field public e:I

.field public f:I

.field public g:Z

.field public h:Z

.field public i:Lhr/h0;

.field public j:Lhr/h0;

.field public k:Lhr/h0;

.field public l:I

.field public m:I

.field public n:Lhr/h0;

.field public o:Lt7/s0;

.field public p:Lhr/h0;

.field public q:Z

.field public r:I

.field public s:Ljava/util/HashMap;

.field public t:Ljava/util/HashSet;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const v0, 0x7fffffff

    .line 5
    .line 6
    .line 7
    iput v0, p0, Lt7/t0;->a:I

    .line 8
    .line 9
    iput v0, p0, Lt7/t0;->b:I

    .line 10
    .line 11
    iput v0, p0, Lt7/t0;->c:I

    .line 12
    .line 13
    iput v0, p0, Lt7/t0;->d:I

    .line 14
    .line 15
    iput v0, p0, Lt7/t0;->e:I

    .line 16
    .line 17
    iput v0, p0, Lt7/t0;->f:I

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    iput-boolean v1, p0, Lt7/t0;->g:Z

    .line 21
    .line 22
    iput-boolean v1, p0, Lt7/t0;->h:Z

    .line 23
    .line 24
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 25
    .line 26
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 27
    .line 28
    iput-object v2, p0, Lt7/t0;->i:Lhr/h0;

    .line 29
    .line 30
    iput-object v2, p0, Lt7/t0;->j:Lhr/h0;

    .line 31
    .line 32
    iput-object v2, p0, Lt7/t0;->k:Lhr/h0;

    .line 33
    .line 34
    iput v0, p0, Lt7/t0;->l:I

    .line 35
    .line 36
    iput v0, p0, Lt7/t0;->m:I

    .line 37
    .line 38
    iput-object v2, p0, Lt7/t0;->n:Lhr/h0;

    .line 39
    .line 40
    sget-object v0, Lt7/s0;->a:Lt7/s0;

    .line 41
    .line 42
    iput-object v0, p0, Lt7/t0;->o:Lt7/s0;

    .line 43
    .line 44
    iput-object v2, p0, Lt7/t0;->p:Lhr/h0;

    .line 45
    .line 46
    iput-boolean v1, p0, Lt7/t0;->q:Z

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    iput v0, p0, Lt7/t0;->r:I

    .line 50
    .line 51
    new-instance v0, Ljava/util/HashMap;

    .line 52
    .line 53
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 54
    .line 55
    .line 56
    iput-object v0, p0, Lt7/t0;->s:Ljava/util/HashMap;

    .line 57
    .line 58
    new-instance v0, Ljava/util/HashSet;

    .line 59
    .line 60
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 61
    .line 62
    .line 63
    iput-object v0, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public a()Lt7/u0;
    .locals 1

    .line 1
    new-instance v0, Lt7/u0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lt7/u0;-><init>(Lt7/t0;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public b(I)Lt7/t0;
    .locals 2

    .line 1
    iget-object v0, p0, Lt7/t0;->s:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

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
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lt7/r0;

    .line 22
    .line 23
    iget-object v1, v1, Lt7/r0;->a:Lt7/q0;

    .line 24
    .line 25
    iget v1, v1, Lt7/q0;->c:I

    .line 26
    .line 27
    if-ne v1, p1, :cond_0

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    return-object p0
.end method

.method public final c(Lt7/u0;)V
    .locals 2

    .line 1
    iget v0, p1, Lt7/u0;->a:I

    .line 2
    .line 3
    iput v0, p0, Lt7/t0;->a:I

    .line 4
    .line 5
    iget v0, p1, Lt7/u0;->b:I

    .line 6
    .line 7
    iput v0, p0, Lt7/t0;->b:I

    .line 8
    .line 9
    iget v0, p1, Lt7/u0;->c:I

    .line 10
    .line 11
    iput v0, p0, Lt7/t0;->c:I

    .line 12
    .line 13
    iget v0, p1, Lt7/u0;->d:I

    .line 14
    .line 15
    iput v0, p0, Lt7/t0;->d:I

    .line 16
    .line 17
    iget v0, p1, Lt7/u0;->e:I

    .line 18
    .line 19
    iput v0, p0, Lt7/t0;->e:I

    .line 20
    .line 21
    iget v0, p1, Lt7/u0;->f:I

    .line 22
    .line 23
    iput v0, p0, Lt7/t0;->f:I

    .line 24
    .line 25
    iget-boolean v0, p1, Lt7/u0;->g:Z

    .line 26
    .line 27
    iput-boolean v0, p0, Lt7/t0;->g:Z

    .line 28
    .line 29
    iget-boolean v0, p1, Lt7/u0;->h:Z

    .line 30
    .line 31
    iput-boolean v0, p0, Lt7/t0;->h:Z

    .line 32
    .line 33
    iget-object v0, p1, Lt7/u0;->i:Lhr/h0;

    .line 34
    .line 35
    iput-object v0, p0, Lt7/t0;->i:Lhr/h0;

    .line 36
    .line 37
    iget-object v0, p1, Lt7/u0;->j:Lhr/h0;

    .line 38
    .line 39
    iput-object v0, p0, Lt7/t0;->j:Lhr/h0;

    .line 40
    .line 41
    iget-object v0, p1, Lt7/u0;->k:Lhr/h0;

    .line 42
    .line 43
    iput-object v0, p0, Lt7/t0;->k:Lhr/h0;

    .line 44
    .line 45
    iget v0, p1, Lt7/u0;->l:I

    .line 46
    .line 47
    iput v0, p0, Lt7/t0;->l:I

    .line 48
    .line 49
    iget v0, p1, Lt7/u0;->m:I

    .line 50
    .line 51
    iput v0, p0, Lt7/t0;->m:I

    .line 52
    .line 53
    iget-object v0, p1, Lt7/u0;->n:Lhr/h0;

    .line 54
    .line 55
    iput-object v0, p0, Lt7/t0;->n:Lhr/h0;

    .line 56
    .line 57
    iget-object v0, p1, Lt7/u0;->o:Lt7/s0;

    .line 58
    .line 59
    iput-object v0, p0, Lt7/t0;->o:Lt7/s0;

    .line 60
    .line 61
    iget-object v0, p1, Lt7/u0;->p:Lhr/h0;

    .line 62
    .line 63
    iput-object v0, p0, Lt7/t0;->p:Lhr/h0;

    .line 64
    .line 65
    iget-boolean v0, p1, Lt7/u0;->q:Z

    .line 66
    .line 67
    iput-boolean v0, p0, Lt7/t0;->q:Z

    .line 68
    .line 69
    iget v0, p1, Lt7/u0;->r:I

    .line 70
    .line 71
    iput v0, p0, Lt7/t0;->r:I

    .line 72
    .line 73
    new-instance v0, Ljava/util/HashSet;

    .line 74
    .line 75
    iget-object v1, p1, Lt7/u0;->t:Lhr/k0;

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 78
    .line 79
    .line 80
    iput-object v0, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 81
    .line 82
    new-instance v0, Ljava/util/HashMap;

    .line 83
    .line 84
    iget-object p1, p1, Lt7/u0;->s:Lhr/c1;

    .line 85
    .line 86
    invoke-direct {v0, p1}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p0, Lt7/t0;->s:Ljava/util/HashMap;

    .line 90
    .line 91
    return-void
.end method

.method public d()Lt7/t0;
    .locals 1

    .line 1
    const/4 v0, -0x3

    .line 2
    iput v0, p0, Lt7/t0;->r:I

    .line 3
    .line 4
    return-object p0
.end method

.method public e(Lt7/r0;)Lt7/t0;
    .locals 2

    .line 1
    iget-object v0, p1, Lt7/r0;->a:Lt7/q0;

    .line 2
    .line 3
    iget v1, v0, Lt7/q0;->c:I

    .line 4
    .line 5
    invoke-virtual {p0, v1}, Lt7/t0;->b(I)Lt7/t0;

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lt7/t0;->s:Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v1, v0, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public f()Lt7/t0;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/String;

    .line 3
    .line 4
    invoke-virtual {p0, v0}, Lt7/t0;->g([Ljava/lang/String;)Lt7/t0;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public varargs g([Ljava/lang/String;)Lt7/t0;
    .locals 5

    .line 1
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v1, p1

    .line 6
    const/4 v2, 0x0

    .line 7
    move v3, v2

    .line 8
    :goto_0
    if-ge v3, v1, :cond_0

    .line 9
    .line 10
    aget-object v4, p1, v3

    .line 11
    .line 12
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-static {v4}, Lw7/w;->E(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {v0, v4}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    add-int/lit8 v3, v3, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v0}, Lhr/e0;->i()Lhr/x0;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lt7/t0;->p:Lhr/h0;

    .line 30
    .line 31
    iput-boolean v2, p0, Lt7/t0;->q:Z

    .line 32
    .line 33
    return-object p0
.end method

.method public h()Lt7/t0;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lt7/t0;->q:Z

    .line 3
    .line 4
    return-object p0
.end method

.method public i(IZ)Lt7/t0;
    .locals 0

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget-object p2, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    iget-object p2, p0, Lt7/t0;->t:Ljava/util/HashSet;

    .line 14
    .line 15
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p2, p1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    return-object p0
.end method
