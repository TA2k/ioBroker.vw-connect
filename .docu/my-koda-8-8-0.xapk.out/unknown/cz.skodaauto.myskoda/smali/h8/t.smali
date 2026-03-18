.class public final Lh8/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/z;
.implements Lh8/y;


# instance fields
.field public final d:Lh8/b0;

.field public final e:J

.field public final f:Lk8/e;

.field public g:Lh8/a;

.field public h:Lh8/z;

.field public i:Lh8/y;

.field public j:J


# direct methods
.method public constructor <init>(Lh8/b0;Lk8/e;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/t;->d:Lh8/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/t;->f:Lk8/e;

    .line 7
    .line 8
    iput-wide p3, p0, Lh8/t;->e:J

    .line 9
    .line 10
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Lh8/t;->j:J

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0}, Lh8/z0;->a()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public final b(JLa8/r1;)J
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2, p3}, Lh8/z;->b(JLa8/r1;)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public final c(Lh8/z;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lh8/t;->i:Lh8/y;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p1, p0}, Lh8/y;->c(Lh8/z;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final d(J)J
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Lh8/z;->d(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lh8/z0;->e()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final f(Lh8/z0;)V
    .locals 1

    .line 1
    check-cast p1, Lh8/z;

    .line 2
    .line 3
    iget-object p1, p0, Lh8/t;->i:Lh8/y;

    .line 4
    .line 5
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-interface {p1, p0}, Lh8/y;->f(Lh8/z0;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0}, Lh8/z;->g()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public final h(Lh8/y;J)V
    .locals 2

    .line 1
    iput-object p1, p0, Lh8/t;->i:Lh8/y;

    .line 2
    .line 3
    iget-object p1, p0, Lh8/t;->h:Lh8/z;

    .line 4
    .line 5
    if-eqz p1, :cond_1

    .line 6
    .line 7
    iget-wide p2, p0, Lh8/t;->j:J

    .line 8
    .line 9
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    cmp-long v0, p2, v0

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-wide p2, p0, Lh8/t;->e:J

    .line 20
    .line 21
    :goto_0
    invoke-interface {p1, p0, p2, p3}, Lh8/z;->h(Lh8/y;J)V

    .line 22
    .line 23
    .line 24
    :cond_1
    return-void
.end method

.method public final i(Lh8/b0;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lh8/t;->j:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long v2, v0, v2

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-wide v0, p0, Lh8/t;->e:J

    .line 14
    .line 15
    :goto_0
    iget-object v2, p0, Lh8/t;->g:Lh8/a;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    iget-object v3, p0, Lh8/t;->f:Lk8/e;

    .line 21
    .line 22
    invoke-virtual {v2, p1, v3, v0, v1}, Lh8/a;->a(Lh8/b0;Lk8/e;J)Lh8/z;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lh8/t;->h:Lh8/z;

    .line 27
    .line 28
    iget-object v2, p0, Lh8/t;->i:Lh8/y;

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-interface {p1, p0, v0, v1}, Lh8/z;->h(Lh8/y;J)V

    .line 33
    .line 34
    .line 35
    :cond_1
    return-void
.end method

.method public final k()V
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lh8/z;->k()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object p0, p0, Lh8/t;->g:Lh8/a;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lh8/a;->i()V

    .line 14
    .line 15
    .line 16
    :cond_1
    return-void
.end method

.method public final l(J)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Lh8/z;->l(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final n()Lh8/e1;
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0}, Lh8/z;->n()Lh8/e1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final o([Lj8/q;[Z[Lh8/y0;[ZJ)J
    .locals 6

    .line 1
    iget-wide v0, p0, Lh8/t;->j:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long v4, v0, v2

    .line 9
    .line 10
    if-eqz v4, :cond_0

    .line 11
    .line 12
    iget-wide v4, p0, Lh8/t;->e:J

    .line 13
    .line 14
    cmp-long v4, p5, v4

    .line 15
    .line 16
    if-nez v4, :cond_0

    .line 17
    .line 18
    move-wide p5, v0

    .line 19
    :cond_0
    iput-wide v2, p0, Lh8/t;->j:J

    .line 20
    .line 21
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 22
    .line 23
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface/range {p0 .. p6}, Lh8/z;->o([Lj8/q;[Z[Lh8/y0;[ZJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide p0

    .line 29
    return-wide p0
.end method

.method public final p(La8/u0;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lh8/z0;->p(La8/u0;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final r()J
    .locals 2

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0}, Lh8/z0;->r()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public final s(J)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/t;->h:Lh8/z;

    .line 2
    .line 3
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Lh8/z0;->s(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
