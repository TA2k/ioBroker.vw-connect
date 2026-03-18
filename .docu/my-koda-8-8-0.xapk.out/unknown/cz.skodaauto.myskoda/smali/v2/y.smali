.class public final Lv2/y;
.super Lv2/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lv2/f;

.field public final f:Z

.field public final g:Z

.field public h:Lay0/k;

.field public final i:J


# direct methods
.method public constructor <init>(Lv2/f;Lay0/k;ZZ)V
    .locals 3

    .line 1
    sget-object v0, Lv2/l;->a:Luu/r;

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    sget-object v2, Lv2/j;->h:Lv2/j;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1, v2}, Lv2/f;-><init>(JLv2/j;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lv2/y;->e:Lv2/f;

    .line 11
    .line 12
    iput-boolean p3, p0, Lv2/y;->f:Z

    .line 13
    .line 14
    iput-boolean p4, p0, Lv2/y;->g:Z

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1}, Lv2/f;->e()Lay0/k;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    if-nez p1, :cond_1

    .line 23
    .line 24
    :cond_0
    sget-object p1, Lv2/l;->j:Lv2/a;

    .line 25
    .line 26
    iget-object p1, p1, Lv2/b;->e:Lay0/k;

    .line 27
    .line 28
    :cond_1
    invoke-static {p2, p1, p3}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lv2/y;->h:Lay0/k;

    .line 33
    .line 34
    invoke-static {}, Lt2/c;->d()J

    .line 35
    .line 36
    .line 37
    move-result-wide p1

    .line 38
    iput-wide p1, p0, Lv2/y;->i:J

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv2/f;->c:Z

    .line 3
    .line 4
    iget-boolean v0, p0, Lv2/y;->g:Z

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lv2/y;->e:Lv2/f;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lv2/f;->c()V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public final d()Lv2/j;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv2/f;->d()Lv2/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final e()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/y;->h:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv2/f;->f()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final g()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public final i()Lay0/k;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final k()V
    .locals 0

    .line 1
    invoke-static {}, Lv2/p;->h()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0
.end method

.method public final l()V
    .locals 0

    .line 1
    invoke-static {}, Lv2/p;->h()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    throw p0
.end method

.method public final m()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv2/f;->m()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final n(Lv2/t;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1}, Lv2/f;->n(Lv2/t;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final u(Lay0/k;)Lv2/f;
    .locals 2

    .line 1
    iget-object v0, p0, Lv2/y;->h:Lay0/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {p1, v0, v1}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iget-boolean v0, p0, Lv2/y;->f:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const/4 v0, 0x0

    .line 17
    invoke-virtual {p0, v0}, Lv2/f;->u(Lay0/k;)Lv2/f;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-static {p0, p1, v1}, Lv2/l;->h(Lv2/f;Lay0/k;Z)Lv2/f;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    invoke-virtual {p0}, Lv2/y;->v()Lv2/f;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0, p1}, Lv2/f;->u(Lay0/k;)Lv2/f;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public final v()Lv2/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/y;->e:Lv2/f;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lv2/l;->j:Lv2/a;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method
