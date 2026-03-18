.class public final Lv2/d;
.super Lv2/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lay0/k;

.field public final f:Lv2/f;


# direct methods
.method public constructor <init>(JLv2/j;Lay0/k;Lv2/f;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lv2/f;-><init>(JLv2/j;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lv2/d;->e:Lay0/k;

    .line 5
    .line 6
    iput-object p5, p0, Lv2/d;->f:Lv2/f;

    .line 7
    .line 8
    invoke-virtual {p5}, Lv2/f;->k()V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv2/d;->f:Lv2/f;

    .line 2
    .line 3
    iget-boolean v1, p0, Lv2/f;->c:Z

    .line 4
    .line 5
    if-nez v1, :cond_1

    .line 6
    .line 7
    iget-wide v1, p0, Lv2/f;->b:J

    .line 8
    .line 9
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 10
    .line 11
    .line 12
    move-result-wide v3

    .line 13
    cmp-long v1, v1, v3

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Lv2/f;->a()V

    .line 18
    .line 19
    .line 20
    :cond_0
    invoke-virtual {v0}, Lv2/f;->l()V

    .line 21
    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    iput-boolean v0, p0, Lv2/f;->c:Z

    .line 25
    .line 26
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    :try_start_0
    invoke-virtual {p0}, Lv2/f;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    monitor-exit v0

    .line 36
    throw p0

    .line 37
    :cond_1
    return-void
.end method

.method public final e()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/d;->e:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
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
    return-void
.end method

.method public final n(Lv2/t;)V
    .locals 0

    .line 1
    sget-object p0, Lv2/l;->a:Luu/r;

    .line 2
    .line 3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 4
    .line 5
    const-string p1, "Cannot modify a state object in a read-only snapshot"

    .line 6
    .line 7
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    throw p0
.end method

.method public final u(Lay0/k;)Lv2/f;
    .locals 6

    .line 1
    new-instance v0, Lv2/d;

    .line 2
    .line 3
    iget-wide v1, p0, Lv2/f;->b:J

    .line 4
    .line 5
    iget-object v3, p0, Lv2/f;->a:Lv2/j;

    .line 6
    .line 7
    iget-object v4, p0, Lv2/d;->e:Lay0/k;

    .line 8
    .line 9
    const/4 v5, 0x1

    .line 10
    invoke-static {p1, v4, v5}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 11
    .line 12
    .line 13
    move-result-object v4

    .line 14
    iget-object v5, p0, Lv2/d;->f:Lv2/f;

    .line 15
    .line 16
    invoke-direct/range {v0 .. v5}, Lv2/d;-><init>(JLv2/j;Lay0/k;Lv2/f;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method
