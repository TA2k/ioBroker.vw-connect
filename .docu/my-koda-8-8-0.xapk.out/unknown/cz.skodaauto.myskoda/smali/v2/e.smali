.class public final Lv2/e;
.super Lv2/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lay0/k;

.field public f:I


# direct methods
.method public constructor <init>(JLv2/j;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lv2/f;-><init>(JLv2/j;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lv2/e;->e:Lay0/k;

    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    iput p1, p0, Lv2/e;->f:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lv2/e;->l()V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Lv2/f;->c:Z

    .line 10
    .line 11
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    invoke-virtual {p0}, Lv2/f;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0

    .line 21
    throw p0

    .line 22
    :cond_0
    return-void
.end method

.method public final e()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/e;->e:Lay0/k;

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
    .locals 1

    .line 1
    iget v0, p0, Lv2/e;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lv2/e;->f:I

    .line 6
    .line 7
    return-void
.end method

.method public final l()V
    .locals 1

    .line 1
    iget v0, p0, Lv2/e;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Lv2/e;->f:I

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lv2/f;->a()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
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
    invoke-static {p0}, Lv2/l;->d(Lv2/f;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lv2/d;

    .line 5
    .line 6
    iget-wide v1, p0, Lv2/f;->b:J

    .line 7
    .line 8
    iget-object v3, p0, Lv2/f;->a:Lv2/j;

    .line 9
    .line 10
    iget-object v4, p0, Lv2/e;->e:Lay0/k;

    .line 11
    .line 12
    const/4 v5, 0x1

    .line 13
    invoke-static {p1, v4, v5}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    move-object v5, p0

    .line 18
    invoke-direct/range {v0 .. v5}, Lv2/d;-><init>(JLv2/j;Lay0/k;Lv2/f;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method
