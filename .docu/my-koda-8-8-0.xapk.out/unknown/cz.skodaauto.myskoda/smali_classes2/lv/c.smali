.class public final Llv/c;
.super Lnv/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhv/a;


# instance fields
.field public final i:Z


# direct methods
.method public constructor <init>(Lhv/b;Llv/e;Ljava/util/concurrent/Executor;Ljp/vg;)V
    .locals 6

    .line 1
    invoke-direct {p0, p2, p3}, Lnv/b;-><init>(Leb/j0;Ljava/util/concurrent/Executor;)V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Llv/a;->c()Z

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    iput-boolean p2, p0, Llv/c;->i:Z

    .line 9
    .line 10
    new-instance p0, Landroidx/lifecycle/c1;

    .line 11
    .line 12
    const/16 p3, 0xc

    .line 13
    .line 14
    invoke-direct {p0, p3}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Llv/a;->a(Lhv/b;)Ljp/pg;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 22
    .line 23
    new-instance p1, Ljp/mc;

    .line 24
    .line 25
    invoke-direct {p1, p0}, Ljp/mc;-><init>(Landroidx/lifecycle/c1;)V

    .line 26
    .line 27
    .line 28
    new-instance p0, Lin/z1;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    if-eqz p2, :cond_0

    .line 34
    .line 35
    sget-object p2, Ljp/zb;->f:Ljp/zb;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    sget-object p2, Ljp/zb;->e:Ljp/zb;

    .line 39
    .line 40
    :goto_0
    iput-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 41
    .line 42
    iput-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 43
    .line 44
    new-instance v2, Lbb/g0;

    .line 45
    .line 46
    const/4 p1, 0x1

    .line 47
    invoke-direct {v2, p0, p1}, Lbb/g0;-><init>(Lin/z1;I)V

    .line 48
    .line 49
    .line 50
    sget-object v3, Ljp/bc;->o:Ljp/bc;

    .line 51
    .line 52
    invoke-virtual {p4}, Ljp/vg;->c()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    new-instance v0, Ld6/z0;

    .line 57
    .line 58
    const/4 v5, 0x1

    .line 59
    move-object v1, p4

    .line 60
    invoke-direct/range {v0 .. v5}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    sget-object p0, Lfv/l;->d:Lfv/l;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method


# virtual methods
.method public final a()[Ljo/d;
    .locals 2

    .line 1
    iget-boolean p0, p0, Llv/c;->i:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lfv/h;->a:[Ljo/d;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x1

    .line 9
    new-array p0, p0, [Ljo/d;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    sget-object v1, Lfv/h;->b:Ljo/d;

    .line 13
    .line 14
    aput-object v1, p0, v0

    .line 15
    .line 16
    return-object p0
.end method

.method public final declared-synchronized close()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-super {p0}, Lnv/b;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    .line 5
    monitor-exit p0

    .line 6
    return-void

    .line 7
    :catchall_0
    move-exception v0

    .line 8
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 9
    throw v0
.end method
