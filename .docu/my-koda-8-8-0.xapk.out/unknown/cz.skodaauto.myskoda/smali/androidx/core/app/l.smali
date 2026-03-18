.class public final Landroidx/core/app/l;
.super Landroid/app/job/JobServiceEngine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/core/app/h;


# instance fields
.field public final a:Landroidx/core/app/o;

.field public final b:Ljava/lang/Object;

.field public c:Landroid/app/job/JobParameters;


# direct methods
.method public constructor <init>(Landroidx/core/app/o;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Landroid/app/job/JobServiceEngine;-><init>(Landroid/app/Service;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/core/app/l;->b:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Landroidx/core/app/l;->a:Landroidx/core/app/o;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final onStartJob(Landroid/app/job/JobParameters;)Z
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/core/app/l;->c:Landroid/app/job/JobParameters;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/core/app/l;->a:Landroidx/core/app/o;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-virtual {p0, p1}, Landroidx/core/app/o;->ensureProcessorRunningLocked(Z)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0
.end method

.method public final onStopJob(Landroid/app/job/JobParameters;)Z
    .locals 2

    .line 1
    iget-object p1, p0, Landroidx/core/app/l;->a:Landroidx/core/app/o;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroidx/core/app/o;->doStopCurrentWork()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iget-object v0, p0, Landroidx/core/app/l;->b:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    const/4 v1, 0x0

    .line 11
    :try_start_0
    iput-object v1, p0, Landroidx/core/app/l;->c:Landroid/app/job/JobParameters;

    .line 12
    .line 13
    monitor-exit v0

    .line 14
    return p1

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method
