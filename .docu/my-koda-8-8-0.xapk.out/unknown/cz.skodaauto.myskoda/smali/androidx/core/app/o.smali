.class public abstract Landroidx/core/app/o;
.super Landroid/app/Service;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final DEBUG:Z = false

.field static final TAG:Ljava/lang/String; = "JobIntentService"

.field static final sClassWorkEnqueuer:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Landroid/content/ComponentName;",
            "Landroidx/core/app/n;",
            ">;"
        }
    .end annotation
.end field

.field static final sLock:Ljava/lang/Object;


# instance fields
.field final mCompatQueue:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroidx/core/app/i;",
            ">;"
        }
    .end annotation
.end field

.field mCompatWorkEnqueuer:Landroidx/core/app/n;

.field mCurProcessor:Landroidx/core/app/g;

.field mDestroyed:Z

.field mInterruptIfStopped:Z

.field mJobImpl:Landroidx/core/app/h;

.field mStopped:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/core/app/o;->sLock:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Landroidx/core/app/o;->sClassWorkEnqueuer:Ljava/util/HashMap;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Landroidx/core/app/o;->mInterruptIfStopped:Z

    .line 6
    .line 7
    iput-boolean v0, p0, Landroidx/core/app/o;->mStopped:Z

    .line 8
    .line 9
    iput-boolean v0, p0, Landroidx/core/app/o;->mDestroyed:Z

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 13
    .line 14
    return-void
.end method

.method public static enqueueWork(Landroid/content/Context;Landroid/content/ComponentName;ILandroid/content/Intent;)V
    .locals 2

    if-eqz p3, :cond_0

    .line 2
    sget-object v0, Landroidx/core/app/o;->sLock:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x1

    .line 3
    :try_start_0
    invoke-static {p0, p1, v1, p2}, Landroidx/core/app/o;->getWorkEnqueuer(Landroid/content/Context;Landroid/content/ComponentName;ZI)Landroidx/core/app/n;

    move-result-object p0

    .line 4
    invoke-virtual {p0, p2}, Landroidx/core/app/n;->a(I)V

    .line 5
    check-cast p0, Landroidx/core/app/m;

    .line 6
    iget-object p1, p0, Landroidx/core/app/m;->d:Landroid/app/job/JobScheduler;

    iget-object p0, p0, Landroidx/core/app/m;->c:Landroid/app/job/JobInfo;

    new-instance p2, Landroid/app/job/JobWorkItem;

    invoke-direct {p2, p3}, Landroid/app/job/JobWorkItem;-><init>(Landroid/content/Intent;)V

    invoke-virtual {p1, p0, p2}, Landroid/app/job/JobScheduler;->enqueue(Landroid/app/job/JobInfo;Landroid/app/job/JobWorkItem;)I

    .line 7
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "work must not be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static enqueueWork(Landroid/content/Context;Ljava/lang/Class;ILandroid/content/Intent;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Ljava/lang/Class<",
            "*>;I",
            "Landroid/content/Intent;",
            ")V"
        }
    .end annotation

    .line 1
    new-instance v0, Landroid/content/ComponentName;

    invoke-direct {v0, p0, p1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-static {p0, v0, p2, p3}, Landroidx/core/app/o;->enqueueWork(Landroid/content/Context;Landroid/content/ComponentName;ILandroid/content/Intent;)V

    return-void
.end method

.method public static getWorkEnqueuer(Landroid/content/Context;Landroid/content/ComponentName;ZI)Landroidx/core/app/n;
    .locals 2

    .line 1
    sget-object v0, Landroidx/core/app/o;->sClassWorkEnqueuer:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Landroidx/core/app/n;

    .line 8
    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    new-instance p2, Landroidx/core/app/m;

    .line 14
    .line 15
    invoke-direct {p2, p0, p1, p3}, Landroidx/core/app/m;-><init>(Landroid/content/Context;Landroid/content/ComponentName;I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p2

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    const-string p1, "Can\'t be here without a job id"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    return-object v1
.end method


# virtual methods
.method public dequeueWork()Landroidx/core/app/j;
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/core/app/o;->mJobImpl:Landroidx/core/app/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    check-cast v0, Landroidx/core/app/l;

    .line 7
    .line 8
    iget-object v2, v0, Landroidx/core/app/l;->b:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v2

    .line 11
    :try_start_0
    iget-object p0, v0, Landroidx/core/app/l;->c:Landroid/app/job/JobParameters;

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    monitor-exit v2

    .line 16
    return-object v1

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {p0}, Landroid/app/job/JobParameters;->dequeueWork()Landroid/app/job/JobWorkItem;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/app/job/JobWorkItem;->getIntent()Landroid/content/Intent;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v2, v0, Landroidx/core/app/l;->a:Landroidx/core/app/o;

    .line 31
    .line 32
    invoke-virtual {v2}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setExtrasClassLoader(Ljava/lang/ClassLoader;)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Landroidx/core/app/k;

    .line 40
    .line 41
    invoke-direct {v1, v0, p0}, Landroidx/core/app/k;-><init>(Landroidx/core/app/l;Landroid/app/job/JobWorkItem;)V

    .line 42
    .line 43
    .line 44
    :cond_1
    return-object v1

    .line 45
    :goto_0
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw p0

    .line 47
    :cond_2
    iget-object v0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 48
    .line 49
    monitor-enter v0

    .line 50
    :try_start_2
    iget-object v2, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-lez v2, :cond_3

    .line 57
    .line 58
    iget-object p0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Landroidx/core/app/j;

    .line 66
    .line 67
    monitor-exit v0

    .line 68
    return-object p0

    .line 69
    :catchall_1
    move-exception p0

    .line 70
    goto :goto_1

    .line 71
    :cond_3
    monitor-exit v0

    .line 72
    return-object v1

    .line 73
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 74
    throw p0
.end method

.method public doStopCurrentWork()Z
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/core/app/o;->mCurProcessor:Landroidx/core/app/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v1, p0, Landroidx/core/app/o;->mInterruptIfStopped:Z

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/os/AsyncTask;->cancel(Z)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    const/4 v0, 0x1

    .line 11
    iput-boolean v0, p0, Landroidx/core/app/o;->mStopped:Z

    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/core/app/o;->onStopCurrentWork()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public ensureProcessorRunningLocked(Z)V
    .locals 1

    .line 1
    iget-object p1, p0, Landroidx/core/app/o;->mCurProcessor:Landroidx/core/app/g;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    new-instance p1, Landroidx/core/app/g;

    .line 6
    .line 7
    invoke-direct {p1, p0}, Landroidx/core/app/g;-><init>(Landroidx/core/app/o;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Landroidx/core/app/o;->mCurProcessor:Landroidx/core/app/g;

    .line 11
    .line 12
    sget-object p0, Landroid/os/AsyncTask;->THREAD_POOL_EXECUTOR:Ljava/util/concurrent/Executor;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    new-array v0, v0, [Ljava/lang/Void;

    .line 16
    .line 17
    invoke-virtual {p1, p0, v0}, Landroid/os/AsyncTask;->executeOnExecutor(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public isStopped()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Landroidx/core/app/o;->mStopped:Z

    .line 2
    .line 3
    return p0
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/app/o;->mJobImpl:Landroidx/core/app/h;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p0, Landroidx/core/app/l;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/app/job/JobServiceEngine;->getBinder()Landroid/os/IBinder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public onCreate()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/core/app/l;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Landroidx/core/app/l;-><init>(Landroidx/core/app/o;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/core/app/o;->mJobImpl:Landroidx/core/app/h;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Landroidx/core/app/o;->mCompatWorkEnqueuer:Landroidx/core/app/n;

    .line 13
    .line 14
    return-void
.end method

.method public onDestroy()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    const/4 v1, 0x1

    .line 10
    :try_start_0
    iput-boolean v1, p0, Landroidx/core/app/o;->mDestroyed:Z

    .line 11
    .line 12
    iget-object p0, p0, Landroidx/core/app/o;->mCompatWorkEnqueuer:Landroidx/core/app/n;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

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
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0

    .line 22
    :cond_0
    return-void
.end method

.method public abstract onHandleWork(Landroid/content/Intent;)V
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 2

    .line 1
    iget-object p2, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-object p2, p0, Landroidx/core/app/o;->mCompatWorkEnqueuer:Landroidx/core/app/n;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 11
    .line 12
    monitor-enter p2

    .line 13
    :try_start_0
    iget-object v0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 14
    .line 15
    new-instance v1, Landroidx/core/app/i;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance p1, Landroid/content/Intent;

    .line 21
    .line 22
    invoke-direct {p1}, Landroid/content/Intent;-><init>()V

    .line 23
    .line 24
    .line 25
    :goto_0
    invoke-direct {v1, p0, p1, p3}, Landroidx/core/app/i;-><init>(Landroidx/core/app/o;Landroid/content/Intent;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    const/4 p1, 0x1

    .line 32
    invoke-virtual {p0, p1}, Landroidx/core/app/o;->ensureProcessorRunningLocked(Z)V

    .line 33
    .line 34
    .line 35
    monitor-exit p2

    .line 36
    const/4 p0, 0x3

    .line 37
    return p0

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0

    .line 41
    :cond_1
    const/4 p0, 0x2

    .line 42
    return p0
.end method

.method public onStopCurrentWork()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public processorFinished()V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    const/4 v1, 0x0

    .line 7
    :try_start_0
    iput-object v1, p0, Landroidx/core/app/o;->mCurProcessor:Landroidx/core/app/g;

    .line 8
    .line 9
    iget-object v1, p0, Landroidx/core/app/o;->mCompatQueue:Ljava/util/ArrayList;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-lez v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-virtual {p0, v1}, Landroidx/core/app/o;->ensureProcessorRunningLocked(Z)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    iget-boolean v1, p0, Landroidx/core/app/o;->mDestroyed:Z

    .line 27
    .line 28
    if-nez v1, :cond_1

    .line 29
    .line 30
    iget-object p0, p0, Landroidx/core/app/o;->mCompatWorkEnqueuer:Landroidx/core/app/n;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    monitor-exit v0

    .line 36
    return-void

    .line 37
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :cond_2
    return-void
.end method

.method public setInterruptIfStopped(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Landroidx/core/app/o;->mInterruptIfStopped:Z

    .line 2
    .line 3
    return-void
.end method
