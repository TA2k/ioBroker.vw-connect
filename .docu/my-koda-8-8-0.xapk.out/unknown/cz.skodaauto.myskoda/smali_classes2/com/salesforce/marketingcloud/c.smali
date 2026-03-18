.class abstract Lcom/salesforce/marketingcloud/c;
.super Landroid/app/Service;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/c$h;,
        Lcom/salesforce/marketingcloud/c$g;,
        Lcom/salesforce/marketingcloud/c$c;,
        Lcom/salesforce/marketingcloud/c$f;,
        Lcom/salesforce/marketingcloud/c$b;,
        Lcom/salesforce/marketingcloud/c$d;,
        Lcom/salesforce/marketingcloud/c$a;,
        Lcom/salesforce/marketingcloud/c$e;
    }
.end annotation


# static fields
.field static final h:Ljava/lang/String;

.field static final i:Ljava/lang/Object;

.field static final j:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Landroid/content/ComponentName;",
            "Lcom/salesforce/marketingcloud/c$h;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field final a:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lcom/salesforce/marketingcloud/c$d;",
            ">;"
        }
    .end annotation
.end field

.field b:Lcom/salesforce/marketingcloud/c$b;

.field c:Lcom/salesforce/marketingcloud/c$h;

.field d:Lcom/salesforce/marketingcloud/c$a;

.field e:Z

.field f:Z

.field g:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "JobIntentService"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v0, Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/c;->i:Ljava/lang/Object;

    .line 15
    .line 16
    new-instance v0, Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lcom/salesforce/marketingcloud/c;->j:Ljava/util/HashMap;

    .line 22
    .line 23
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
    iput-object v0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    .line 6
    .line 7
    return-void
.end method

.method public static a(Landroid/content/Context;Landroid/content/ComponentName;ZI)Lcom/salesforce/marketingcloud/c$h;
    .locals 2

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/c;->j:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/c$h;

    if-nez v1, :cond_1

    if-eqz p2, :cond_0

    .line 10
    new-instance p2, Lcom/salesforce/marketingcloud/c$g;

    invoke-direct {p2, p0, p1, p3}, Lcom/salesforce/marketingcloud/c$g;-><init>(Landroid/content/Context;Landroid/content/ComponentName;I)V

    .line 11
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Can\'t be here without a job id"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    return-object v1
.end method

.method public static a(Landroid/content/Context;Landroid/content/ComponentName;ILandroid/content/Intent;)V
    .locals 2

    if-eqz p3, :cond_0

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/c;->i:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x1

    .line 3
    :try_start_0
    invoke-static {p0, p1, v1, p2}, Lcom/salesforce/marketingcloud/c;->a(Landroid/content/Context;Landroid/content/ComponentName;ZI)Lcom/salesforce/marketingcloud/c$h;

    move-result-object p0

    .line 4
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/c$h;->a(I)V

    .line 5
    invoke-virtual {p0, p3}, Lcom/salesforce/marketingcloud/c$h;->a(Landroid/content/Intent;)V

    .line 6
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    .line 7
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

.method public static a(Landroid/content/Context;Ljava/lang/Class;ILandroid/content/Intent;)V
    .locals 1

    .line 1
    new-instance v0, Landroid/content/ComponentName;

    invoke-direct {v0, p0, p1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-static {p0, v0, p2, p3}, Lcom/salesforce/marketingcloud/c;->a(Landroid/content/Context;Landroid/content/ComponentName;ILandroid/content/Intent;)V

    return-void
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/c$e;
    .locals 2

    .line 19
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->b:Lcom/salesforce/marketingcloud/c$b;

    if-eqz v0, :cond_0

    .line 20
    invoke-interface {v0}, Lcom/salesforce/marketingcloud/c$b;->a()Lcom/salesforce/marketingcloud/c$e;

    move-result-object p0

    return-object p0

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    monitor-enter v0

    .line 22
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-lez v1, :cond_1

    .line 23
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    const/4 v1, 0x0

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lcom/salesforce/marketingcloud/c$e;

    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    .line 24
    monitor-exit v0

    return-object p0

    .line 25
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public abstract a(Landroid/content/Intent;)V
.end method

.method public a(Z)V
    .locals 2

    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    if-nez v0, :cond_1

    .line 14
    new-instance v0, Lcom/salesforce/marketingcloud/c$a;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/c$a;-><init>(Lcom/salesforce/marketingcloud/c;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    .line 15
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->c:Lcom/salesforce/marketingcloud/c$h;

    if-eqz v0, :cond_0

    if-eqz p1, :cond_0

    .line 16
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/c$h;->b()V

    .line 17
    :cond_0
    sget-object p1, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "Starting processor: %s"

    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    sget-object p1, Landroid/os/AsyncTask;->THREAD_POOL_EXECUTOR:Ljava/util/concurrent/Executor;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Void;

    invoke-virtual {p0, p1, v0}, Landroid/os/AsyncTask;->executeOnExecutor(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;

    :cond_1
    return-void
.end method

.method public b(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/c;->e:Z

    return-void
.end method

.method public b()Z
    .locals 2

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    if-eqz v0, :cond_0

    .line 3
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/c;->e:Z

    invoke-virtual {v0, v1}, Landroid/os/AsyncTask;->cancel(Z)Z

    :cond_0
    const/4 v0, 0x1

    .line 4
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/c;->f:Z

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/c;->d()Z

    move-result p0

    return p0
.end method

.method public c()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/c;->f:Z

    .line 2
    .line 3
    return p0
.end method

.method public d()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

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
    iput-object v1, p0, Lcom/salesforce/marketingcloud/c;->d:Lcom/salesforce/marketingcloud/c$a;

    .line 8
    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

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
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/c;->a(Z)V

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
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/c;->g:Z

    .line 27
    .line 28
    if-nez v1, :cond_1

    .line 29
    .line 30
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c;->c:Lcom/salesforce/marketingcloud/c$h;

    .line 31
    .line 32
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/c$h;->a()V

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

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/c;->b:Lcom/salesforce/marketingcloud/c$b;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/c$b;->b()Landroid/os/IBinder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    sget-object p1, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 10
    .line 11
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "Returning engine: %s"

    .line 16
    .line 17
    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return-object p0
.end method

.method public onCreate()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 5
    .line 6
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "CREATING: %s"

    .line 11
    .line 12
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lcom/salesforce/marketingcloud/c$f;

    .line 16
    .line 17
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/c$f;-><init>(Lcom/salesforce/marketingcloud/c;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lcom/salesforce/marketingcloud/c;->b:Lcom/salesforce/marketingcloud/c$b;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    iput-object v0, p0, Lcom/salesforce/marketingcloud/c;->c:Lcom/salesforce/marketingcloud/c$h;

    .line 24
    .line 25
    return-void
.end method

.method public onDestroy()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    const/4 v1, 0x1

    .line 7
    :try_start_0
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/c;->g:Z

    .line 8
    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/c;->c:Lcom/salesforce/marketingcloud/c$h;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/c$h;->a()V

    .line 12
    .line 13
    .line 14
    monitor-exit v0

    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    throw p0

    .line 19
    :cond_0
    :goto_0
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 2

    .line 1
    iget-object p2, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-object p2, p0, Lcom/salesforce/marketingcloud/c;->c:Lcom/salesforce/marketingcloud/c$h;

    .line 6
    .line 7
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/c$h;->c()V

    .line 8
    .line 9
    .line 10
    sget-object p2, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    filled-new-array {v0, p1}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v1, "Received compat start command #%d: %s"

    .line 21
    .line 22
    invoke-static {p2, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object p2, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    .line 26
    .line 27
    monitor-enter p2

    .line 28
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/c;->a:Ljava/util/ArrayList;

    .line 29
    .line 30
    new-instance v1, Lcom/salesforce/marketingcloud/c$d;

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance p1, Landroid/content/Intent;

    .line 36
    .line 37
    invoke-direct {p1}, Landroid/content/Intent;-><init>()V

    .line 38
    .line 39
    .line 40
    :goto_0
    invoke-direct {v1, p0, p1, p3}, Lcom/salesforce/marketingcloud/c$d;-><init>(Lcom/salesforce/marketingcloud/c;Landroid/content/Intent;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    const/4 p1, 0x1

    .line 47
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/c;->a(Z)V

    .line 48
    .line 49
    .line 50
    monitor-exit p2

    .line 51
    const/4 p0, 0x3

    .line 52
    return p0

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    throw p0

    .line 56
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/c;->h:Ljava/lang/String;

    .line 57
    .line 58
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    const-string p2, "Ignoring start command: %s"

    .line 63
    .line 64
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    const/4 p0, 0x2

    .line 68
    return p0
.end method
