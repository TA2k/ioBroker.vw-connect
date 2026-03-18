.class public Lcom/salesforce/marketingcloud/media/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/media/h$b;,
        Lcom/salesforce/marketingcloud/media/h$a;
    }
.end annotation


# static fields
.field static final h:I = 0x1

.field static final i:I = 0x2

.field static final j:I = 0x3

.field static final k:I = 0x4

.field static final l:I = 0x5

.field static final m:I = 0x6

.field private static final n:Ljava/lang/String;


# instance fields
.field final a:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/media/n;",
            ">;"
        }
    .end annotation
.end field

.field final b:Lcom/salesforce/marketingcloud/media/h$b;

.field final c:Landroid/content/Context;

.field final d:Ljava/util/concurrent/ExecutorService;

.field final e:Landroid/os/Handler;

.field final f:Landroid/os/Handler;

.field final g:Lcom/salesforce/marketingcloud/media/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "Dispatcher"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/media/h;->n:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/util/concurrent/ExecutorService;Landroid/os/Handler;Lcom/salesforce/marketingcloud/media/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/salesforce/marketingcloud/media/h$b;

    .line 5
    .line 6
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/media/h$b;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->b:Lcom/salesforce/marketingcloud/media/h$b;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/h;->c:Landroid/content/Context;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/h;->d:Ljava/util/concurrent/ExecutorService;

    .line 17
    .line 18
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    .line 24
    .line 25
    new-instance p1, Lcom/salesforce/marketingcloud/media/h$a;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-direct {p1, p2, p0}, Lcom/salesforce/marketingcloud/media/h$a;-><init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/media/h;)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    .line 35
    .line 36
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/h;->f:Landroid/os/Handler;

    .line 37
    .line 38
    iput-object p4, p0, Lcom/salesforce/marketingcloud/media/h;->g:Lcom/salesforce/marketingcloud/media/c;

    .line 39
    .line 40
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->j()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    .line 2
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->i()Lcom/salesforce/marketingcloud/media/v$b;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->d()Z

    move-result v1

    if-eqz v1, :cond_1

    .line 4
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->a()Landroid/graphics/Bitmap;

    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->prepareToDraw()V

    .line 6
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->f:Landroid/os/Handler;

    const/4 v0, 0x2

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 1

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x6

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/d;)V
    .locals 1

    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x4

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/e;)V
    .locals 1

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x5

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 1

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x1

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/media/d;)V
    .locals 1

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->d:Ljava/util/concurrent/ExecutorService;

    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->isShutdown()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/media/h;->n:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "ExecutorService is shutdown.  Ignoring request."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 4
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/media/e;

    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/media/e;-><init>(Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/d;)V

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->d:Ljava/util/concurrent/ExecutorService;

    invoke-interface {p0, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/media/e;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->f:Landroid/os/Handler;

    const/4 v0, 0x5

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 1

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x2

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public c(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->c()Ljava/lang/String;

    move-result-object v0

    .line 2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/media/n;

    if-eqz v1, :cond_0

    .line 3
    invoke-virtual {v1, p1}, Lcom/salesforce/marketingcloud/media/n;->b(Lcom/salesforce/marketingcloud/media/a;)V

    .line 4
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/media/n;->a()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    invoke-interface {p0, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public c(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 1

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->e:Landroid/os/Handler;

    const/4 v0, 0x3

    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    return-void
.end method

.method public d(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->c()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/media/n;

    if-eqz v0, :cond_0

    .line 2
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/media/n;->a(Lcom/salesforce/marketingcloud/media/a;)V

    return-void

    .line 3
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->d:Ljava/util/concurrent/ExecutorService;

    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->isShutdown()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 4
    sget-object p0, Lcom/salesforce/marketingcloud/media/h;->n:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "ExecutorService is shutdown.  Ignoring request."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 5
    :cond_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->b()Lcom/salesforce/marketingcloud/media/o;

    move-result-object v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/h;->g:Lcom/salesforce/marketingcloud/media/c;

    invoke-static {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/media/n;->a(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/a;)Lcom/salesforce/marketingcloud/media/n;

    move-result-object v0

    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/h;->d:Ljava/util/concurrent/ExecutorService;

    invoke-interface {v1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    move-result-object v1

    iput-object v1, v0, Lcom/salesforce/marketingcloud/media/n;->k:Ljava/util/concurrent/Future;

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->c()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public d(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 3

    .line 8
    iget-object v0, p1, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    iget v0, v0, Lcom/salesforce/marketingcloud/media/t;->d:I

    invoke-static {v0}, Lcom/salesforce/marketingcloud/media/t$b;->b(I)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 9
    iget-object v0, p1, Lcom/salesforce/marketingcloud/media/n;->j:Lcom/salesforce/marketingcloud/media/v$b;

    .line 10
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->d()Z

    move-result v1

    if-eqz v1, :cond_0

    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/h;->g:Lcom/salesforce/marketingcloud/media/c;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->h()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->a()Landroid/graphics/Bitmap;

    move-result-object v0

    invoke-virtual {v1, v2, v0}, Lcom/salesforce/marketingcloud/media/c;->a(Ljava/lang/String;Landroid/graphics/Bitmap;)V

    .line 12
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->h()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->a(Lcom/salesforce/marketingcloud/media/n;)V

    return-void
.end method

.method public e(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/h;->a:Ljava/util/Map;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->h()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->a(Lcom/salesforce/marketingcloud/media/n;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
