.class Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Callback;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lretrofit2/Callback<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field public final synthetic d:Lretrofit2/Callback;

.field public final synthetic e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;


# direct methods
.method public constructor <init>(Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;Lretrofit2/Callback;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->d:Lretrofit2/Callback;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/Call;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 2
    .line 3
    iget-object p1, p1, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->d:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    new-instance v0, Lretrofit2/a;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iget-object v2, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->d:Lretrofit2/Callback;

    .line 9
    .line 10
    invoke-direct {v0, p0, v2, p2, v1}, Lretrofit2/a;-><init>(Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;Lretrofit2/Callback;Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final b(Lretrofit2/Call;Lretrofit2/Response;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 2
    .line 3
    iget-object p1, p1, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->d:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    new-instance v0, Lretrofit2/a;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iget-object v2, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->d:Lretrofit2/Callback;

    .line 9
    .line 10
    invoke-direct {v0, p0, v2, p2, v1}, Lretrofit2/a;-><init>(Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;Lretrofit2/Callback;Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
