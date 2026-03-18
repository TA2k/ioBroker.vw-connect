.class final Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Call;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/DefaultCallAdapterFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ExecutorCallbackCall"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/Call<",
        "TT;>;"
    }
.end annotation


# instance fields
.field public final d:Ljava/util/concurrent/Executor;

.field public final e:Lretrofit2/Call;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;Lretrofit2/Call;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->d:Ljava/util/concurrent/Executor;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final cancel()V
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 2
    .line 3
    invoke-interface {p0}, Lretrofit2/Call;->cancel()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->clone()Lretrofit2/Call;

    move-result-object p0

    return-object p0
.end method

.method public final clone()Lretrofit2/Call;
    .locals 2

    .line 2
    new-instance v0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    iget-object v1, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    invoke-interface {v1}, Lretrofit2/Call;->clone()Lretrofit2/Call;

    move-result-object v1

    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->d:Ljava/util/concurrent/Executor;

    invoke-direct {v0, p0, v1}, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;-><init>(Ljava/util/concurrent/Executor;Lretrofit2/Call;)V

    return-object v0
.end method

.method public final g(Lretrofit2/Callback;)V
    .locals 1

    .line 1
    new-instance v0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;-><init>(Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;Lretrofit2/Callback;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lretrofit2/Call;->g(Lretrofit2/Callback;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final isCanceled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 2
    .line 3
    invoke-interface {p0}, Lretrofit2/Call;->isCanceled()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final request()Ld01/k0;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 2
    .line 3
    invoke-interface {p0}, Lretrofit2/Call;->request()Ld01/k0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
