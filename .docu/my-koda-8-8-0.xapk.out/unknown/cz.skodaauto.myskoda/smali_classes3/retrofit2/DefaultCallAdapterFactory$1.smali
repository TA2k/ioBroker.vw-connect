.class Lretrofit2/DefaultCallAdapterFactory$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/CallAdapter;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lretrofit2/CallAdapter<",
        "Ljava/lang/Object;",
        "Lretrofit2/Call<",
        "*>;>;"
    }
.end annotation


# instance fields
.field public final synthetic d:Ljava/lang/reflect/Type;

.field public final synthetic e:Ljava/util/concurrent/Executor;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Type;Ljava/util/concurrent/Executor;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/DefaultCallAdapterFactory$1;->d:Ljava/lang/reflect/Type;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/DefaultCallAdapterFactory$1;->e:Ljava/util/concurrent/Executor;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final d()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$1;->d:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e(Lretrofit2/Call;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lretrofit2/DefaultCallAdapterFactory$1;->e:Ljava/util/concurrent/Executor;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-object p1

    .line 6
    :cond_0
    new-instance v0, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;-><init>(Ljava/util/concurrent/Executor;Lretrofit2/Call;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
