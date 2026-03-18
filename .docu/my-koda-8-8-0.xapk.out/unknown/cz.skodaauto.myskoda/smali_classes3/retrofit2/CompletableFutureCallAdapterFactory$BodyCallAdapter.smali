.class final Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/CallAdapter;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/CompletableFutureCallAdapterFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BodyCallAdapter"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter$BodyCallback;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<R:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/CallAdapter<",
        "TR;",
        "Ljava/util/concurrent/CompletableFuture<",
        "TR;>;>;"
    }
.end annotation

.annotation build Lorg/codehaus/mojo/animal_sniffer/IgnoreJRERequirement;
.end annotation


# instance fields
.field public final d:Ljava/lang/reflect/Type;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Type;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter;->d:Ljava/lang/reflect/Type;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final d()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter;->d:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e(Lretrofit2/Call;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lretrofit2/CompletableFutureCallAdapterFactory$CallCancelCompletableFuture;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lretrofit2/CompletableFutureCallAdapterFactory$CallCancelCompletableFuture;-><init>(Lretrofit2/Call;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter$BodyCallback;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lretrofit2/CompletableFutureCallAdapterFactory$BodyCallAdapter$BodyCallback;-><init>(Ljava/util/concurrent/CompletableFuture;)V

    .line 9
    .line 10
    .line 11
    check-cast p1, Lretrofit2/OkHttpCall;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Lretrofit2/OkHttpCall;->g(Lretrofit2/Callback;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method
