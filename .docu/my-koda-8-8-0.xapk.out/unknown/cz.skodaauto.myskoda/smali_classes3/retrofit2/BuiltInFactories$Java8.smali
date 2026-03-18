.class final Lretrofit2/BuiltInFactories$Java8;
.super Lretrofit2/BuiltInFactories;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/TargetApi;
    value = 0x18
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/BuiltInFactories;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Java8"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/BuiltInFactories;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/concurrent/Executor;)Ljava/util/List;
    .locals 2

    .line 1
    new-instance p0, Lretrofit2/CompletableFutureCallAdapterFactory;

    .line 2
    .line 3
    invoke-direct {p0}, Lretrofit2/CompletableFutureCallAdapterFactory;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lretrofit2/DefaultCallAdapterFactory;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lretrofit2/DefaultCallAdapterFactory;-><init>(Ljava/util/concurrent/Executor;)V

    .line 9
    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    new-array p1, p1, [Lretrofit2/CallAdapter$Factory;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    aput-object p0, p1, v1

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    aput-object v0, p1, p0

    .line 19
    .line 20
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final b()Ljava/util/List;
    .locals 0

    .line 1
    new-instance p0, Lretrofit2/OptionalConverterFactory;

    .line 2
    .line 3
    invoke-direct {p0}, Lretrofit2/OptionalConverterFactory;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
