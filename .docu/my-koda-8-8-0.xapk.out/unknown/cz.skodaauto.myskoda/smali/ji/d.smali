.class public final Lji/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Call;


# instance fields
.field public final d:Lretrofit2/Call;

.field public final e:Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;


# direct methods
.method public constructor <init>(Lretrofit2/Call;Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lji/d;->d:Lretrofit2/Call;

    .line 5
    .line 6
    iput-object p2, p0, Lji/d;->e:Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lji/d;
    .locals 3

    .line 1
    new-instance v0, Lji/d;

    .line 2
    .line 3
    iget-object v1, p0, Lji/d;->d:Lretrofit2/Call;

    .line 4
    .line 5
    invoke-interface {v1}, Lretrofit2/Call;->clone()Lretrofit2/Call;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-string v2, "clone(...)"

    .line 10
    .line 11
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lji/d;->e:Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;

    .line 15
    .line 16
    invoke-direct {v0, v1, p0}, Lji/d;-><init>(Lretrofit2/Call;Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public final cancel()V
    .locals 0

    .line 1
    iget-object p0, p0, Lji/d;->d:Lretrofit2/Call;

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
    invoke-virtual {p0}, Lji/d;->a()Lji/d;

    move-result-object p0

    return-object p0
.end method

.method public final bridge synthetic clone()Lretrofit2/Call;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lji/d;->a()Lji/d;

    move-result-object p0

    return-object p0
.end method

.method public final g(Lretrofit2/Callback;)V
    .locals 3

    .line 1
    new-instance v0, Lb81/d;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, p1, v2, v1}, Lb81/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lji/d;->d:Lretrofit2/Call;

    .line 10
    .line 11
    invoke-interface {p0, v0}, Lretrofit2/Call;->g(Lretrofit2/Callback;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final isCanceled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lji/d;->d:Lretrofit2/Call;

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
    .locals 1

    .line 1
    iget-object p0, p0, Lji/d;->d:Lretrofit2/Call;

    .line 2
    .line 3
    invoke-interface {p0}, Lretrofit2/Call;->request()Ld01/k0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "request(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
