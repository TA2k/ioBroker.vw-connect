.class final Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/location/Location;->isLocationEnabled$genx_release(Landroid/content/Context;)Lyy0/i;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0003\u001a\u00020\u0002*\u0008\u0012\u0004\u0012\u00020\u00010\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "Lxy0/x;",
        "",
        "Llx0/b0;",
        "<anonymous>",
        "(Lxy0/x;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.location.Location$isLocationEnabled$1"
    f = "Location.kt"
    l = {
        0x2d
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $this_isLocationEnabled:Landroid/content/Context;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->$this_isLocationEnabled:Landroid/content/Context;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static synthetic b(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->invokeSuspend$lambda$0(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)Llx0/b0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->$this_isLocationEnabled:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;-><init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->L$0:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lxy0/x;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->invoke(Lxy0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lxy0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lxy0/x;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lxy0/x;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->label:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->L$1:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    new-instance p1, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;

    .line 34
    .line 35
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;-><init>(Lxy0/x;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->$this_isLocationEnabled:Landroid/content/Context;

    .line 39
    .line 40
    new-instance v4, Landroid/content/IntentFilter;

    .line 41
    .line 42
    const-string v5, "android.location.PROVIDERS_CHANGED"

    .line 43
    .line 44
    invoke-direct {v4, v5}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v2, p1, v4}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 48
    .line 49
    .line 50
    iget-object v2, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->$this_isLocationEnabled:Landroid/content/Context;

    .line 51
    .line 52
    new-instance v4, Ltechnology/cariad/cat/genx/location/a;

    .line 53
    .line 54
    invoke-direct {v4, v2, p1}, Ltechnology/cariad/cat/genx/location/a;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)V

    .line 55
    .line 56
    .line 57
    const/4 p1, 0x0

    .line 58
    iput-object p1, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->L$0:Ljava/lang/Object;

    .line 59
    .line 60
    iput-object p1, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->L$1:Ljava/lang/Object;

    .line 61
    .line 62
    iput v3, p0, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->label:I

    .line 63
    .line 64
    invoke-static {v0, v4, p0}, Llp/mf;->b(Lxy0/x;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v1, :cond_2

    .line 69
    .line 70
    return-object v1

    .line 71
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0
.end method
