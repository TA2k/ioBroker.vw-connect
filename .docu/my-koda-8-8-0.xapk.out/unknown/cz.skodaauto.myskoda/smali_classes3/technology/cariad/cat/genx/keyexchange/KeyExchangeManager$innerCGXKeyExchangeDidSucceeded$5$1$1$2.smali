.class final Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->innerCGXKeyExchangeDidSucceeded(Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0001\u001a\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;",
        "it",
        "Llx0/b0;",
        "<anonymous>",
        "(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.keyexchange.KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2"
    f = "KeyExchangeManager.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $app:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

.field final synthetic $keyExchangeInformation:Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;",
            "Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$keyExchangeInformation:Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$app:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3
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
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$keyExchangeInformation:Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$app:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;-><init>(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->L$0:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->invoke(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->label:I

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$keyExchangeInformation:Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$innerCGXKeyExchangeDidSucceeded$5$1$1$2;->$app:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getVehicle()Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p1, v0, v1, p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->access$handleKeyExchangeServiceResult(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;Ltechnology/cariad/cat/genx/KeyExchangeInformation;Ltechnology/cariad/cat/genx/InternalVehicle;)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method
