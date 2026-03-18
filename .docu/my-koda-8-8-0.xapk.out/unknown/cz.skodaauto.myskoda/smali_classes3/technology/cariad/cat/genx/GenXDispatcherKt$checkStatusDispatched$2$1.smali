.class public final Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/GenXDispatcherKt;->checkStatusDispatched(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0xb0
.end annotation


# instance fields
.field final synthetic $continuation:Lkotlin/coroutines/Continuation;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/coroutines/Continuation<",
            "Llx0/o;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $function:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lay0/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->$function:Lay0/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 2

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1$genXError$1;

    iget-object v1, p0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->$function:Lay0/a;

    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1$genXError$1;-><init>(Lay0/a;)V

    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    move-result-object v0

    if-nez v0, :cond_0

    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 4
    new-instance v0, Llx0/o;

    sget-object v1, Llx0/b0;->a:Llx0/b0;

    invoke-direct {v0, v1}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 5
    invoke-interface {p0, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;->$continuation:Lkotlin/coroutines/Continuation;

    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    move-result-object v0

    invoke-interface {p0, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method
