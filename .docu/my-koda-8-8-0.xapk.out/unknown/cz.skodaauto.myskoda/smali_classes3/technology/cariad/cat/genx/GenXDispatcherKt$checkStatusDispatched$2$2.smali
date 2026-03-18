.class public final Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;
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


# static fields
.field public static final INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;->invoke()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/String;
    .locals 0

    .line 2
    const-string p0, "dispatchSuspendedWithResult(): Failed to execute the function due to internal error on the Dispatcher."

    return-object p0
.end method
