.class final Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;-><init>()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;

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
.method public bridge synthetic invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 2
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;->invoke(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ljava/lang/Void;
    .locals 0

    .line 1
    const-string p0, "it"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p0, 0x0

    return-object p0
.end method
