.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R(\u0010\u0006\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "<init>",
        "()V",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState$transition$1;

    .line 5
    .line 6
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;->transition:Lay0/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public getTransition()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
