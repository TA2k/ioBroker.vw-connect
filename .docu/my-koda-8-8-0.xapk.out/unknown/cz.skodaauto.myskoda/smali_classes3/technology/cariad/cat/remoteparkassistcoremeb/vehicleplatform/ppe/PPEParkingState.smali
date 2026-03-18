.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R(\u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\nR\u001a\u0010\u000c\u001a\u00020\u000b8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0010"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;",
        "<init>",
        "()V",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "stateMachine",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "getStateMachine",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
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
.field private final stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ls81/a;->d:Ls81/a;

    .line 5
    .line 6
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;->transition:Lay0/k;

    .line 7
    .line 8
    new-instance v0, Ls81/b;

    .line 9
    .line 10
    invoke-direct {v0}, Ls81/b;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;->stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public getStateMachine()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;->stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransition()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
