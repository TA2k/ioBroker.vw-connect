.class public abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "DriveCorrectionSubState"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\n\u0008 \u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0004\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0017\u0010\t\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0004\u00a2\u0006\u0004\u0008\t\u0010\u0008R(\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\u000b\u0012\u0006\u0012\u0004\u0018\u00010\u00060\n8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000fR$\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0010\u001a\u00020\u00048&@dX\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0011\u0010\u0012\"\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u0015"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "<init>",
        "()V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "values",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "getTransitionForStartParking",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "getTransitionForStartUndoing",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "value",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "setValues",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/c;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/c;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;->transition:Lay0/k;

    .line 10
    .line 11
    return-void
.end method

.method public static final synthetic access$getStateCallback(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$DriveCorrectionSubState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTransitionForStartParking(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 1

    .line 1
    const-string p0, "values"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 7
    .line 8
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 9
    .line 10
    if-ne p0, v0, :cond_0

    .line 11
    .line 12
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;

    .line 13
    .line 14
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public final getTransitionForStartUndoing(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 1

    .line 1
    const-string p0, "values"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 7
    .line 8
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 9
    .line 10
    if-ne p0, v0, :cond_0

    .line 11
    .line 12
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;

    .line 13
    .line 14
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public abstract getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;
.end method

.method public abstract setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V
.end method
