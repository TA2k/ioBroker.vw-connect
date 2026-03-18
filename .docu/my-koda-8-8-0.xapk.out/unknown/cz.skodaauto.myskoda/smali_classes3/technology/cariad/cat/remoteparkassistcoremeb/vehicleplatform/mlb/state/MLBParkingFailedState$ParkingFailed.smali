.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ParkingFailed"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0019\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\t\u0010\nJ\u001a\u0010\u000e\u001a\u00020\r2\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u000bH\u0096\u0002\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0012R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0013\u001a\u0004\u0008\u0014\u0010\u0015R\u0019\u0010\u0005\u001a\u0004\u0018\u00010\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010\u0016\u001a\u0004\u0008\u0017\u0010\u0018R(\u0010\u001c\u001a\u0010\u0012\u0004\u0012\u00020\u001a\u0012\u0006\u0012\u0004\u0018\u00010\u001b0\u00198\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u001c\u0010\u001d\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006 "
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;",
        "errorState",
        "Ll71/c;",
        "internalTimeout",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ll71/c;)V",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "",
        "hashCode",
        "()I",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;",
        "getErrorState",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;",
        "Ll71/c;",
        "getInternalTimeout",
        "()Ll71/c;",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
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
.field private final errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

.field private final internalTimeout:Ll71/c;

.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ll71/c;)V
    .locals 1

    .line 1
    const-string v0, "errorState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 10
    .line 11
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->internalTimeout:Ll71/c;

    .line 12
    .line 13
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/q;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/q;

    .line 14
    .line 15
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->transition:Lay0/k;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 6
    .line 7
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 8
    .line 9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->internalTimeout:Ll71/c;

    .line 14
    .line 15
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->internalTimeout:Ll71/c;

    .line 16
    .line 17
    if-ne p1, p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final getErrorState()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInternalTimeout()Ll71/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->internalTimeout:Ll71/c;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x1f

    .line 6
    .line 7
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    mul-int/lit8 v1, v1, 0x1f

    .line 15
    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->internalTimeout:Ll71/c;

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    :goto_0
    add-int/2addr v1, p0

    .line 27
    return v1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    const-class v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 2
    .line 3
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->errorState:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 14
    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, "(errorState: "

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string p0, ")"

    .line 32
    .line 33
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
