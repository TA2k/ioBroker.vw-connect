.class public interface abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;
.end method

.method public isTimeoutReachedOnInactivity(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;Lo71/a;)Z
    .locals 2

    .line 1
    const-string p0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    sget-wide v0, Li81/b;->e:J

    .line 11
    .line 12
    invoke-static {p0, p1, v0, v1}, Lmy0/c;->c(JJ)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-ltz p0, :cond_1

    .line 17
    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    const-string p0, "Timeout occurred during MEBParkingFinishedState. Finish the RPA process and inform the user."

    .line 21
    .line 22
    invoke-static {p2, p0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public abstract setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;)V
.end method

.method public updateValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;Lo71/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V
    .locals 3

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 7
    .line 8
    invoke-static {p1}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {p1}, Llp/fd;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v1, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 21
    .line 22
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    iget-boolean v2, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 27
    .line 28
    invoke-static {v0, p1, v2, v1}, Lkp/x9;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;ZLs71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 37
    .line 38
    iget-object v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 39
    .line 40
    if-eq v0, v1, :cond_0

    .line 41
    .line 42
    if-eqz p2, :cond_0

    .line 43
    .line 44
    const-string v0, "Received a new different active parking maneuver in ParkingFinished"

    .line 45
    .line 46
    invoke-static {p2, v0}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_0
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-nez p2, :cond_1

    .line 58
    .line 59
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/i;->setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;)V

    .line 60
    .line 61
    .line 62
    if-eqz p3, :cond_1

    .line 63
    .line 64
    invoke-interface {p3, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onStateValuesChange(Ll71/x;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    return-void
.end method
