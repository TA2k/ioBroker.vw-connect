.class public interface abstract Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx61/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0011\u0008f\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0004R\u001c\u0010\n\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00070\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0008\u0010\tR\u001a\u0010\r\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\tR\u001a\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000f\u0010\tR\u001c\u0010\u0010\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0010\u0010\tR\u001a\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u00110\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0012\u0010\tR\u001c\u0010\u0014\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0014\u0010\tR\u001c\u0010\u0015\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0015\u0010\tR\u001a\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\tR\u001a\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0017\u0010\tR\u001a\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\tR\u001a\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0019\u0010\tR \u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a7\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u001b\u0010\u0004\u001a\u0004\u0008\u001a\u0010\tR\u001a\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001c\u0010\tR\u001a\u0010\u001e\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001d\u0010\tR\u001a\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001f\u0010\tR\u001a\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008 \u0010\tR\u001a\u0010!\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\t\u00a8\u0006\"\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;",
        "Lx61/a;",
        "Llx0/b0;",
        "startCloseWindows",
        "()V",
        "stopCloseWindows",
        "Lyy0/a2;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;",
        "getError",
        "()Lyy0/a2;",
        "error",
        "Ls71/h;",
        "getActiveParkingManeuver",
        "activeParkingManeuver",
        "",
        "isTargetPositionReached",
        "isEngineTurnedOff",
        "Lz71/f;",
        "getDoorsAndFlapsStatus",
        "doorsAndFlapsStatus",
        "isHandbrakeActive",
        "isHavingOpenWindows",
        "isCloseWindowsEnabled",
        "isClosingWindowsSupported",
        "isClosingWindows",
        "isParkingFinishedWithoutWarnings",
        "isParkingProcessActive",
        "isParkingProcessActive$annotations",
        "isAwaitingFinished",
        "getHasUserTakenOverVehicle",
        "hasUserTakenOverVehicle",
        "isSafeLockActive",
        "isChargerUnlocking",
        "isSunroofAvailable",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract synthetic closeRPAModule()V
.end method

.method public abstract getActiveParkingManeuver()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getDoorsAndFlapsStatus()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getError()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getHasUserTakenOverVehicle()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isAwaitingFinished()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isChargerUnlocking()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract synthetic isClosable()Lyy0/a2;
.end method

.method public abstract isCloseWindowsEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isClosingWindows()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isClosingWindowsSupported()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isEngineTurnedOff()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isHandbrakeActive()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isHavingOpenWindows()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isParkingFinishedWithoutWarnings()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isParkingProcessActive()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isSafeLockActive()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isSunroofAvailable()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isTargetPositionReached()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract startCloseWindows()V
.end method

.method public abstract stopCloseWindows()V
.end method
