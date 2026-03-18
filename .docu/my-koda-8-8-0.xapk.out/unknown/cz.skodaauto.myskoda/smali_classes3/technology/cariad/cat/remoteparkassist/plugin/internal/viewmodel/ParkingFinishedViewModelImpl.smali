.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv61/a;
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;
.implements Lz71/g;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000V\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u000b\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008)\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B\u0019\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\r\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000cJ\u000f\u0010\u000e\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000cJ\u000f\u0010\u000f\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u000cJ\u0017\u0010\u0012\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0010H\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0019\u0010\u0015\u001a\u00020\n2\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0014H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0017\u0010\u0018\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0017H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u0019\u0010\u001a\u001a\u00020\n2\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0014H\u0016\u00a2\u0006\u0004\u0008\u001a\u0010\u0016J\u0019\u0010\u001b\u001a\u00020\n2\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0014H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u0016J\u0017\u0010\u001c\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0017\u0010\u001e\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u001dJ\u0017\u0010\u001f\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u001f\u0010\u001dJ\u0017\u0010 \u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008 \u0010\u001dJ\u0017\u0010!\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0017\u00a2\u0006\u0004\u0008!\u0010\u001dJ\u0017\u0010\"\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\"\u0010\u001dJ\u0017\u0010#\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008#\u0010\u001dJ\u0019\u0010&\u001a\u00020\n2\u0008\u0010%\u001a\u0004\u0018\u00010$H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u0017\u0010(\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008(\u0010\u001dJ\u0017\u0010)\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008)\u0010\u001dJ\u0017\u0010*\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008*\u0010\u001dJ\u0017\u0010+\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008+\u0010\u001dR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010,R\u001a\u0010\u0007\u001a\u00020\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010-\u001a\u0004\u0008.\u0010/R \u00101\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00081\u00102\u001a\u0004\u00081\u00103R\u001a\u00105\u001a\u0008\u0012\u0004\u0012\u00020\u0010048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00085\u00106R \u00107\u001a\u0008\u0012\u0004\u0012\u00020\u0010008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00087\u00102\u001a\u0004\u00088\u00103R\u001a\u00109\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00089\u00106R \u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008:\u00102\u001a\u0004\u0008:\u00103R\u001c\u0010;\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008;\u00106R\"\u0010<\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008<\u00102\u001a\u0004\u0008<\u00103R\u001a\u0010=\u001a\u0008\u0012\u0004\u0012\u00020\u0017048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008=\u00106R \u0010>\u001a\u0008\u0012\u0004\u0012\u00020\u0017008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008>\u00102\u001a\u0004\u0008?\u00103R\u001c\u0010@\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008@\u00106R\"\u0010A\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008A\u00102\u001a\u0004\u0008A\u00103R\u001c\u0010B\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008B\u00106R\"\u0010C\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008C\u00102\u001a\u0004\u0008C\u00103R\u001a\u0010D\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008D\u00106R \u0010E\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008E\u00102\u001a\u0004\u0008E\u00103R\u001a\u0010F\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008F\u00106R \u0010G\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008G\u00102\u001a\u0004\u0008G\u00103R\u001a\u0010H\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008H\u00106R \u0010I\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008I\u00102\u001a\u0004\u0008I\u00103R\u001a\u0010J\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008J\u00106R \u0010K\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008K\u00102\u001a\u0004\u0008K\u00103R\u001a\u0010L\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008L\u00106R \u0010M\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008M\u00102\u001a\u0004\u0008M\u00103R\u001a\u0010N\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008N\u00106R&\u0010O\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0097\u0004\u00a2\u0006\u0012\n\u0004\u0008O\u00102\u0012\u0004\u0008P\u0010\u000c\u001a\u0004\u0008O\u00103R\u001c\u0010Q\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010$048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008Q\u00106R\"\u0010R\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010$008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008R\u00102\u001a\u0004\u0008S\u00103R\u001a\u0010T\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008T\u00106R \u0010U\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008U\u00102\u001a\u0004\u0008U\u00103R\u001a\u0010V\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008V\u00106R \u0010W\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008W\u00102\u001a\u0004\u0008W\u00103R\u001a\u0010X\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008X\u00106R \u0010Y\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008Y\u00102\u001a\u0004\u0008Y\u00103R\u001a\u0010Z\u001a\u0008\u0012\u0004\u0012\u00020\u0014048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008Z\u00106R \u0010[\u001a\u0008\u0012\u0004\u0012\u00020\u0014008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008[\u00102\u001a\u0004\u0008\\\u00103\u00a8\u0006]"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;",
        "Lv61/a;",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;",
        "Lz71/g;",
        "Le81/q;",
        "viewModelController",
        "",
        "viewModelControllerHashCode",
        "<init>",
        "(Le81/q;I)V",
        "Llx0/b0;",
        "close",
        "()V",
        "startCloseWindows",
        "stopCloseWindows",
        "closeRPAModule",
        "Ls71/h;",
        "newStatus",
        "parkingFinishedActiveParkingManeuverDidChange",
        "(Ls71/h;)V",
        "",
        "parkingFinishedIsEngineTurnedOffDidChange",
        "(Ljava/lang/Boolean;)V",
        "Lz71/f;",
        "parkingFinishedDoorsAndFlapsStatusDidChange",
        "(Lz71/f;)V",
        "parkingFinishedIsHandbrakeActiveDidChange",
        "parkingFinishedIsHavingOpenWindowsDidChange",
        "parkingFinishedIsCloseWindowsEnabledDidChange",
        "(Z)V",
        "parkingFinishedIsClosingWindowsSupportedDidChange",
        "parkingFinishedIsClosingWindowsDidChange",
        "parkingFinishedIsParkingFinishedWithoutWarningsDidChange",
        "parkingFinishedIsParkingProcessActiveDidChange",
        "parkingFinishedIsTargetPositionReachedDidChange",
        "parkingFinishedIsAwaitingFinishedDidChange",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;",
        "newErrorStatus",
        "parkingFinishedErrorDidChange",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V",
        "parkingFinishedIsSafeLockActiveDidChange",
        "parkingFinishedIsChargerUnlockingDidChange",
        "parkingFinishedIsSunroofAvailableDidChange",
        "parkingFinishedHasUserTakenOverVehicleDidChange",
        "Le81/q;",
        "I",
        "getViewModelControllerHashCode",
        "()I",
        "Lyy0/a2;",
        "isClosable",
        "Lyy0/a2;",
        "()Lyy0/a2;",
        "Lyy0/j1;",
        "_activeParkingManeuver",
        "Lyy0/j1;",
        "activeParkingManeuver",
        "getActiveParkingManeuver",
        "_isAwaitingFinished",
        "isAwaitingFinished",
        "_isEngineTurnedOff",
        "isEngineTurnedOff",
        "_doorsAndFlapsStatus",
        "doorsAndFlapsStatus",
        "getDoorsAndFlapsStatus",
        "_isHandbrakeActive",
        "isHandbrakeActive",
        "_isHavingOpenWindows",
        "isHavingOpenWindows",
        "_isCloseWindowsEnabled",
        "isCloseWindowsEnabled",
        "_isClosingWindowsSupported",
        "isClosingWindowsSupported",
        "_isClosingWindows",
        "isClosingWindows",
        "_isTargetPositionReached",
        "isTargetPositionReached",
        "_isParkingFinishedWithoutWarnings",
        "isParkingFinishedWithoutWarnings",
        "_isParkingProcessActive",
        "isParkingProcessActive",
        "isParkingProcessActive$annotations",
        "_error",
        "error",
        "getError",
        "_isSafeLockActive",
        "isSafeLockActive",
        "_isChargerUnlocking",
        "isChargerUnlocking",
        "_isSunroofAvailable",
        "isSunroofAvailable",
        "_hasUserTakenOverVehicle",
        "hasUserTakenOverVehicle",
        "getHasUserTakenOverVehicle",
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


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final _activeParkingManeuver:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _doorsAndFlapsStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _error:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _hasUserTakenOverVehicle:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isAwaitingFinished:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isChargerUnlocking:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isCloseWindowsEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isClosingWindows:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isClosingWindowsSupported:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isEngineTurnedOff:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isHandbrakeActive:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isHavingOpenWindows:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isParkingFinishedWithoutWarnings:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isParkingProcessActive:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isSafeLockActive:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isSunroofAvailable:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isTargetPositionReached:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final activeParkingManeuver:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final doorsAndFlapsStatus:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final error:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final hasUserTakenOverVehicle:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isAwaitingFinished:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isChargerUnlocking:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isClosable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isCloseWindowsEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isClosingWindows:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isClosingWindowsSupported:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isEngineTurnedOff:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isHandbrakeActive:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isHavingOpenWindows:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isParkingFinishedWithoutWarnings:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isParkingProcessActive:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isSafeLockActive:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isSunroofAvailable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isTargetPositionReached:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final viewModelController:Le81/q;

.field private final viewModelControllerHashCode:I


# direct methods
.method public constructor <init>(Le81/q;I)V
    .locals 4

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 3
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelControllerHashCode:I

    .line 4
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    .line 5
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosable:Lyy0/a2;

    .line 7
    sget-object v0, Ls71/h;->d:Ls71/h;

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_activeParkingManeuver:Lyy0/j1;

    .line 8
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 9
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->activeParkingManeuver:Lyy0/a2;

    .line 10
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v1

    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isAwaitingFinished:Lyy0/j1;

    .line 11
    new-instance v2, Lyy0/l1;

    invoke-direct {v2, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 12
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isAwaitingFinished:Lyy0/a2;

    const/4 v1, 0x0

    .line 13
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v2

    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isEngineTurnedOff:Lyy0/j1;

    .line 14
    new-instance v3, Lyy0/l1;

    invoke-direct {v3, v2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isEngineTurnedOff:Lyy0/a2;

    .line 16
    sget-object v2, Lz71/f;->d:Lz71/f;

    invoke-static {v2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v2

    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_doorsAndFlapsStatus:Lyy0/j1;

    .line 17
    new-instance v3, Lyy0/l1;

    invoke-direct {v3, v2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 18
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->doorsAndFlapsStatus:Lyy0/a2;

    .line 19
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v2

    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isHandbrakeActive:Lyy0/j1;

    .line 20
    new-instance v3, Lyy0/l1;

    invoke-direct {v3, v2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 21
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isHandbrakeActive:Lyy0/a2;

    .line 22
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v2

    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isHavingOpenWindows:Lyy0/j1;

    .line 23
    new-instance v3, Lyy0/l1;

    invoke-direct {v3, v2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 24
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isHavingOpenWindows:Lyy0/a2;

    .line 25
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v2

    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isCloseWindowsEnabled:Lyy0/j1;

    .line 26
    new-instance v3, Lyy0/l1;

    invoke-direct {v3, v2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 27
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isCloseWindowsEnabled:Lyy0/a2;

    .line 28
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isClosingWindowsSupported:Lyy0/j1;

    .line 29
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosingWindowsSupported:Lyy0/a2;

    .line 30
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isClosingWindows:Lyy0/j1;

    .line 31
    new-instance v2, Lyy0/l1;

    invoke-direct {v2, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 32
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosingWindows:Lyy0/a2;

    .line 33
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isTargetPositionReached:Lyy0/j1;

    .line 34
    new-instance v2, Lyy0/l1;

    invoke-direct {v2, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 35
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isTargetPositionReached:Lyy0/a2;

    .line 36
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isParkingFinishedWithoutWarnings:Lyy0/j1;

    .line 37
    new-instance v2, Lyy0/l1;

    invoke-direct {v2, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 38
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isParkingFinishedWithoutWarnings:Lyy0/a2;

    .line 39
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isParkingProcessActive:Lyy0/j1;

    .line 40
    new-instance v2, Lyy0/l1;

    invoke-direct {v2, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 41
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isParkingProcessActive:Lyy0/a2;

    .line 42
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_error:Lyy0/j1;

    .line 43
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 44
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->error:Lyy0/a2;

    .line 45
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isSafeLockActive:Lyy0/j1;

    .line 46
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 47
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isSafeLockActive:Lyy0/a2;

    .line 48
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isChargerUnlocking:Lyy0/j1;

    .line 49
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 50
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isChargerUnlocking:Lyy0/a2;

    .line 51
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isSunroofAvailable:Lyy0/j1;

    .line 52
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 53
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isSunroofAvailable:Lyy0/a2;

    .line 54
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_hasUserTakenOverVehicle:Lyy0/j1;

    .line 55
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 56
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->hasUserTakenOverVehicle:Lyy0/a2;

    const/4 p2, 0x1

    .line 57
    invoke-interface {p1, p0, p2}, Le81/q;->addObserver(Lz71/g;Z)V

    .line 58
    invoke-interface {p1}, Lz71/h;->onAppear()V

    return-void
.end method

.method public synthetic constructor <init>(Le81/q;IILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 59
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result p2

    .line 60
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;-><init>(Le81/q;I)V

    return-void
.end method

.method public static synthetic isParkingProcessActive$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 2
    .line 3
    invoke-interface {v0}, Lz71/h;->onDisappear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 7
    .line 8
    invoke-interface {v0, p0}, Le81/q;->removeObserver(Lz71/g;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public closeRPAModule()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 2
    .line 3
    invoke-interface {p0}, Lz71/h;->closeScreen()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getActiveParkingManeuver()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->activeParkingManeuver:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDoorsAndFlapsStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->doorsAndFlapsStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->error:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHasUserTakenOverVehicle()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->hasUserTakenOverVehicle:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewModelControllerHashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelControllerHashCode:I

    .line 2
    .line 3
    return p0
.end method

.method public isAwaitingFinished()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isAwaitingFinished:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isChargerUnlocking()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isChargerUnlocking:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isClosable()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isCloseWindowsEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isCloseWindowsEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isClosingWindows()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosingWindows:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isClosingWindowsSupported()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isClosingWindowsSupported:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEngineTurnedOff()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isEngineTurnedOff:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isHandbrakeActive()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isHandbrakeActive:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isHavingOpenWindows()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isHavingOpenWindows:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isParkingFinishedWithoutWarnings()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isParkingFinishedWithoutWarnings:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isParkingProcessActive()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isParkingProcessActive:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSafeLockActive()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isSafeLockActive:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSunroofAvailable()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isSunroofAvailable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isTargetPositionReached()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->isTargetPositionReached:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public parkingFinishedActiveParkingManeuverDidChange(Ls71/h;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_activeParkingManeuver:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ls71/h;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public parkingFinishedDoorsAndFlapsStatusDidChange(Lz71/f;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_doorsAndFlapsStatus:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Lz71/f;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public parkingFinishedErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_error:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedHasUserTakenOverVehicleDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_hasUserTakenOverVehicle:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsAwaitingFinishedDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isAwaitingFinished:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsChargerUnlockingDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isChargerUnlocking:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsCloseWindowsEnabledDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isCloseWindowsEnabled:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsClosingWindowsDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isClosingWindows:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsClosingWindowsSupportedDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isClosingWindowsSupported:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsEngineTurnedOffDidChange(Ljava/lang/Boolean;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isEngineTurnedOff:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsHandbrakeActiveDidChange(Ljava/lang/Boolean;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isHandbrakeActive:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsHavingOpenWindowsDidChange(Ljava/lang/Boolean;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isHavingOpenWindows:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsParkingFinishedWithoutWarningsDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isParkingFinishedWithoutWarnings:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsParkingProcessActiveDidChange(Z)V
    .locals 3
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isParkingProcessActive:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsSafeLockActiveDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isSafeLockActive:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsSunroofAvailableDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isSunroofAvailable:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public parkingFinishedIsTargetPositionReachedDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->_isTargetPositionReached:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public startCloseWindows()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/q;->startCloseWindows()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public stopCloseWindows()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;->viewModelController:Le81/q;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/q;->stopCloseWindows()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
