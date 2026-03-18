.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv61/a;
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;
.implements Lz71/b;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B\u0019\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0017\u0010\u000f\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0017\u0010\u0012\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0010J\u0017\u0010\u0014\u001a\u00020\n2\u0006\u0010\u0013\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u0014\u0010\u0010J\u0019\u0010\u0017\u001a\u00020\n2\u0008\u0010\u0016\u001a\u0004\u0018\u00010\u0015H\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u0017\u0010\u001b\u001a\u00020\n2\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u001b\u0010 \u001a\u00020\n2\n\u0010\u001f\u001a\u00060\u001dj\u0002`\u001eH\u0016\u00a2\u0006\u0004\u0008 \u0010!J\u000f\u0010\"\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\"\u0010\u000cJ\u000f\u0010#\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008#\u0010\u000cJ\u000f\u0010$\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008$\u0010\u000cR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010%R\u001a\u0010\u0007\u001a\u00020\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010&\u001a\u0004\u0008\'\u0010(R \u0010*\u001a\u0008\u0012\u0004\u0012\u00020\r0)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008*\u0010+\u001a\u0004\u0008*\u0010,R\u001a\u0010.\u001a\u0008\u0012\u0004\u0012\u00020\r0-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008.\u0010/R \u0010\u0011\u001a\u0008\u0012\u0004\u0012\u00020\r0)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0011\u0010+\u001a\u0004\u0008\u0011\u0010,R\u001a\u00100\u001a\u0008\u0012\u0004\u0012\u00020\r0-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00080\u0010/R \u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010+\u001a\u0004\u0008\u000e\u0010,R\u001a\u00101\u001a\u0008\u0012\u0004\u0012\u00020\r0-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00081\u0010/R \u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\r0)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0013\u0010+\u001a\u0004\u0008\u0013\u0010,R\u001c\u00102\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00150-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00082\u0010/R\"\u00103\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00150)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00083\u0010+\u001a\u0004\u00084\u0010,R\u001a\u00105\u001a\u0008\u0012\u0004\u0012\u00020\u00190-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00085\u0010/R \u00106\u001a\u0008\u0012\u0004\u0012\u00020\u00190)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00086\u0010+\u001a\u0004\u00087\u0010,R\u001a\u00109\u001a\u0008\u0012\u0004\u0012\u0002080-8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00089\u0010/R \u0010\u001f\u001a\u0008\u0012\u0004\u0012\u0002080)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u001f\u0010+\u001a\u0004\u0008:\u0010,\u00a8\u0006;"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;",
        "Lv61/a;",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;",
        "Lz71/b;",
        "Le81/n;",
        "viewModelController",
        "",
        "viewModelControllerHashCode",
        "<init>",
        "(Le81/n;I)V",
        "Llx0/b0;",
        "close",
        "()V",
        "",
        "isDriveActivationActionAllowed",
        "driveActivationIsDriveActivationActionAllowedDidChange",
        "(Z)V",
        "isWaitingForResponse",
        "driveActivationIsWaitingForResponseDidChange",
        "isElectricalVehicle",
        "driveActivationIsElectricalVehicleDidChange",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "newErrorStatus",
        "driveActivationErrorDidChange",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
        "Ls71/h;",
        "newStatus",
        "driveActivationParkingManeuverStatusDidChange",
        "(Ls71/h;)V",
        "",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/data/Milliseconds;",
        "pressTimeThreshold",
        "driveActivationPressTimeThresholdInMillisecondsDidChange",
        "(J)V",
        "startActivation",
        "stopActivation",
        "closeRPAModule",
        "Le81/n;",
        "I",
        "getViewModelControllerHashCode",
        "()I",
        "Lyy0/a2;",
        "isClosable",
        "Lyy0/a2;",
        "()Lyy0/a2;",
        "Lyy0/j1;",
        "_isWaitingForResponse",
        "Lyy0/j1;",
        "_isDriveActivationActionAllowed",
        "_isElectricalVehicle",
        "_error",
        "error",
        "getError",
        "_parkingManeuverStatus",
        "parkingManeuverStatus",
        "getParkingManeuverStatus",
        "Lmy0/c;",
        "_pressTimeThreshold",
        "getPressTimeThreshold",
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
.field private final _error:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isDriveActivationActionAllowed:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isElectricalVehicle:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isWaitingForResponse:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _parkingManeuverStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _pressTimeThreshold:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
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

.field private final isClosable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isDriveActivationActionAllowed:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isElectricalVehicle:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isWaitingForResponse:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final parkingManeuverStatus:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final pressTimeThreshold:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final viewModelController:Le81/n;

.field private final viewModelControllerHashCode:I


# direct methods
.method public constructor <init>(Le81/n;I)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 3
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelControllerHashCode:I

    .line 4
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    .line 5
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isClosable:Lyy0/a2;

    .line 7
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isWaitingForResponse:Lyy0/j1;

    .line 8
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 9
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isWaitingForResponse:Lyy0/a2;

    .line 10
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isDriveActivationActionAllowed:Lyy0/j1;

    .line 11
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 12
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isDriveActivationActionAllowed:Lyy0/a2;

    .line 13
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isElectricalVehicle:Lyy0/j1;

    .line 14
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isElectricalVehicle:Lyy0/a2;

    const/4 p2, 0x0

    .line 16
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_error:Lyy0/j1;

    .line 17
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 18
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->error:Lyy0/a2;

    .line 19
    sget-object p2, Ls71/h;->d:Ls71/h;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    .line 20
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 21
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 22
    new-instance p2, Lmy0/c;

    const-wide/16 v0, 0x0

    invoke-direct {p2, v0, v1}, Lmy0/c;-><init>(J)V

    .line 23
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_pressTimeThreshold:Lyy0/j1;

    .line 24
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 25
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->pressTimeThreshold:Lyy0/a2;

    const/4 p2, 0x1

    .line 26
    invoke-interface {p1, p0, p2}, Le81/n;->addObserver(Lz71/b;Z)V

    .line 27
    invoke-interface {p1}, Lz71/h;->onAppear()V

    return-void
.end method

.method public synthetic constructor <init>(Le81/n;IILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 28
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result p2

    .line 29
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;-><init>(Le81/n;I)V

    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 2
    .line 3
    invoke-interface {v0}, Lz71/h;->onDisappear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 7
    .line 8
    invoke-interface {v0, p0}, Le81/n;->removeObserver(Lz71/b;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public closeRPAModule()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 2
    .line 3
    invoke-interface {p0}, Lz71/h;->closeScreen()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public driveActivationErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_error:Lyy0/j1;

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
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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

.method public driveActivationIsDriveActivationActionAllowedDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isDriveActivationActionAllowed:Lyy0/j1;

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

.method public driveActivationIsElectricalVehicleDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isElectricalVehicle:Lyy0/j1;

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

.method public driveActivationIsWaitingForResponseDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_isWaitingForResponse:Lyy0/j1;

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

.method public driveActivationParkingManeuverStatusDidChange(Ls71/h;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

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

.method public driveActivationPressTimeThresholdInMillisecondsDidChange(J)V
    .locals 5

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->_pressTimeThreshold:Lyy0/j1;

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
    check-cast v2, Lmy0/c;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 17
    .line 18
    invoke-static {p1, p2, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 19
    .line 20
    .line 21
    move-result-wide v2

    .line 22
    new-instance v4, Lmy0/c;

    .line 23
    .line 24
    invoke-direct {v4, v2, v3}, Lmy0/c;-><init>(J)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v1, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    return-void
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->error:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPressTimeThreshold()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->pressTimeThreshold:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewModelControllerHashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelControllerHashCode:I

    .line 2
    .line 3
    return p0
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isClosable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isDriveActivationActionAllowed()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isDriveActivationActionAllowed:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isElectricalVehicle()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isElectricalVehicle:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isWaitingForResponse()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->isWaitingForResponse:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public startActivation()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/n;->startActivationIfAllowed()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public stopActivation()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;->viewModelController:Le81/n;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/n;->stopActivation()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
