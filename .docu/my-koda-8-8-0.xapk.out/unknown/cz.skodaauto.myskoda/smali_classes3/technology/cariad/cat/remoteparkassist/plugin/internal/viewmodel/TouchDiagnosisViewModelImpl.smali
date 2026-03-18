.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv61/a;
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;
.implements Lz71/j;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u000b\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000f\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B\u0019\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0017\u0010\u000f\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0017\u0010\u0012\u001a\u00020\n2\u0006\u0010\u0011\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0010J\u0017\u0010\u0015\u001a\u00020\n2\u0006\u0010\u0014\u001a\u00020\u0013H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0017\u0010\u0018\u001a\u00020\n2\u0006\u0010\u0017\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0010J\u0019\u0010\u001b\u001a\u00020\n2\u0008\u0010\u001a\u001a\u0004\u0018\u00010\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u000f\u0010\u001d\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001d\u0010\u000cJ\u000f\u0010\u001e\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u000cJ\u000f\u0010\u001f\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001f\u0010\u000cJ\u000f\u0010 \u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008 \u0010\u000cR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010!R\u001a\u0010\u0007\u001a\u00020\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\"\u001a\u0004\u0008#\u0010$R\u001c\u0010&\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00190%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008&\u0010\'R\"\u0010)\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00190(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008)\u0010*\u001a\u0004\u0008+\u0010,R\u001a\u0010-\u001a\u0008\u0012\u0004\u0012\u00020\r0%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008-\u0010\'R \u0010.\u001a\u0008\u0012\u0004\u0012\u00020\r0(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008.\u0010*\u001a\u0004\u0008.\u0010,R\u001a\u0010/\u001a\u0008\u0012\u0004\u0012\u00020\r0%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008/\u0010\'R \u00100\u001a\u0008\u0012\u0004\u0012\u00020\r0(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00080\u0010*\u001a\u0004\u00080\u0010,R\u001a\u00101\u001a\u0008\u0012\u0004\u0012\u00020\r0%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00081\u0010\'R \u00102\u001a\u0008\u0012\u0004\u0012\u00020\r0(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00082\u0010*\u001a\u0004\u00082\u0010,R\u001a\u00103\u001a\u0008\u0012\u0004\u0012\u00020\u00130%8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00083\u0010\'R \u00104\u001a\u0008\u0012\u0004\u0012\u00020\u00130(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00084\u0010*\u001a\u0004\u00085\u0010,R \u00106\u001a\u0008\u0012\u0004\u0012\u00020\r0(8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00086\u0010*\u001a\u0004\u00086\u0010,\u00a8\u00067"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;",
        "Lv61/a;",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;",
        "Lz71/j;",
        "Le81/s;",
        "viewModelController",
        "",
        "viewModelControllerHashCode",
        "<init>",
        "(Le81/s;I)V",
        "Llx0/b0;",
        "close",
        "()V",
        "",
        "isInProgress",
        "touchDiagnosisIsUnlockActionInProgressDidChange",
        "(Z)V",
        "isEnabled",
        "touchDiagnosisIsUnlockActionEnabledDidChange",
        "Ls71/h;",
        "newStatus",
        "touchDiagnosisParkingManeuverStatusDidChange",
        "(Ls71/h;)V",
        "isExceeded",
        "touchDiagnosisIsUnlockTouchThresholdExceeded",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "newErrorStatus",
        "touchDiagnosisErrorDidChange",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
        "startUnlock",
        "cancelUnlock",
        "finishUnlock",
        "closeRPAModule",
        "Le81/s;",
        "I",
        "getViewModelControllerHashCode",
        "()I",
        "Lyy0/j1;",
        "_error",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "error",
        "Lyy0/a2;",
        "getError",
        "()Lyy0/a2;",
        "_isUnlockActionInProgress",
        "isUnlockActionInProgress",
        "_isUnlockActionEnabled",
        "isUnlockActionEnabled",
        "_isUnlockTouchThresholdExceeded",
        "isUnlockTouchThresholdExceeded",
        "_parkingManeuverStatus",
        "parkingManeuverStatus",
        "getParkingManeuverStatus",
        "isClosable",
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

.field private final _isUnlockActionEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isUnlockActionInProgress:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isUnlockTouchThresholdExceeded:Lyy0/j1;
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

.field private final isUnlockActionEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isUnlockActionInProgress:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isUnlockTouchThresholdExceeded:Lyy0/a2;
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

.field private final viewModelController:Le81/s;

.field private final viewModelControllerHashCode:I


# direct methods
.method public constructor <init>(Le81/s;I)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 3
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelControllerHashCode:I

    const/4 p2, 0x0

    .line 4
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_error:Lyy0/j1;

    .line 5
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->error:Lyy0/a2;

    .line 7
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockActionInProgress:Lyy0/j1;

    .line 8
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 9
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockActionInProgress:Lyy0/a2;

    .line 10
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockActionEnabled:Lyy0/j1;

    .line 11
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 12
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockActionEnabled:Lyy0/a2;

    .line 13
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockTouchThresholdExceeded:Lyy0/j1;

    .line 14
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockTouchThresholdExceeded:Lyy0/a2;

    .line 16
    sget-object p2, Ls71/h;->d:Ls71/h;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    .line 17
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 18
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 19
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    .line 20
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 21
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isClosable:Lyy0/a2;

    const/4 p2, 0x1

    .line 22
    invoke-interface {p1, p0, p2}, Le81/s;->addObserver(Lz71/j;Z)V

    .line 23
    invoke-interface {p1}, Lz71/h;->onAppear()V

    return-void
.end method

.method public synthetic constructor <init>(Le81/s;IILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 24
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result p2

    .line 25
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;-><init>(Le81/s;I)V

    return-void
.end method


# virtual methods
.method public cancelUnlock()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/s;->cancelUnlock()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 2
    .line 3
    invoke-interface {v0}, Lz71/h;->onDisappear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 7
    .line 8
    invoke-interface {v0, p0}, Le81/s;->removeObserver(Lz71/j;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public closeRPAModule()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 2
    .line 3
    invoke-interface {p0}, Lz71/h;->closeScreen()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public finishUnlock()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/s;->finishUnlock()V

    .line 4
    .line 5
    .line 6
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->error:Lyy0/a2;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewModelControllerHashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelControllerHashCode:I

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isClosable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUnlockActionEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockActionEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUnlockActionInProgress()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockActionInProgress:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUnlockTouchThresholdExceeded()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->isUnlockTouchThresholdExceeded:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public startUnlock()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->viewModelController:Le81/s;

    .line 2
    .line 3
    invoke-interface {p0}, Le81/s;->startUnlock()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public touchDiagnosisErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_error:Lyy0/j1;

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

.method public touchDiagnosisIsUnlockActionEnabledDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockActionEnabled:Lyy0/j1;

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

.method public touchDiagnosisIsUnlockActionInProgressDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockActionInProgress:Lyy0/j1;

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

.method public touchDiagnosisIsUnlockTouchThresholdExceeded(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_isUnlockTouchThresholdExceeded:Lyy0/j1;

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

.method public touchDiagnosisParkingManeuverStatusDidChange(Ls71/h;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

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
