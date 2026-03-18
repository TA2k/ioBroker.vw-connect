.class public interface abstract Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx61/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\"\n\u0002\u0008\u0004\n\u0002\u0010 \n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0006\u0010\u0004J\u000f\u0010\u0007\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0004J\u000f\u0010\u0008\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0008\u0010\u0004J\u0017\u0010\u000b\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\tH&\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0017\u0010\u000f\u001a\u00020\u00022\u0006\u0010\u000e\u001a\u00020\rH&\u00a2\u0006\u0004\u0008\u000f\u0010\u0010R\u001a\u0010\u0015\u001a\u0008\u0012\u0004\u0012\u00020\u00120\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u001a\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0017\u0010\u0014R\u001a\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\u0014R\u001a\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0019\u0010\u0014R\u001a\u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001a\u0010\u0014R\u001c\u0010\u001d\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u001b0\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001c\u0010\u0014R\u001a\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001f\u0010\u0014R\u001a\u0010!\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\u0014R \u0010$\u001a\u0008\u0012\u0004\u0012\u00020\t0\u00118&X\u00a7\u0004\u00a2\u0006\u000c\u0012\u0004\u0008#\u0010\u0004\u001a\u0004\u0008\"\u0010\u0014R\u001a\u0010&\u001a\u0008\u0012\u0004\u0012\u00020\t0\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008%\u0010\u0014R\u001a\u0010\'\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\'\u0010\u0014R\u001a\u0010(\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008(\u0010\u0014R \u0010)\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a7\u0004\u00a2\u0006\u000c\u0012\u0004\u0008*\u0010\u0004\u001a\u0004\u0008)\u0010\u0014R\u001a\u0010+\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008+\u0010\u0014R \u0010.\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\t0,0\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008-\u0010\u0014R \u00100\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\t0,0\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008/\u0010\u0014R \u00103\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\r010\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00082\u0010\u0014R\u001a\u00106\u001a\u0008\u0012\u0004\u0012\u0002040\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00085\u0010\u0014R\u001c\u00109\u001a\n\u0012\u0006\u0012\u0004\u0018\u0001070\u00118&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00088\u0010\u0014\u00a8\u0006:\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;",
        "Lx61/a;",
        "Llx0/b0;",
        "startParking",
        "()V",
        "stopParking",
        "stopEngine",
        "startUndoingParkingRoute",
        "stopUndoingParkingRoute",
        "Ls71/k;",
        "newScenario",
        "requestScenarioSelection",
        "(Ls71/k;)V",
        "Ll71/y;",
        "newManeuver",
        "requestTrainedParkingSelection",
        "(Ll71/y;)V",
        "Lyy0/a2;",
        "Lx61/b;",
        "getScreenType",
        "()Lyy0/a2;",
        "screenType",
        "",
        "isParkActionPossible",
        "isUndoActionSupported",
        "isUndoActionPossible",
        "isInTargetPosition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "getError",
        "error",
        "Lt71/d;",
        "getDriveMovementStatus",
        "driveMovementStatus",
        "isDriving",
        "getCurrentScenarioSelection",
        "getCurrentScenarioSelection$annotations",
        "currentScenarioSelection",
        "getCurrentScenario",
        "currentScenario",
        "isWaitingForScenarioSelectionConfirmation",
        "isScenarioSelectionConfirmationSuccessful",
        "isScenarioSelectionRequestEnabled",
        "isScenarioSelectionRequestEnabled$annotations",
        "isSelectionDisabled",
        "",
        "getSupportedScenarios",
        "supportedScenarios",
        "getEnabledScenarios",
        "enabledScenarios",
        "",
        "getAvailableTPAManeuvers",
        "availableTPAManeuvers",
        "Ls71/h;",
        "getParkingManeuverStatus",
        "parkingManeuverStatus",
        "Lg61/u;",
        "getVehicleTrajectory",
        "vehicleTrajectory",
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

.method public abstract getAvailableTPAManeuvers()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getCurrentScenario()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getCurrentScenarioSelection()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getDriveMovementStatus()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getEnabledScenarios()Lyy0/a2;
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

.method public abstract getParkingManeuverStatus()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getScreenType()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getSupportedScenarios()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getVehicleTrajectory()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract synthetic isClosable()Lyy0/a2;
.end method

.method public abstract isDriving()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isInTargetPosition()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isParkActionPossible()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isScenarioSelectionConfirmationSuccessful()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isScenarioSelectionRequestEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isSelectionDisabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isUndoActionPossible()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isUndoActionSupported()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isWaitingForScenarioSelectionConfirmation()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract requestScenarioSelection(Ls71/k;)V
.end method

.method public abstract requestTrainedParkingSelection(Ll71/y;)V
.end method

.method public abstract startParking()V
.end method

.method public abstract startUndoingParkingRoute()V
.end method

.method public abstract stopEngine()V
.end method

.method public abstract stopParking()V
.end method

.method public abstract stopUndoingParkingRoute()V
.end method
