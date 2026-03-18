.class public interface abstract Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx61/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0006\u0010\u0004J\u000f\u0010\u0007\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0004J\u000f\u0010\u0008\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0008\u0010\u0004R\u001c\u0010\r\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\n0\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u000cR\u001a\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000f\u0010\u000cR\u001a\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00110\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0012\u0010\u000cR\u001a\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u00110\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u000cR\u001a\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00140\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0015\u0010\u000c\u00a8\u0006\u0017\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;",
        "Lx61/a;",
        "Llx0/b0;",
        "startCorrectionMoveForward",
        "()V",
        "stopCorrectionMoveForward",
        "startCorrectionMoveBackward",
        "stopCorrectionMoveBackward",
        "stopParking",
        "Lyy0/a2;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "getError",
        "()Lyy0/a2;",
        "error",
        "Lt71/d;",
        "getDriveMovementStatus",
        "driveMovementStatus",
        "",
        "isDriveForwardPossible",
        "isDriveBackwardPossible",
        "Ls71/h;",
        "getParkingManeuverStatus",
        "parkingManeuverStatus",
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

.method public abstract getDriveMovementStatus()Lyy0/a2;
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

.method public abstract synthetic isClosable()Lyy0/a2;
.end method

.method public abstract isDriveBackwardPossible()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isDriveForwardPossible()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract startCorrectionMoveBackward()V
.end method

.method public abstract startCorrectionMoveForward()V
.end method

.method public abstract stopCorrectionMoveBackward()V
.end method

.method public abstract stopCorrectionMoveForward()V
.end method

.method public abstract stopParking()V
.end method
