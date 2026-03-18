.class public interface abstract Lorg/altbeacon/beacon/Settings$ScanStrategy;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "ScanStrategy"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u000f\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001J\u000f\u0010\u0002\u001a\u00020\u0000H&\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "",
        "clone",
        "()Lorg/altbeacon/beacon/Settings$ScanStrategy;",
        "Lorg/altbeacon/beacon/BeaconManager;",
        "beaconManager",
        "Llx0/b0;",
        "configure",
        "(Lorg/altbeacon/beacon/BeaconManager;)V",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;
.end method

.method public abstract configure(Lorg/altbeacon/beacon/BeaconManager;)V
.end method
