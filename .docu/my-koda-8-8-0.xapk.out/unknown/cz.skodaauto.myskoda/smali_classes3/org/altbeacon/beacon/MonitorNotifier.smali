.class public interface abstract Lorg/altbeacon/beacon/MonitorNotifier;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final INSIDE:I = 0x1

.field public static final OUTSIDE:I


# virtual methods
.method public abstract didDetermineStateForRegion(ILorg/altbeacon/beacon/Region;)V
.end method

.method public abstract didEnterRegion(Lorg/altbeacon/beacon/Region;)V
.end method

.method public abstract didExitRegion(Lorg/altbeacon/beacon/Region;)V
.end method
