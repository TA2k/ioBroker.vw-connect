.class Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;->this$0:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;->this$0:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 2
    .line 3
    invoke-static {p1}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->d(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;->this$0:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 7
    .line 8
    invoke-static {p1}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->b(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)Landroid/content/Context;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;->this$0:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;

    .line 17
    .line 18
    invoke-static {p0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->c(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)Landroid/content/BroadcastReceiver;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
