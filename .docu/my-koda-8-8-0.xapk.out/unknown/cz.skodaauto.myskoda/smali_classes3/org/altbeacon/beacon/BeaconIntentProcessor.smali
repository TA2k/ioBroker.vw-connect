.class public Lorg/altbeacon/beacon/BeaconIntentProcessor;
.super Landroid/app/IntentService;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "BeaconIntentProcessor"


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    const-string v0, "BeaconIntentProcessor"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Landroid/app/IntentService;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onHandleIntent(Landroid/content/Intent;)V
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/IntentHandler;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/IntentHandler;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {v0, p0, p1}, Lorg/altbeacon/beacon/IntentHandler;->convertIntentsToCallbacks(Landroid/content/Context;Landroid/content/Intent;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
