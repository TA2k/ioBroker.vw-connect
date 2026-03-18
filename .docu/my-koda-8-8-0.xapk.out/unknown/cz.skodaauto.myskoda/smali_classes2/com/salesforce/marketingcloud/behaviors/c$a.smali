.class Lcom/salesforce/marketingcloud/behaviors/c$a;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/behaviors/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/behaviors/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/behaviors/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/behaviors/c$a;->a:Lcom/salesforce/marketingcloud/behaviors/c;

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
    .locals 1

    .line 1
    const/4 p1, 0x0

    .line 2
    if-nez p2, :cond_0

    .line 3
    .line 4
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 5
    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string p2, "Received null intent"

    .line 9
    .line 10
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    sget-object p0, Lcom/salesforce/marketingcloud/behaviors/c;->k:Ljava/lang/String;

    .line 21
    .line 22
    new-array p1, p1, [Ljava/lang/Object;

    .line 23
    .line 24
    const-string p2, "Received null action"

    .line 25
    .line 26
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    invoke-static {v0}, Lcom/salesforce/marketingcloud/behaviors/a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/behaviors/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    if-eqz p1, :cond_2

    .line 35
    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/behaviors/c$a;->a:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 37
    .line 38
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/behaviors/c;->onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 43
    .line 44
    .line 45
    :cond_2
    return-void
.end method
