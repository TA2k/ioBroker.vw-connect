.class Lcom/salesforce/marketingcloud/proximity/b$a;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/proximity/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/proximity/b;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/proximity/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/b$a;->a:Lcom/salesforce/marketingcloud/proximity/b;

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
    .locals 2

    .line 1
    const/4 p1, 0x0

    .line 2
    if-nez p2, :cond_0

    .line 3
    .line 4
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 5
    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string p2, "Received null intent."

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
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

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
    const-string p1, "com.salesforce.marketingcloud.proximity.BEACON_REGION_ENTERED"

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    const-string v1, "beaconRegion"

    .line 37
    .line 38
    if-nez p1, :cond_3

    .line 39
    .line 40
    const-string p1, "com.salesforce.marketingcloud.proximity.BEACON_REGION_EXITED"

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-nez p1, :cond_2

    .line 47
    .line 48
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 49
    .line 50
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    const-string p2, "Received unknown action: "

    .line 55
    .line 56
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b$a;->a:Lcom/salesforce/marketingcloud/proximity/b;

    .line 61
    .line 62
    invoke-virtual {p2, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Lcom/salesforce/marketingcloud/proximity/c;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/proximity/b;->b(Lcom/salesforce/marketingcloud/proximity/c;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/b$a;->a:Lcom/salesforce/marketingcloud/proximity/b;

    .line 73
    .line 74
    invoke-virtual {p2, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    check-cast p1, Lcom/salesforce/marketingcloud/proximity/c;

    .line 79
    .line 80
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/proximity/b;->a(Lcom/salesforce/marketingcloud/proximity/c;)V

    .line 81
    .line 82
    .line 83
    return-void
.end method
