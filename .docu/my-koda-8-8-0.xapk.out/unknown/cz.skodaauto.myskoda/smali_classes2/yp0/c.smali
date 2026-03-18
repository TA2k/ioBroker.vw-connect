.class public final synthetic Lyp0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;
.implements Laq/e;


# instance fields
.field public final synthetic d:Lyp0/h;


# direct methods
.method public synthetic constructor <init>(Lyp0/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyp0/c;->d:Lyp0/h;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public getNotificationChannelId(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "<unused var>"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lyp0/c;->d:Lyp0/h;

    .line 12
    .line 13
    iget-object p2, p0, Lyp0/h;->c:Landroid/app/NotificationManager;

    .line 14
    .line 15
    iget-object p0, p0, Lyp0/h;->d:Lij0/a;

    .line 16
    .line 17
    sget-object v0, Lap0/a;->f:Lap0/a;

    .line 18
    .line 19
    const-string v1, "marketing"

    .line 20
    .line 21
    invoke-virtual {p2, v1}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    new-instance v2, Landroid/app/NotificationChannel;

    .line 28
    .line 29
    invoke-static {v0}, Lmx0/n;->y(Lap0/a;)I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    const/4 v4, 0x0

    .line 34
    new-array v5, v4, [Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Ljj0/f;

    .line 37
    .line 38
    invoke-virtual {p0, v3, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    const/4 v5, 0x4

    .line 43
    invoke-direct {v2, v1, v3, v5}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0}, Lmx0/n;->x(Lap0/a;)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    new-array v3, v4, [Ljava/lang/Object;

    .line 51
    .line 52
    invoke-virtual {p0, v0, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {v2, p0}, Landroid/app/NotificationChannel;->setDescription(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x1

    .line 60
    invoke-virtual {v2, p0}, Landroid/app/NotificationChannel;->setShowBadge(Z)V

    .line 61
    .line 62
    .line 63
    const p0, 0x7f0603b2

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, p0}, Landroid/content/Context;->getColor(I)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    invoke-virtual {v2, p0}, Landroid/app/NotificationChannel;->setLightColor(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p2, v2}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 74
    .line 75
    .line 76
    :cond_0
    return-object v1
.end method

.method public onComplete(Laq/j;)V
    .locals 2

    .line 1
    const-string v0, "tokenTask"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const-string v0, "getResult(...)"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    check-cast p1, Ljava/lang/String;

    .line 22
    .line 23
    new-instance v0, Lq61/c;

    .line 24
    .line 25
    const/16 v1, 0x13

    .line 26
    .line 27
    invoke-direct {v0, p1, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 28
    .line 29
    .line 30
    const-string v1, "~$SFMCSdk"

    .line 31
    .line 32
    iget-object p0, p0, Lyp0/c;->d:Lyp0/h;

    .line 33
    .line 34
    invoke-static {v1, p0, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 35
    .line 36
    .line 37
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 38
    .line 39
    new-instance v0, Lod0/d;

    .line 40
    .line 41
    const/16 v1, 0xd

    .line 42
    .line 43
    invoke-direct {v0, p1, v1}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 44
    .line 45
    .line 46
    new-instance p1, Lnd0/c;

    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    invoke-direct {p1, v1, v0}, Lnd0/c;-><init>(ILay0/k;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->requestSdk(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    return-void
.end method
