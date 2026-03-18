.class public final Landroidx/core/app/z;
.super Landroidx/core/app/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Lcom/google/firebase/messaging/w;)V
    .locals 0

    .line 1
    iget-object p0, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/app/Notification$Builder;

    .line 4
    .line 5
    invoke-static {}, Landroidx/core/app/y;->a()Landroid/app/Notification$Style;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Landroid/app/Notification$Builder;->setStyle(Landroid/app/Notification$Style;)Landroid/app/Notification$Builder;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "androidx.core.app.NotificationCompat$DecoratedCustomViewStyle"

    .line 2
    .line 3
    return-object p0
.end method
