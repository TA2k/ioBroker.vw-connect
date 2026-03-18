.class public final Lcom/salesforce/marketingcloud/internal/h$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/internal/h$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->getLastShownDate$sdk_release()Ljava/util/Date;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/Message;I)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->setNotificationId$sdk_release(I)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->setLastShownDate$sdk_release(Ljava/util/Date;)V

    return-void
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/Message;)Ljava/util/Date;
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->getNextAllowedShow$sdk_release()Ljava/util/Date;

    move-result-object p0

    return-object p0
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/Message;I)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->setPeriodShowCount$sdk_release(I)V

    return-void
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/Message;Ljava/util/Date;)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->setNextAllowedShow$sdk_release(Ljava/util/Date;)V

    return-void
.end method

.method public final c(Lcom/salesforce/marketingcloud/messages/Message;)I
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->getNotificationId$sdk_release()I

    move-result p0

    return p0
.end method

.method public final c(Lcom/salesforce/marketingcloud/messages/Message;I)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->setShowCount$sdk_release(I)V

    return-void
.end method

.method public final d(Lcom/salesforce/marketingcloud/messages/Message;)I
    .locals 0

    .line 1
    const-string p0, "message"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->getPeriodShowCount$sdk_release()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final e(Lcom/salesforce/marketingcloud/messages/Message;)I
    .locals 0

    .line 1
    const-string p0, "message"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Message;->getShowCount$sdk_release()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method
