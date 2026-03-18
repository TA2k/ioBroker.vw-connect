.class public final Lcom/salesforce/marketingcloud/internal/d$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/d;
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/internal/d$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)Ljava/lang/String;
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getMessageHash$sdk_release()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setDeleted(Z)V

    return-void
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)Ljava/lang/String;
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getRequestId$sdk_release()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setDirty$sdk_release(Z)V

    return-void
.end method

.method public final c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)I
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getViewCount$sdk_release()I

    move-result p0

    return p0
.end method

.method public final c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->setRead(Z)V

    return-void
.end method
