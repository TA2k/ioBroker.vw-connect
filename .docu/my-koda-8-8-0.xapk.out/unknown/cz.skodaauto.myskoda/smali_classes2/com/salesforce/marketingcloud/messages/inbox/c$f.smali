.class Lcom/salesforce/marketingcloud/messages/inbox/c$f;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/lang/String;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$f;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$f;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$f;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$f;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->setMessageRead(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
