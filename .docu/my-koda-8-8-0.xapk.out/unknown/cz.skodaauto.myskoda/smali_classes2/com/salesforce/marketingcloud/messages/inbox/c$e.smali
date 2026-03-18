.class Lcom/salesforce/marketingcloud/messages/inbox/c$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$e;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$e;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

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
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$e;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$e;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$e;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
