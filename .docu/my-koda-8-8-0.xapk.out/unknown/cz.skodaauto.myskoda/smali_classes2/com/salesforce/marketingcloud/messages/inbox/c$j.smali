.class Lcom/salesforce/marketingcloud/messages/inbox/c$j;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->markAllMessagesDeleted()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$j;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$j;->c:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/storage/f;->b()V

    .line 10
    .line 11
    .line 12
    return-void
.end method
