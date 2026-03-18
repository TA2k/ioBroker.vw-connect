.class Lcom/salesforce/marketingcloud/messages/iam/m$a;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/m;->showMessage(Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/lang/String;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/iam/m;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->c:Ljava/lang/String;

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
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->c:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 16
    .line 17
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    .line 19
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/e;->a(Ljava/util/Collection;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->d:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/messages/iam/m;->d(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 36
    .line 37
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$a;->c:Ljava/lang/String;

    .line 38
    .line 39
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    const-string v1, "Unable to find InAppMessage for message id [%s]"

    .line 44
    .line 45
    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
