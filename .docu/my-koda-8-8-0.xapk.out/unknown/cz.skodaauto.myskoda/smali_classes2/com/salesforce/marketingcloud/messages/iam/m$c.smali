.class Lcom/salesforce/marketingcloud/messages/iam/m$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/m;->a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/iam/m;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m$c;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

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
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$c;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m$c;->c:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {v1, p0}, Lcom/salesforce/marketingcloud/storage/e;->d(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Ljava/util/List;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
