.class Lcom/salesforce/marketingcloud/messages/proximity/a$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/proximity/a;->b()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/proximity/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$b;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

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
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$b;->c:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 v0, 0x3

    .line 10
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 11
    .line 12
    .line 13
    return-void
.end method
