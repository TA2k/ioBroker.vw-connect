.class Lcom/salesforce/marketingcloud/messages/iam/f$a;
.super Lb/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/f;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/messages/iam/f;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/f;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/f$a;->a:Lcom/salesforce/marketingcloud/messages/iam/f;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lb/a0;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public handleOnBackPressed()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/f$a;->a:Lcom/salesforce/marketingcloud/messages/iam/f;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/iam/f;->g(Lcom/salesforce/marketingcloud/messages/iam/f;)Lcom/salesforce/marketingcloud/messages/iam/k;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/k;->k()Ljava/util/Date;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/f$a;->a:Lcom/salesforce/marketingcloud/messages/iam/f;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/iam/f;->a()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/messages/iam/j;->b(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/f;->h(Lcom/salesforce/marketingcloud/messages/iam/f;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-virtual {p0, v0}, Lb/a0;->setEnabled(Z)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/f$a;->a:Lcom/salesforce/marketingcloud/messages/iam/f;

    .line 29
    .line 30
    invoke-virtual {p0}, Lb/r;->getOnBackPressedDispatcher()Lb/h0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p0}, Lb/h0;->c()V

    .line 35
    .line 36
    .line 37
    return-void
.end method
