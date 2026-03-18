.class Lcom/salesforce/marketingcloud/messages/iam/d$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/iam/d;->a(Landroid/view/View;Lcom/salesforce/marketingcloud/messages/iam/k;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/util/Comparator<",
        "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/messages/iam/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/d;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/d$a;->a:Lcom/salesforce/marketingcloud/messages/iam/d;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;->index()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    sub-int/2addr p0, p1

    .line 10
    return p0
.end method

.method public bridge synthetic compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 2
    .line 3
    check-cast p2, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/d$a;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
