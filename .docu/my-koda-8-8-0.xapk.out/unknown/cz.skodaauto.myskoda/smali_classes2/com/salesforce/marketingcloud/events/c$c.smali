.class Lcom/salesforce/marketingcloud/events/c$c;
.super Ljava/util/ArrayList;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/events/c;->a(Lcom/salesforce/marketingcloud/events/h;)Ljava/util/Map;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/ArrayList<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic b:Lcom/salesforce/marketingcloud/events/h;

.field final synthetic c:Lcom/salesforce/marketingcloud/events/c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/events/c;Lcom/salesforce/marketingcloud/events/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c$c;->c:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/events/c$c;->b:Lcom/salesforce/marketingcloud/events/h;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object p1, p1, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    .line 10
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->q()Lcom/salesforce/marketingcloud/storage/m;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-interface {p1, p2}, Lcom/salesforce/marketingcloud/storage/m;->b(Lcom/salesforce/marketingcloud/events/h;)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    return-void
.end method
