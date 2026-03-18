.class Lcom/salesforce/marketingcloud/media/n$b;
.super Lcom/salesforce/marketingcloud/media/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/n;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/v;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/v$a;)V
    .locals 0

    .line 2
    new-instance p0, Lcom/salesforce/marketingcloud/media/k;

    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/media/k;-><init>(Lcom/salesforce/marketingcloud/media/t;)V

    invoke-interface {p3, p0}, Lcom/salesforce/marketingcloud/media/v$a;->a(Ljava/lang/Throwable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/t;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    return p0
.end method
