.class Lcom/salesforce/marketingcloud/analytics/piwama/j$a;
.super Landroidx/collection/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/analytics/piwama/j;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 3
    .line 4
    .line 5
    const-string v0, "Content-Type"

    .line 6
    .line 7
    const-string v1, "application/json; charset=utf-8"

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    const-string v0, "Connection"

    .line 13
    .line 14
    const-string v1, "close"

    .line 15
    .line 16
    invoke-virtual {p0, v0, v1}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-void
.end method
