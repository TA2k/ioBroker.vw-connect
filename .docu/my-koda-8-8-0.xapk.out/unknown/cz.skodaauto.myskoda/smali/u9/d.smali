.class public final Lu9/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/analytics/piwama/m;


# instance fields
.field public final a:Lu9/e;

.field public final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lu9/d;->c:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lu9/e;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu9/d;->a:Lu9/e;

    .line 5
    .line 6
    iput p2, p0, Lu9/d;->b:I

    .line 7
    .line 8
    return-void
.end method
