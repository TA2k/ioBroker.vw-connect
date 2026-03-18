.class public final Ly9/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lcom/salesforce/marketingcloud/analytics/piwama/m;

.field public static final f:Lcom/salesforce/marketingcloud/analytics/piwama/m;


# instance fields
.field public final a:I

.field public final b:I

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ly9/c0;->e:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 11
    .line 12
    const/16 v1, 0x1c

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Ly9/c0;->f:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Ly9/c0;->a:I

    .line 5
    .line 6
    iput p4, p0, Ly9/c0;->b:I

    .line 7
    .line 8
    iput-object p1, p0, Ly9/c0;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p2, p0, Ly9/c0;->d:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method
