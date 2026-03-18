.class Lcom/salesforce/marketingcloud/media/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/media/o;

.field private final b:Lcom/salesforce/marketingcloud/media/s;

.field private final c:Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final d:Lcom/salesforce/marketingcloud/media/f;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Ljava/util/Collection;Lcom/salesforce/marketingcloud/media/s;Lcom/salesforce/marketingcloud/media/f;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/media/o;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/media/s;",
            "Lcom/salesforce/marketingcloud/media/f;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/d;->a:Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/d;->c:Ljava/util/Collection;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/d;->b:Lcom/salesforce/marketingcloud/media/s;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/media/d;->d:Lcom/salesforce/marketingcloud/media/f;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/media/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/d;->b:Lcom/salesforce/marketingcloud/media/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public b()Lcom/salesforce/marketingcloud/media/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/d;->d:Lcom/salesforce/marketingcloud/media/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public c()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/d;->a:Lcom/salesforce/marketingcloud/media/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public d()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/d;->c:Ljava/util/Collection;

    .line 2
    .line 3
    return-object p0
.end method
