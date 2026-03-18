.class Lcom/salesforce/marketingcloud/location/d$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/location/d;->e()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Laq/e;"
    }
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/location/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/location/d;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/d$a;->a:Lcom/salesforce/marketingcloud/location/d;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onComplete(Laq/j;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Laq/j;",
            ")V"
        }
    .end annotation

    .line 1
    sget-object p1, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    new-array v1, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v2, "Location request completed."

    .line 7
    .line 8
    invoke-static {p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/d$a;->a:Lcom/salesforce/marketingcloud/location/d;

    .line 12
    .line 13
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/location/d;->b:Z

    .line 14
    .line 15
    return-void
.end method
