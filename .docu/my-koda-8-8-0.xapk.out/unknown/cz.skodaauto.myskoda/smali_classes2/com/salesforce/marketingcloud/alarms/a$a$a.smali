.class final enum Lcom/salesforce/marketingcloud/alarms/a$a$a;
.super Lcom/salesforce/marketingcloud/alarms/a$a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/alarms/a$a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4011
    name = null
.end annotation


# instance fields
.field private n:J


# direct methods
.method public synthetic constructor <init>()V
    .locals 3

    .line 1
    const/16 v0, 0x9

    const v1, 0xddf3c

    const-string v2, "DELIVERY_RECEIPT"

    invoke-direct {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/alarms/a$a$a;-><init>(Ljava/lang/String;II)V

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/alarms/a$a;-><init>(Ljava/lang/String;III)V

    const-wide/16 p1, 0x2710

    .line 3
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/alarms/a$a$a;->n:J

    return-void
.end method


# virtual methods
.method public a(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/alarms/a$a$a;->n:J

    .line 2
    .line 3
    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/alarms/a;
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/alarms/a$c;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/alarms/a$a;->c()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/alarms/a$a$a;->n:J

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/alarms/a$c;-><init>(IJ)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
