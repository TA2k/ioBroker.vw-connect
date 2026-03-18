.class final Lcom/salesforce/marketingcloud/alarms/a$c;
.super Lcom/salesforce/marketingcloud/alarms/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/alarms/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "c"
.end annotation


# direct methods
.method public constructor <init>(IJ)V
    .locals 11

    .line 1
    const-wide/high16 v6, 0x3ff0000000000000L    # 1.0

    .line 2
    .line 3
    const/4 v10, 0x0

    .line 4
    const-string v2, "et_delivery_receipt_alarm_created_date"

    .line 5
    .line 6
    const-string v3, "et_delivery_receipt_alarm_interval"

    .line 7
    .line 8
    move-wide v8, p2

    .line 9
    move-object v0, p0

    .line 10
    move v1, p1

    .line 11
    move-wide v4, p2

    .line 12
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/alarms/a;-><init>(ILjava/lang/String;Ljava/lang/String;JDJZ)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
