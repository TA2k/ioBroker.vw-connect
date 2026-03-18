.class public final Lcom/salesforce/marketingcloud/push/m;
.super Lcom/salesforce/marketingcloud/push/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/f$a;->f:Lcom/salesforce/marketingcloud/push/f$a;

    .line 2
    .line 3
    const-string v1, "Unsupported widget type: "

    .line 4
    .line 5
    invoke-static {v1, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/push/f;-><init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
