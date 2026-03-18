.class public final Lcom/salesforce/marketingcloud/push/c;
.super Lcom/salesforce/marketingcloud/push/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lcom/salesforce/marketingcloud/push/f$a;->d:Lcom/salesforce/marketingcloud/push/f$a;

    .line 7
    .line 8
    const-string v1, "Invalid compression: "

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/push/f;-><init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
