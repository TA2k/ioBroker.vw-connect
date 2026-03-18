.class public final Lcom/salesforce/marketingcloud/push/l;
.super Lcom/salesforce/marketingcloud/push/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    const-string v0, "cause"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lcom/salesforce/marketingcloud/push/f$a;->b:Lcom/salesforce/marketingcloud/push/f$a;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v1, "Unknown error occurred: "

    .line 13
    .line 14
    invoke-static {v1, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/push/f;-><init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
