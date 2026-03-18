.class final Lcom/salesforce/marketingcloud/http/a$b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/http/a;->a(Lcom/salesforce/marketingcloud/http/g;Lcom/salesforce/marketingcloud/http/g;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation


# instance fields
.field final synthetic b:I

.field final synthetic c:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/http/a$b;->b:I

    .line 2
    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/http/a$b;->c:I

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/http/a$b;->b:I

    .line 2
    .line 3
    iget p0, p0, Lcom/salesforce/marketingcloud/http/a$b;->c:I

    .line 4
    .line 5
    const-string v1, " bytes, Response size: "

    .line 6
    .line 7
    const-string v2, " bytes"

    .line 8
    .line 9
    const-string v3, "Request or response too large. Request size: "

    .line 10
    .line 11
    invoke-static {v0, p0, v3, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/http/a$b;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
