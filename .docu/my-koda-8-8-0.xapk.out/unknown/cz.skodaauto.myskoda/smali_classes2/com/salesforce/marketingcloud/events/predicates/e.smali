.class public final Lcom/salesforce/marketingcloud/events/predicates/e;
.super Lcom/salesforce/marketingcloud/events/predicates/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private e:[Lcom/salesforce/marketingcloud/events/predicates/f;


# direct methods
.method public varargs constructor <init>([Lcom/salesforce/marketingcloud/events/predicates/f;)V
    .locals 1

    .line 1
    const-string v0, "predicates"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/predicates/f;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/predicates/e;->e:[Lcom/salesforce/marketingcloud/events/predicates/f;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public a()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/predicates/e;->e:[Lcom/salesforce/marketingcloud/events/predicates/f;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/4 v1, 0x0

    .line 5
    move v2, v1

    .line 6
    :goto_0
    if-ge v2, v0, :cond_1

    .line 7
    .line 8
    aget-object v3, p0, v2

    .line 9
    .line 10
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/events/predicates/f;->b()Z

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    return p0

    .line 18
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    return v1
.end method

.method public c()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Or"

    .line 2
    .line 3
    return-object p0
.end method
