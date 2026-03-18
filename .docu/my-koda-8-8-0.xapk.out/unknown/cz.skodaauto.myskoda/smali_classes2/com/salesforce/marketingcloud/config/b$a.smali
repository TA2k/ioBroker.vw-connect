.class public final Lcom/salesforce/marketingcloud/config/b$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/config/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/config/b$a;-><init>()V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/config/b$a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/config/b;
    .locals 1

    and-int/lit8 p5, p4, 0x2

    const/4 v0, 0x0

    if-eqz p5, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    move-object p3, v0

    .line 3
    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/config/b$a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)Lcom/salesforce/marketingcloud/config/b;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b;
    .locals 7

    .line 1
    const-string v0, "endpointIn"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x6

    const/4 v6, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/config/b$a;->a(Lcom/salesforce/marketingcloud/config/b$a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/config/b;

    move-result-object p0

    return-object p0
.end method

.method public final a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b;
    .locals 7

    .line 2
    const-string v0, "endpointIn"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x4

    const/4 v6, 0x0

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/config/b$a;->a(Lcom/salesforce/marketingcloud/config/b$a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/config/b;

    move-result-object p0

    return-object p0
.end method

.method public final a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)Lcom/salesforce/marketingcloud/config/b;
    .locals 5

    const-string p0, "endpointIn"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-static {p1}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    if-eqz p1, :cond_6

    invoke-static {}, Lcom/salesforce/marketingcloud/config/b$b;->values()[Lcom/salesforce/marketingcloud/config/b$b;

    move-result-object p1

    invoke-static {p0}, Lcom/salesforce/marketingcloud/config/b$b;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b$b;

    move-result-object v0

    invoke-static {v0, p1}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_6

    const-string p1, " endpoint config."

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    .line 6
    invoke-static {p2}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_1

    .line 7
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v1

    if-eqz v1, :cond_0

    const-string v1, "/"

    const/4 v2, 0x0

    .line 8
    invoke-static {p2, v1, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 9
    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v1

    invoke-virtual {v1}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    move-result-object v1

    .line 10
    invoke-virtual {p2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    .line 11
    :cond_0
    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string p3, "Invalid \'path\' for "

    .line 12
    invoke-static {p3, p0, p1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 13
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    move-object p2, v0

    :goto_0
    const/4 v1, 0x1

    if-nez p3, :cond_2

    goto :goto_1

    .line 14
    :cond_2
    new-instance v2, Lgy0/j;

    const/16 v3, 0xa

    const v4, 0x7fffffff

    .line 15
    invoke-direct {v2, v3, v4, v1}, Lgy0/h;-><init>(III)V

    .line 16
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    move-result v1

    invoke-virtual {v2, v1}, Lgy0/j;->i(I)Z

    move-result v1

    :goto_1
    if-eqz v1, :cond_5

    if-nez p2, :cond_4

    if-eqz p3, :cond_3

    goto :goto_2

    .line 17
    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Empty endpoint config for "

    const-string p3, " is pointless."

    .line 18
    invoke-static {p2, p0, p3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 19
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 20
    :cond_4
    :goto_2
    new-instance p1, Lcom/salesforce/marketingcloud/config/b;

    invoke-direct {p1, p0, p2, p3, v0}, Lcom/salesforce/marketingcloud/config/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Lkotlin/jvm/internal/g;)V

    return-object p1

    .line 21
    :cond_5
    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string p3, "Invalid \'maxBatchSize\' for "

    .line 22
    invoke-static {p3, p0, p1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 23
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    .line 24
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Invalid \'endpoint\' for endpoint config."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method
