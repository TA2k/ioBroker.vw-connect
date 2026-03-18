.class public final Lcom/salesforce/marketingcloud/http/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/http/a;

.field private static final b:Ljava/lang/String; = "HttpUtils"

.field private static final c:I = 0xe1000


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/http/a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/http/a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/http/a;->a:Lcom/salesforce/marketingcloud/http/a;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final a(Lcom/salesforce/marketingcloud/http/g;Lcom/salesforce/marketingcloud/http/g;)Z
    .locals 9

    const-string v0, "request"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "response"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/http/a;->a:Lcom/salesforce/marketingcloud/http/a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/http/a;->a(Lcom/salesforce/marketingcloud/http/g;)I

    move-result p0

    .line 8
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/http/a;->a(Lcom/salesforce/marketingcloud/http/g;)I

    move-result p1

    const/4 v0, 0x0

    const/4 v1, -0x1

    if-eq p0, v1, :cond_2

    if-ne p1, v1, :cond_0

    goto :goto_0

    :cond_0
    add-int v1, p0, p1

    const v2, 0xe1000

    if-lt v1, v2, :cond_1

    .line 9
    sget-object v3, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    new-instance v6, Lcom/salesforce/marketingcloud/http/a$b;

    invoke-direct {v6, p0, p1}, Lcom/salesforce/marketingcloud/http/a$b;-><init>(II)V

    const/4 v7, 0x2

    const/4 v8, 0x0

    const-string v4, "HttpUtils"

    const/4 v5, 0x0

    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/g;->b(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    return v0

    :cond_1
    const/4 p0, 0x1

    return p0

    .line 10
    :cond_2
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v4, Lcom/salesforce/marketingcloud/http/a$a;->b:Lcom/salesforce/marketingcloud/http/a$a;

    const/4 v5, 0x2

    const/4 v6, 0x0

    const-string v2, "HttpUtils"

    const/4 v3, 0x0

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->b(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    return v0
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/http/g;)I
    .locals 2

    const-string p0, "sizeEstimatable"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    :try_start_0
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/http/g;->h()Landroid/os/Bundle;

    move-result-object p0

    .line 2
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object p1

    const-string v0, "obtain(...)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 3
    invoke-virtual {p0, p1, v0}, Landroid/os/Bundle;->writeToParcel(Landroid/os/Parcel;I)V

    .line 4
    invoke-virtual {p1}, Landroid/os/Parcel;->dataSize()I

    move-result p0

    .line 5
    invoke-virtual {p1}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 6
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v0, Lcom/salesforce/marketingcloud/http/a$c;->b:Lcom/salesforce/marketingcloud/http/a$c;

    const-string v1, "HttpUtils"

    invoke-virtual {p1, v1, p0, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    const/4 p0, -0x1

    return p0
.end method
