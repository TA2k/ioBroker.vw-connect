.class public final Lcom/salesforce/marketingcloud/push/data/Style$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/Style;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field static final synthetic a:Lcom/salesforce/marketingcloud/push/data/Style$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/Style$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$a;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

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


# virtual methods
.method public final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/Style$b;
    .locals 10

    const-string p0, "json"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    const-string p0, "fc"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    const-string v0, "optString(...)"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    const/4 v1, 0x0

    const-string v2, "#"

    if-eqz p0, :cond_0

    .line 2
    invoke-static {p0, v2, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v3

    if-nez v3, :cond_0

    .line 3
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    :cond_0
    move-object v4, p0

    .line 4
    const-string p0, "bgc"

    .line 5
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 6
    invoke-static {p0, v2, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-nez v1, :cond_1

    .line 7
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    :cond_1
    move-object v5, p0

    .line 8
    const-string p0, "fz"

    .line 9
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    const/4 v1, 0x0

    if-eqz p0, :cond_2

    .line 10
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/Style$Size;->Companion:Lcom/salesforce/marketingcloud/push/data/Style$Size$a;

    invoke-virtual {v2, p0}, Lcom/salesforce/marketingcloud/push/data/Style$Size$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Style$Size;

    move-result-object p0

    move-object v6, p0

    goto :goto_0

    :cond_2
    move-object v6, v1

    .line 11
    :goto_0
    const-string p0, "an"

    .line 12
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_3

    .line 13
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/Style$Alignment;->Companion:Lcom/salesforce/marketingcloud/push/data/Style$Alignment$a;

    invoke-virtual {v2, p0}, Lcom/salesforce/marketingcloud/push/data/Style$Alignment$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object p0

    move-object v7, p0

    goto :goto_1

    :cond_3
    move-object v7, v1

    .line 14
    :goto_1
    const-string p0, "fs"

    .line 15
    invoke-static {p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_4

    .line 16
    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;->Companion:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle$a;

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/push/data/Style$FontStyle$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    move-result-object v1

    :cond_4
    move-object v8, v1

    .line 17
    new-instance v3, Lcom/salesforce/marketingcloud/push/data/Style$b;

    const/4 v9, 0x0

    invoke-direct/range {v3 .. v9}, Lcom/salesforce/marketingcloud/push/data/Style$b;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)V

    return-object v3
.end method

.method public final a(Lcom/salesforce/marketingcloud/push/data/Style;)Lorg/json/JSONObject;
    .locals 3

    const-string p0, "style"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 31
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Style;->g()Ljava/lang/String;

    move-result-object v0

    const-string v1, "fc"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 32
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    move-result-object v0

    const-string v1, "bgc"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 33
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Style;->c()Lcom/salesforce/marketingcloud/push/data/Style$Size;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    const-string v2, "fz"

    invoke-virtual {p0, v2, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 34
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Style;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v0

    goto :goto_1

    :cond_1
    move-object v0, v1

    :goto_1
    const-string v2, "an"

    invoke-virtual {p0, v2, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 35
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Style;->b()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    :cond_2
    const-string p1, "fs"

    invoke-virtual {p0, p1, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    return-object p0
.end method
