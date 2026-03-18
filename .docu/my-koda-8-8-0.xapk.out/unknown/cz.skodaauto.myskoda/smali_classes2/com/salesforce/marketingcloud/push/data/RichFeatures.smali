.class public final Lcom/salesforce/marketingcloud/push/data/RichFeatures;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/RichFeatures;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

.field private static final TAG:Ljava/lang/String;


# instance fields
.field private final buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

.field private final largeIcon:Ljava/lang/String;

.field private final smallIcon:Ljava/lang/String;

.field private final viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    const-string v0, "RichFeatures"

    .line 17
    .line 18
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->TAG:Ljava/lang/String;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>()V
    .locals 7

    const/16 v5, 0xf

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    .line 1
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 6
    iput-object p4, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x1

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    move-object p2, v0

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    move-object p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    move-object p4, v0

    .line 7
    :cond_3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->copy(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static final fromJson(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcom/salesforce/marketingcloud/push/data/Template;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcom/salesforce/marketingcloud/push/buttons/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 47
    .line 48
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final getButtons()Lcom/salesforce/marketingcloud/push/buttons/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLargeIcon()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSmallIcon()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getViewTemplate()Lcom/salesforce/marketingcloud/push/data/Template;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v0, v2

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 28
    .line 29
    if-nez v2, :cond_2

    .line 30
    .line 31
    move v2, v1

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    :goto_2
    add-int/2addr v0, v2

    .line 38
    mul-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 41
    .line 42
    if-nez p0, :cond_3

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/buttons/a;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    :goto_3
    add-int/2addr v0, v1

    .line 50
    return v0
.end method

.method public final toJson()Ljava/lang/String;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    new-instance v1, Lorg/json/JSONObject;

    .line 3
    .line 4
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 5
    .line 6
    .line 7
    const-string v2, "lic"

    .line 8
    .line 9
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 12
    .line 13
    .line 14
    const-string v2, "sic"

    .line 15
    .line 16
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 22
    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    invoke-interface {v2}, Lcom/salesforce/marketingcloud/push/data/Template;->f()Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    sget-object v3, Lcom/salesforce/marketingcloud/push/j$a;->a:Lcom/salesforce/marketingcloud/push/j$a$a;

    .line 32
    .line 33
    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/push/j$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;)Lcom/salesforce/marketingcloud/push/j;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 40
    .line 41
    invoke-interface {v2, v3}, Lcom/salesforce/marketingcloud/push/j;->hydrate(Lcom/salesforce/marketingcloud/push/data/Template;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    if-eqz v2, :cond_0

    .line 46
    .line 47
    const-string v3, "vt"

    .line 48
    .line 49
    new-instance v4, Lorg/json/JSONObject;

    .line 50
    .line 51
    invoke-direct {v4, v2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catch_0
    move-exception v1

    .line 59
    goto :goto_2

    .line 60
    :cond_0
    :goto_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 61
    .line 62
    if-eqz v2, :cond_2

    .line 63
    .line 64
    const-string v3, "btn"

    .line 65
    .line 66
    new-instance v4, Lorg/json/JSONArray;

    .line 67
    .line 68
    sget-object v5, Lcom/salesforce/marketingcloud/push/j$a;->a:Lcom/salesforce/marketingcloud/push/j$a$a;

    .line 69
    .line 70
    sget-object v6, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 71
    .line 72
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/push/j$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;)Lcom/salesforce/marketingcloud/push/j;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    if-eqz v5, :cond_1

    .line 77
    .line 78
    invoke-interface {v5, v2}, Lcom/salesforce/marketingcloud/push/j;->hydrate(Lcom/salesforce/marketingcloud/push/data/Template;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    goto :goto_1

    .line 83
    :cond_1
    move-object v2, v0

    .line 84
    :goto_1
    invoke-direct {v4, v2}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 88
    .line 89
    .line 90
    :cond_2
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 94
    return-object p0

    .line 95
    :goto_2
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 96
    .line 97
    sget-object v3, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->TAG:Ljava/lang/String;

    .line 98
    .line 99
    new-instance v4, Lcom/salesforce/marketingcloud/push/data/RichFeatures$c;

    .line 100
    .line 101
    invoke-direct {v4, p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$c;-><init>(Lcom/salesforce/marketingcloud/push/data/RichFeatures;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v2, v3, v1, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 105
    .line 106
    .line 107
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 8
    .line 9
    const-string v3, ", smallIcon="

    .line 10
    .line 11
    const-string v4, ", viewTemplate="

    .line 12
    .line 13
    const-string v5, "RichFeatures(largeIcon="

    .line 14
    .line 15
    invoke-static {v5, v0, v3, v1, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", buttons="

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ")"

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->largeIcon:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->smallIcon:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->viewTemplate:Lcom/salesforce/marketingcloud/push/data/Template;

    .line 17
    .line 18
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->buttons:Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x0

    .line 26
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    const/4 v0, 0x1

    .line 31
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->writeToParcel(Landroid/os/Parcel;I)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
