.class public abstract Lcom/salesforce/marketingcloud/push/data/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/data/a$a;,
        Lcom/salesforce/marketingcloud/push/data/a$b;,
        Lcom/salesforce/marketingcloud/push/data/a$c;,
        Lcom/salesforce/marketingcloud/push/data/a$d;,
        Lcom/salesforce/marketingcloud/push/data/a$e;,
        Lcom/salesforce/marketingcloud/push/data/a$f;,
        Lcom/salesforce/marketingcloud/push/data/a$g;
    }
.end annotation


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/push/data/a$b;


# instance fields
.field private final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/a$b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/data/a$b;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/a;->c:Lcom/salesforce/marketingcloud/push/data/a$b;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(I)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Lcom/salesforce/marketingcloud/push/data/a;->b:I

    return-void
.end method

.method public synthetic constructor <init>(ILkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/data/a;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/push/data/a;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public final j()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Lcom/salesforce/marketingcloud/push/data/a;->b:I

    .line 7
    .line 8
    const-string v2, "t"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    instance-of v1, p0, Lcom/salesforce/marketingcloud/push/data/a$c;

    .line 14
    .line 15
    const-string v2, "ul"

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    check-cast p0, Lcom/salesforce/marketingcloud/push/data/a$c;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/a$c;->l()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :cond_0
    instance-of v1, p0, Lcom/salesforce/marketingcloud/push/data/a$g;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    check-cast p0, Lcom/salesforce/marketingcloud/push/data/a$g;

    .line 34
    .line 35
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/a$g;->l()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 40
    .line 41
    .line 42
    return-object v0

    .line 43
    :cond_1
    instance-of v1, p0, Lcom/salesforce/marketingcloud/push/data/a$a;

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    check-cast p0, Lcom/salesforce/marketingcloud/push/data/a$a;

    .line 48
    .line 49
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/a$a;->l()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    .line 55
    .line 56
    :cond_2
    return-object v0
.end method
