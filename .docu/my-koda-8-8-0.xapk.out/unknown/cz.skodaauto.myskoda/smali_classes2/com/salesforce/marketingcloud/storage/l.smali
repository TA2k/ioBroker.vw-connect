.class public abstract Lcom/salesforce/marketingcloud/storage/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field protected static final f:Ljava/lang/String;

.field protected static final g:I = -0x1

.field protected static final h:Ljava/lang/String; = "create_date"

.field private static final i:Ljava/lang/String; = "mcsdk_%s"


# instance fields
.field protected final a:Ljava/lang/String;

.field protected final b:Landroid/content/Context;

.field protected final c:Lcom/salesforce/marketingcloud/util/Crypto;

.field private final d:Ljava/lang/String;

.field private final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "Storage"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/l;->f:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "Application ID is null."

    .line 5
    .line 6
    invoke-static {p3, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    const-string v1, "Application ID is empty."

    .line 13
    .line 14
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Ljava/lang/String;

    .line 19
    .line 20
    iput-object v0, p0, Lcom/salesforce/marketingcloud/storage/l;->d:Ljava/lang/String;

    .line 21
    .line 22
    const-string v0, "Access Token is null."

    .line 23
    .line 24
    invoke-static {p4, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p4

    .line 28
    check-cast p4, Ljava/lang/String;

    .line 29
    .line 30
    const-string v0, "Access Token is empty."

    .line 31
    .line 32
    invoke-static {p4, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 33
    .line 34
    .line 35
    move-result-object p4

    .line 36
    check-cast p4, Ljava/lang/String;

    .line 37
    .line 38
    iput-object p4, p0, Lcom/salesforce/marketingcloud/storage/l;->e:Ljava/lang/String;

    .line 39
    .line 40
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/l;->b:Landroid/content/Context;

    .line 41
    .line 42
    iput-object p2, p0, Lcom/salesforce/marketingcloud/storage/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 43
    .line 44
    iput-object p3, p0, Lcom/salesforce/marketingcloud/storage/l;->a:Ljava/lang/String;

    .line 45
    .line 46
    return-void
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    const-string v0, "mcsdk_"

    .line 2
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public abstract a()Landroid/content/Context;
.end method

.method public abstract a(Landroid/content/SharedPreferences;)Z
.end method

.method public abstract b()Lcom/salesforce/marketingcloud/util/Crypto;
.end method

.method public abstract c()Lcom/salesforce/marketingcloud/storage/b;
.end method

.method public abstract d()Landroid/database/sqlite/SQLiteOpenHelper;
.end method

.method public abstract e()Landroid/content/SharedPreferences;
.end method
