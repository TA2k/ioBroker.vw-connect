.class public final Lcom/salesforce/marketingcloud/push/style/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/style/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field static final synthetic a:Lcom/salesforce/marketingcloud/push/style/a$a;

.field public static final b:F = 3.0f

.field public static final c:Ljava/lang/String; = "#333333"

.field private static final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/style/a$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/style/a$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/style/a$a;->a:Lcom/salesforce/marketingcloud/push/style/a$a;

    .line 7
    .line 8
    const-string v0, "ViewStyler"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/style/a$a;->d:Ljava/lang/String;

    .line 15
    .line 16
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
.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/push/style/a$a;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
