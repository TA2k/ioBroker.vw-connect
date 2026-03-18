.class public final Lcom/salesforce/marketingcloud/http/f$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/http/f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field private a:I

.field private b:Ljava/lang/String;

.field private c:Ljava/lang/String;

.field private d:J

.field private e:J

.field private f:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(I)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->a:I

    return-object p0
.end method

.method public final a(J)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 3
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->e:J

    return-object p0
.end method

.method public final a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->b:Ljava/lang/String;

    return-object p0
.end method

.method public final a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;)",
            "Lcom/salesforce/marketingcloud/http/f$a;"
        }
    .end annotation

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->f:Ljava/util/Map;

    return-object p0
.end method

.method public final a()Lcom/salesforce/marketingcloud/http/f;
    .locals 9

    .line 5
    new-instance v0, Lcom/salesforce/marketingcloud/http/f;

    .line 6
    iget v1, p0, Lcom/salesforce/marketingcloud/http/f$a;->a:I

    .line 7
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/f$a;->b:Ljava/lang/String;

    .line 8
    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/f$a;->c:Ljava/lang/String;

    .line 9
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/http/f$a;->d:J

    .line 10
    iget-wide v6, p0, Lcom/salesforce/marketingcloud/http/f$a;->e:J

    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/f$a;->f:Ljava/util/Map;

    if-nez p0, :cond_0

    sget-object p0, Lmx0/t;->d:Lmx0/t;

    :cond_0
    move-object v8, p0

    .line 12
    invoke-direct/range {v0 .. v8}, Lcom/salesforce/marketingcloud/http/f;-><init>(ILjava/lang/String;Ljava/lang/String;JJLjava/util/Map;)V

    return-object v0
.end method

.method public final b(J)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 2
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->d:J

    return-object p0
.end method

.method public final b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/f$a;->c:Ljava/lang/String;

    return-object p0
.end method
