.class public Lcom/salesforce/marketingcloud/analytics/stats/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:I = 0x64

.field public static final g:I = 0x65

.field public static final h:I = 0x66

.field public static final i:I = 0x67

.field public static final j:I = 0x68

.field public static final k:I = 0x69

.field public static final l:I = 0x6a

.field public static final m:I = 0x6b

.field public static final n:I = 0x6e

.field public static final o:I = 0x6f

.field public static final p:I = 0x70


# instance fields
.field private final a:Ljava/lang/Integer;

.field private final b:I

.field private final c:Ljava/util/Date;

.field d:Lcom/salesforce/marketingcloud/analytics/stats/d;

.field private e:Z


# direct methods
.method private constructor <init>(Ljava/lang/Integer;ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->a:Ljava/lang/Integer;

    .line 5
    .line 6
    iput p2, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->c:Ljava/util/Date;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->d:Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 11
    .line 12
    iput-boolean p5, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->e:Z

    .line 13
    .line 14
    return-void
.end method

.method public static a(IILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;
    .locals 6

    .line 2
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/stats/b;

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    move v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/stats/b;-><init>(Ljava/lang/Integer;ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)V

    return-object v0
.end method

.method public static a(ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;
    .locals 6

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/stats/b;

    const/4 v1, 0x0

    move v2, p0

    move-object v3, p1

    move-object v4, p2

    move v5, p3

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/stats/b;-><init>(Ljava/lang/Integer;ILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)V

    return-object v0
.end method


# virtual methods
.method public a()Ljava/util/Date;
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->c:Ljava/util/Date;

    return-object p0
.end method

.method public a(Ljava/util/Date;)V
    .locals 4

    .line 5
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->c:Ljava/util/Date;

    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v2

    sub-long/2addr v0, v2

    long-to-double v0, v0

    const-wide v2, 0x408f400000000000L    # 1000.0

    div-double/2addr v0, v2

    double-to-int p1, v0

    const/4 v0, 0x1

    if-gtz p1, :cond_0

    move p1, v0

    .line 6
    :cond_0
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->d:Lcom/salesforce/marketingcloud/analytics/stats/d;

    if-eqz v1, :cond_1

    .line 7
    invoke-virtual {v1, p1}, Lcom/salesforce/marketingcloud/analytics/stats/d;->b(I)V

    .line 8
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->e:Z
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    goto :goto_0

    :cond_1
    return-void

    .line 9
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/stats/c;->k:Ljava/lang/String;

    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->b:I

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v1, "Unable to finalize event [%d]"

    invoke-static {v0, p1, v1, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Z)V
    .locals 0

    .line 4
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->e:Z

    return-void
.end method

.method public b()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public c()Lcom/salesforce/marketingcloud/analytics/stats/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->d:Lcom/salesforce/marketingcloud/analytics/stats/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public d()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public e()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/analytics/stats/b;->e:Z

    .line 2
    .line 3
    return p0
.end method
