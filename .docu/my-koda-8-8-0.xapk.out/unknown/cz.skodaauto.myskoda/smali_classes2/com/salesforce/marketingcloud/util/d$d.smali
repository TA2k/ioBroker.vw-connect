.class final Lcom/salesforce/marketingcloud/util/d$d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/util/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "d"
.end annotation


# instance fields
.field final a:Ljava/lang/String;

.field final b:[J

.field c:Z

.field d:Lcom/salesforce/marketingcloud/util/d$c;

.field e:J

.field final synthetic f:Lcom/salesforce/marketingcloud/util/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/util/d;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/d$d;->f:Lcom/salesforce/marketingcloud/util/d;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget p1, p1, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 9
    .line 10
    new-array p1, p1, [J

    .line 11
    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    .line 13
    .line 14
    return-void
.end method

.method private a([Ljava/lang/String;)Ljava/io/IOException;
    .locals 2

    .line 5
    new-instance p0, Ljava/io/IOException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "unexpected journal line: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {p1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public a(I)Ljava/io/File;
    .locals 3

    .line 6
    new-instance v0, Ljava/io/File;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d$d;->f:Lcom/salesforce/marketingcloud/util/d;

    iget-object v1, v1, Lcom/salesforce/marketingcloud/util/d;->b:Ljava/io/File;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, "."

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public a()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    array-length v1, p0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-wide v3, p0, v2

    const/16 v5, 0x20

    .line 3
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public b(I)Ljava/io/File;
    .locals 3

    .line 6
    new-instance v0, Ljava/io/File;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d$d;->f:Lcom/salesforce/marketingcloud/util/d;

    iget-object v1, v1, Lcom/salesforce/marketingcloud/util/d;->b:Ljava/io/File;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, "."

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p0, ".tmp"

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public b([Ljava/lang/String;)V
    .locals 4

    .line 1
    array-length v0, p1

    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d$d;->f:Lcom/salesforce/marketingcloud/util/d;

    iget v1, v1, Lcom/salesforce/marketingcloud/util/d;->c:I

    if-ne v0, v1, :cond_1

    const/4 v0, 0x0

    .line 2
    :goto_0
    :try_start_0
    array-length v1, p1

    if-ge v0, v1, :cond_0

    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    aget-object v2, p1, v0

    invoke-static {v2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v2

    aput-wide v2, v1, v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void

    .line 4
    :catch_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/util/d$d;->a([Ljava/lang/String;)Ljava/io/IOException;

    move-result-object p0

    throw p0

    .line 5
    :cond_1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/util/d$d;->a([Ljava/lang/String;)Ljava/io/IOException;

    move-result-object p0

    throw p0
.end method
