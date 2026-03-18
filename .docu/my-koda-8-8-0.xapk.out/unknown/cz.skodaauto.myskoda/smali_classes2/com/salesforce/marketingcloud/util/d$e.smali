.class public final Lcom/salesforce/marketingcloud/util/d$e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/util/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "e"
.end annotation


# instance fields
.field private final a:Ljava/lang/String;

.field private final b:J

.field private final c:[Ljava/io/InputStream;

.field private final d:[J

.field final synthetic e:Lcom/salesforce/marketingcloud/util/d;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/util/d;Ljava/lang/String;J[Ljava/io/InputStream;[J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/d$e;->e:Lcom/salesforce/marketingcloud/util/d;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/util/d$e;->a:Ljava/lang/String;

    .line 7
    .line 8
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/util/d$e;->b:J

    .line 9
    .line 10
    iput-object p5, p0, Lcom/salesforce/marketingcloud/util/d$e;->c:[Ljava/io/InputStream;

    .line 11
    .line 12
    iput-object p6, p0, Lcom/salesforce/marketingcloud/util/d$e;->d:[J

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/util/d$c;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d$e;->e:Lcom/salesforce/marketingcloud/util/d;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d$e;->a:Ljava/lang/String;

    iget-wide v2, p0, Lcom/salesforce/marketingcloud/util/d$e;->b:J

    invoke-virtual {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/lang/String;J)Lcom/salesforce/marketingcloud/util/d$c;

    move-result-object p0

    return-object p0
.end method

.method public a(I)Ljava/io/InputStream;
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$e;->c:[Ljava/io/InputStream;

    aget-object p0, p0, p1

    return-object p0
.end method

.method public b(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$e;->d:[J

    .line 2
    .line 3
    aget-wide p0, p0, p1

    .line 4
    .line 5
    return-wide p0
.end method

.method public c(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/d$e;->a(I)Ljava/io/InputStream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/InputStream;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public close()V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$e;->c:[Ljava/io/InputStream;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    if-ge v1, v0, :cond_0

    .line 6
    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 10
    .line 11
    .line 12
    add-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    return-void
.end method
