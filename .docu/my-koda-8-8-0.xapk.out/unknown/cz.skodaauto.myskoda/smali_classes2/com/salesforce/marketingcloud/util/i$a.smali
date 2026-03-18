.class Lcom/salesforce/marketingcloud/util/i$a;
.super Ljava/io/ByteArrayOutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/util/i;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/util/i;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/i$a;->a:Lcom/salesforce/marketingcloud/util/i;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Ljava/io/ByteArrayOutputStream;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Ljava/io/ByteArrayOutputStream;->count:I

    .line 2
    .line 3
    if-lez v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Ljava/io/ByteArrayOutputStream;->buf:[B

    .line 6
    .line 7
    add-int/lit8 v2, v0, -0x1

    .line 8
    .line 9
    aget-byte v1, v1, v2

    .line 10
    .line 11
    const/16 v3, 0xd

    .line 12
    .line 13
    if-ne v1, v3, :cond_0

    .line 14
    .line 15
    move v0, v2

    .line 16
    :cond_0
    new-instance v1, Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p0, Ljava/io/ByteArrayOutputStream;->buf:[B

    .line 19
    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/i$a;->a:Lcom/salesforce/marketingcloud/util/i;

    .line 21
    .line 22
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/i;->a:Ljava/nio/charset/Charset;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    invoke-direct {v1, v2, v3, v0, p0}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 26
    .line 27
    .line 28
    return-object v1
.end method
