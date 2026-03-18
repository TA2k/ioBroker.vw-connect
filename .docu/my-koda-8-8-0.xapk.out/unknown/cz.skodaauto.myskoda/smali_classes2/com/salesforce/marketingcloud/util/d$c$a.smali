.class Lcom/salesforce/marketingcloud/util/d$c$a;
.super Ljava/io/FilterOutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/util/d$c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field final synthetic a:Lcom/salesforce/marketingcloud/util/d$c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/util/d$c;Ljava/io/OutputStream;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/d$c$a;->a:Lcom/salesforce/marketingcloud/util/d$c;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Ljava/io/FilterOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Ljava/io/FilterOutputStream;->out:Ljava/io/OutputStream;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :catch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$c$a;->a:Lcom/salesforce/marketingcloud/util/d$c;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/util/d$c;->c:Z

    .line 11
    .line 12
    return-void
.end method

.method public flush()V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Ljava/io/FilterOutputStream;->out:Ljava/io/OutputStream;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/OutputStream;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :catch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$c$a;->a:Lcom/salesforce/marketingcloud/util/d$c;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/util/d$c;->c:Z

    .line 11
    .line 12
    return-void
.end method

.method public write(I)V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Ljava/io/FilterOutputStream;->out:Ljava/io/OutputStream;

    invoke-virtual {v0, p1}, Ljava/io/OutputStream;->write(I)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 2
    :catch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$c$a;->a:Lcom/salesforce/marketingcloud/util/d$c;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/util/d$c;->c:Z

    return-void
.end method

.method public write([BII)V
    .locals 1

    .line 3
    :try_start_0
    iget-object v0, p0, Ljava/io/FilterOutputStream;->out:Ljava/io/OutputStream;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/OutputStream;->write([BII)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 4
    :catch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d$c$a;->a:Lcom/salesforce/marketingcloud/util/d$c;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/util/d$c;->c:Z

    return-void
.end method
