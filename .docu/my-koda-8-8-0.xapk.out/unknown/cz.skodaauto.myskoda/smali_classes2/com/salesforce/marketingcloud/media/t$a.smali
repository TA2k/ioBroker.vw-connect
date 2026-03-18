.class public Lcom/salesforce/marketingcloud/media/t$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/media/t;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field a:Landroid/net/Uri;

.field b:Lcom/salesforce/marketingcloud/media/o$c;

.field c:I

.field d:I

.field e:I

.field f:Z

.field g:Z

.field h:F

.field i:F

.field j:I


# direct methods
.method public constructor <init>(Landroid/net/Uri;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/t$a;->a:Landroid/net/Uri;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(FFI)Lcom/salesforce/marketingcloud/media/t$a;
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/media/t$a;->h:F

    .line 2
    iput p2, p0, Lcom/salesforce/marketingcloud/media/t$a;->i:F

    .line 3
    iput p3, p0, Lcom/salesforce/marketingcloud/media/t$a;->j:I

    return-object p0
.end method

.method public a(II)Lcom/salesforce/marketingcloud/media/t$a;
    .locals 0

    .line 4
    iput p1, p0, Lcom/salesforce/marketingcloud/media/t$a;->d:I

    .line 5
    iput p2, p0, Lcom/salesforce/marketingcloud/media/t$a;->e:I

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/t$a;
    .locals 0

    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/t$a;->b:Lcom/salesforce/marketingcloud/media/o$c;

    return-object p0
.end method

.method public varargs a(Lcom/salesforce/marketingcloud/media/t$b;[Lcom/salesforce/marketingcloud/media/t$b;)Lcom/salesforce/marketingcloud/media/t$a;
    .locals 3

    if-nez p1, :cond_0

    goto :goto_1

    .line 7
    :cond_0
    iget v0, p0, Lcom/salesforce/marketingcloud/media/t$a;->c:I

    iget p1, p1, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    or-int/2addr p1, v0

    iput p1, p0, Lcom/salesforce/marketingcloud/media/t$a;->c:I

    if-nez p2, :cond_1

    goto :goto_1

    .line 8
    :cond_1
    array-length p1, p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p1, :cond_2

    aget-object v1, p2, v0

    .line 9
    iget v2, p0, Lcom/salesforce/marketingcloud/media/t$a;->c:I

    iget v1, v1, Lcom/salesforce/marketingcloud/media/t$b;->b:I

    or-int/2addr v1, v2

    iput v1, p0, Lcom/salesforce/marketingcloud/media/t$a;->c:I

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    :goto_1
    return-object p0
.end method

.method public a()Lcom/salesforce/marketingcloud/media/t;
    .locals 1

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/t$a;->b:Lcom/salesforce/marketingcloud/media/o$c;

    if-nez v0, :cond_0

    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/media/o$c;->b:Lcom/salesforce/marketingcloud/media/o$c;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/t$a;->b:Lcom/salesforce/marketingcloud/media/o$c;

    .line 12
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/media/t;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/media/t;-><init>(Lcom/salesforce/marketingcloud/media/t$a;)V

    return-object v0
.end method

.method public b()Lcom/salesforce/marketingcloud/media/t$a;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/t$a;->f:Z

    .line 3
    .line 4
    return-object p0
.end method

.method public c()Lcom/salesforce/marketingcloud/media/t$a;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/t$a;->g:Z

    .line 3
    .line 4
    return-object p0
.end method

.method public d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/t$a;->b:Lcom/salesforce/marketingcloud/media/o$c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method
