.class public final Lg11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:Z

.field public final d:Ljava/io/Serializable;


# direct methods
.method public constructor <init>(Lh0/z;Landroid/util/Rational;)V
    .locals 1

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    invoke-interface {p1}, Lh0/z;->e()I

    move-result v0

    iput v0, p0, Lg11/b;->a:I

    .line 8
    invoke-interface {p1}, Lh0/z;->h()I

    move-result p1

    iput p1, p0, Lg11/b;->b:I

    .line 9
    iput-object p2, p0, Lg11/b;->d:Ljava/io/Serializable;

    const/4 p1, 0x1

    if-eqz p2, :cond_1

    .line 10
    invoke-virtual {p2}, Landroid/util/Rational;->getNumerator()I

    move-result v0

    .line 11
    invoke-virtual {p2}, Landroid/util/Rational;->getDenominator()I

    move-result p2

    if-lt v0, p2, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :cond_1
    :goto_0
    iput-boolean p1, p0, Lg11/b;->c:Z

    return-void
.end method

.method public varargs constructor <init>([Ll11/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    .line 2
    iput v0, p0, Lg11/b;->a:I

    .line 3
    iput v0, p0, Lg11/b;->b:I

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lg11/b;->c:Z

    .line 5
    iput-object p1, p0, Lg11/b;->d:Ljava/io/Serializable;

    return-void
.end method


# virtual methods
.method public a(Lh0/a1;)Landroid/util/Size;
    .locals 3

    .line 1
    invoke-interface {p1}, Lh0/a1;->o()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    sget-object v2, Lh0/a1;->J0:Lh0/g;

    .line 7
    .line 8
    invoke-interface {p1, v2, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    check-cast p1, Landroid/util/Size;

    .line 13
    .line 14
    iget v1, p0, Lg11/b;->b:I

    .line 15
    .line 16
    iget p0, p0, Lg11/b;->a:I

    .line 17
    .line 18
    if-eqz p1, :cond_2

    .line 19
    .line 20
    invoke-static {v0}, Llp/h1;->c(I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne v2, v1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x0

    .line 29
    :goto_0
    invoke-static {v0, p0, v2}, Llp/h1;->b(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    const/16 v0, 0x5a

    .line 34
    .line 35
    if-eq p0, v0, :cond_1

    .line 36
    .line 37
    const/16 v0, 0x10e

    .line 38
    .line 39
    if-ne p0, v0, :cond_2

    .line 40
    .line 41
    :cond_1
    new-instance p0, Landroid/util/Size;

    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    invoke-direct {p0, v0, p1}, Landroid/util/Size;-><init>(II)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_2
    return-object p1
.end method
