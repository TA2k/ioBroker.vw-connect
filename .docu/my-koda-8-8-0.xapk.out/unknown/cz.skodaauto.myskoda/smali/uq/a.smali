.class public final Luq/a;
.super Llp/y9;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/graphics/Typeface;

.field public final b:Lj1/a;

.field public c:Z


# direct methods
.method public constructor <init>(Lj1/a;Landroid/graphics/Typeface;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Luq/a;->a:Landroid/graphics/Typeface;

    .line 5
    .line 6
    iput-object p1, p0, Luq/a;->b:Lj1/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(I)V
    .locals 0

    .line 1
    iget-boolean p1, p0, Luq/a;->c:Z

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Luq/a;->b:Lj1/a;

    .line 6
    .line 7
    iget-object p1, p1, Lj1/a;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p1, Lrq/b;

    .line 10
    .line 11
    iget-object p0, p0, Luq/a;->a:Landroid/graphics/Typeface;

    .line 12
    .line 13
    invoke-virtual {p1, p0}, Lrq/b;->l(Landroid/graphics/Typeface;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    invoke-virtual {p1, p0}, Lrq/b;->j(Z)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public final c(Landroid/graphics/Typeface;Z)V
    .locals 0

    .line 1
    iget-boolean p2, p0, Luq/a;->c:Z

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Luq/a;->b:Lj1/a;

    .line 6
    .line 7
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lrq/b;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lrq/b;->l(Landroid/graphics/Typeface;)Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    invoke-virtual {p0, p1}, Lrq/b;->j(Z)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method
