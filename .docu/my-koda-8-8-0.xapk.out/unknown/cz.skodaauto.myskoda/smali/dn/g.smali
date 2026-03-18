.class public final Ldn/g;
.super Ldn/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Lwm/d;

.field public final B:Ldn/c;

.field public final C:Lxm/g;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;Ldn/c;Lum/a;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1, p2}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Ldn/g;->B:Ldn/c;

    .line 5
    .line 6
    new-instance p3, Lcn/m;

    .line 7
    .line 8
    iget-object p2, p2, Ldn/e;->a:Ljava/util/List;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    const-string v1, "__container"

    .line 12
    .line 13
    invoke-direct {p3, v1, p2, v0}, Lcn/m;-><init>(Ljava/lang/String;Ljava/util/List;Z)V

    .line 14
    .line 15
    .line 16
    new-instance p2, Lwm/d;

    .line 17
    .line 18
    invoke-direct {p2, p1, p0, p3, p4}, Lwm/d;-><init>(Lum/j;Ldn/b;Lcn/m;Lum/a;)V

    .line 19
    .line 20
    .line 21
    iput-object p2, p0, Ldn/g;->A:Lwm/d;

    .line 22
    .line 23
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 24
    .line 25
    invoke-virtual {p2, p1, p1}, Lwm/d;->b(Ljava/util/List;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Ldn/b;->p:Ldn/e;

    .line 29
    .line 30
    iget-object p1, p1, Ldn/e;->x:Landroidx/lifecycle/c1;

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    new-instance p2, Lxm/g;

    .line 35
    .line 36
    invoke-direct {p2, p0, p0, p1}, Lxm/g;-><init>(Ldn/b;Ldn/b;Landroidx/lifecycle/c1;)V

    .line 37
    .line 38
    .line 39
    iput-object p2, p0, Ldn/g;->C:Lxm/g;

    .line 40
    .line 41
    :cond_0
    return-void
.end method


# virtual methods
.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Ldn/g;->A:Lwm/d;

    .line 5
    .line 6
    iget-object p0, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 7
    .line 8
    invoke-virtual {p2, p1, p0, p3}, Lwm/d;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ldn/g;->C:Lxm/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p2, p3}, Lxm/g;->b(Landroid/graphics/Matrix;I)Lgn/a;

    .line 6
    .line 7
    .line 8
    move-result-object p4

    .line 9
    :cond_0
    iget-object p0, p0, Ldn/g;->A:Lwm/d;

    .line 10
    .line 11
    invoke-virtual {p0, p1, p2, p3, p4}, Lwm/d;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final i()Laq/a;
    .locals 1

    .line 1
    iget-object v0, p0, Ldn/b;->p:Ldn/e;

    .line 2
    .line 3
    iget-object v0, v0, Ldn/e;->w:Laq/a;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-object v0

    .line 8
    :cond_0
    iget-object p0, p0, Ldn/g;->B:Ldn/c;

    .line 9
    .line 10
    iget-object p0, p0, Ldn/b;->p:Ldn/e;

    .line 11
    .line 12
    iget-object p0, p0, Ldn/e;->w:Laq/a;

    .line 13
    .line 14
    return-object p0
.end method
