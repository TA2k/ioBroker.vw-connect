.class public final Lwm/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxm/a;
.implements Lwm/c;


# instance fields
.field public final a:Lum/j;

.field public final b:Lxm/e;

.field public c:Lcn/k;


# direct methods
.method public constructor <init>(Lum/j;Ldn/b;Lcn/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwm/p;->a:Lum/j;

    .line 5
    .line 6
    iget-object p1, p3, Lcn/j;->a:Lbn/f;

    .line 7
    .line 8
    invoke-interface {p1}, Lbn/f;->p()Lxm/e;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lwm/p;->b:Lxm/e;

    .line 13
    .line 14
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public static f(II)I
    .locals 2

    .line 1
    div-int v0, p0, p1

    .line 2
    .line 3
    xor-int v1, p0, p1

    .line 4
    .line 5
    if-gez v1, :cond_0

    .line 6
    .line 7
    mul-int v1, v0, p1

    .line 8
    .line 9
    if-eq v1, p0, :cond_0

    .line 10
    .line 11
    add-int/lit8 v0, v0, -0x1

    .line 12
    .line 13
    :cond_0
    mul-int/2addr v0, p1

    .line 14
    sub-int/2addr p0, v0

    .line 15
    return p0
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwm/p;->a:Lum/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Ljava/util/List;Ljava/util/List;)V
    .locals 0

    .line 1
    return-void
.end method
