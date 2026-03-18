.class public final Lrm/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lrm/f;


# instance fields
.field public final a:Lzl/i;

.field public final b:Lmm/j;

.field public final c:I


# direct methods
.method public constructor <init>(Lzl/i;Lmm/j;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrm/b;->a:Lzl/i;

    .line 5
    .line 6
    iput-object p2, p0, Lrm/b;->b:Lmm/j;

    .line 7
    .line 8
    iput p3, p0, Lrm/b;->c:I

    .line 9
    .line 10
    if-lez p3, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "durationMillis must be > 0."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 5

    .line 1
    new-instance v0, Lml/a;

    .line 2
    .line 3
    iget-object v1, p0, Lrm/b;->a:Lzl/i;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lrm/b;->b:Lmm/j;

    .line 9
    .line 10
    invoke-interface {v1}, Lmm/j;->r()Lyl/j;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-nez v2, :cond_4

    .line 15
    .line 16
    invoke-interface {v1}, Lmm/j;->a()Lmm/g;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    iget-object v2, v2, Lmm/g;->p:Lnm/g;

    .line 21
    .line 22
    instance-of v3, v1, Lmm/p;

    .line 23
    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    move-object v4, v1

    .line 27
    check-cast v4, Lmm/p;

    .line 28
    .line 29
    iget-boolean v4, v4, Lmm/p;->g:Z

    .line 30
    .line 31
    if-nez v4, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v4, 0x0

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    :goto_0
    const/4 v4, 0x1

    .line 37
    :goto_1
    iget p0, p0, Lrm/b;->c:I

    .line 38
    .line 39
    invoke-direct {v0, v2, p0, v4}, Lml/a;-><init>(Lnm/g;IZ)V

    .line 40
    .line 41
    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    invoke-static {v0}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_2
    instance-of p0, v1, Lmm/c;

    .line 49
    .line 50
    if-eqz p0, :cond_3

    .line 51
    .line 52
    invoke-static {v0}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_3
    new-instance p0, La8/r0;

    .line 57
    .line 58
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 63
    .line 64
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 65
    .line 66
    .line 67
    throw p0
.end method
