.class public final synthetic Lxf0/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z


# direct methods
.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/i1;->d:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lxf0/i1;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lx2/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$composed"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    check-cast p2, Ll2/t;

    .line 16
    .line 17
    const p3, 0x6a9c21e4

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 21
    .line 22
    .line 23
    sget-object p3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 24
    .line 25
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    check-cast p3, Landroid/content/res/Resources;

    .line 30
    .line 31
    iget v0, p0, Lxf0/i1;->d:I

    .line 32
    .line 33
    invoke-virtual {p3, v0}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p3

    .line 37
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-boolean p0, p0, Lxf0/i1;->e:Z

    .line 42
    .line 43
    invoke-virtual {p2, p0}, Ll2/t;->h(Z)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    or-int/2addr v0, v1

    .line 48
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-nez v0, :cond_0

    .line 53
    .line 54
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 55
    .line 56
    if-ne v1, v0, :cond_1

    .line 57
    .line 58
    :cond_0
    new-instance v1, Lac0/g;

    .line 59
    .line 60
    const/4 v0, 0x4

    .line 61
    invoke-direct {v1, p3, p0, v0}, Lac0/g;-><init>(Ljava/lang/String;ZI)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    check-cast v1, Lay0/a;

    .line 68
    .line 69
    invoke-static {p1, v1}, Lxf0/i0;->K(Lx2/s;Lay0/a;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-static {p0, p3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const/4 p1, 0x0

    .line 81
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 82
    .line 83
    .line 84
    return-object p0
.end method
